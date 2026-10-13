use crate::broker_build_status;
use crate::handlers::data::RAW_RESULT_MIME;
use crate::handlers::gateway::{
    GatewayForwardLimits, GatewayResponseStreamInput, gateway_response_body_stream,
};
use crate::ingress::guards::IngressGuards;
use crate::ingress::source::TrustedProxy;
use crate::reload::ReloadTrigger;
use crate::reload::validate_reload_timeout;
use crate::reload::validate_shutdown_timeout;
use crate::state::{ReloadableState, RuntimeSnapshot};
use crate::test_support::{IsolatedBroker, ProviderFixture};
use agent_access_cloudbees_ci::CLOUDBEES_CI_JOB_RESOURCE;
use agent_access_confluence::CONFLUENCE_SPACE_RESOURCE;
use agent_access_core::{
    BrokerConfig, BrokerRuntime, CredentialConfig, CredentialWriteRequest, CredentialsConfig,
    DeploymentConfig, EXECUTION_CONTEXT_HEADER, ExecutionContextConfig, IdentityConfig,
    IdentityGroupConfig, IdentitySourceConfig, LimitsConfig, PolicyConfig, PolicyGrantConfig,
    PrincipalPatchRequest, PrincipalWriteRequest, REASON_CODE_HEADER, ResourceDefinition,
    ResourceSelection, SourceContext, StateLockDomain, StateLockFailureKind, StateLockSet,
    StaticPrincipalConfig,
};
use agent_access_fake::FAKE_PROJECT_RESOURCE;
use agent_access_gitlab::PositionInputCategory;
use agent_access_jira::JIRA_PROJECT_RESOURCE;
use agent_access_provider::test_support::{
    credential_token, credential_username, install_trace_capture,
};
use agent_access_provider::{
    ActionDescriptor, AdmittedRequest, BROKER_REQUEST_ID_HEADER, BodyAdmission, BrokerBodyPartSpec,
    CredentialDescriptor, GIT_REPOSITORY_RESOURCE, LookupRequirement, Provider, ProviderError,
    ProviderInvocation, ProviderResult, ProviderResultStream, ProviderState, REQUEST_ID_HEADER,
    RESULT_METADATA_HEADER, ReasonCode, ResourceScopes, ResourceSelector, ResourceType,
    ScopeRequest, ScopeResolution, ServiceDescriptor, StateDisposition, attachment_upload_plan,
};
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::header::{
    ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, RETRY_AFTER, VARY,
    WWW_AUTHENTICATE,
};
use axum::http::{Method, Request, StatusCode, Uri};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use filetime::FileTime;
use futures_util::{TryStreamExt, stream};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use tower::ServiceExt;
use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::Context as TracingLayerContext;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

mod audit_query;
mod body_admission;
mod broker;
mod config_render;
pub(crate) use broker::{ConfigDoc, TestBroker, TestProvider, with_provider_instances};
mod confluence_read_presentation;
mod conformance;
pub(crate) mod conformance_import;
mod discovery;
mod domain_reasons;
mod gitlab_uploads;
mod gitlab_webhooks;
mod gmail;
mod identity_management;
mod imports_foundation;
mod imports_mcp;
mod imports_publication;
mod invocation_limits;
mod local_login_methods;
mod login_lockout;
mod management_read_audit;
mod management_service_metadata;
mod mcp;
mod mcp_managed;
mod mcp_spans;
mod microsoft_oidc;
mod oauth;
mod principal_access;
mod resource_management;
mod security_snapshot;
mod service_limits;
mod trusted_user_mcp;

fn resource_id(scope: &str, value: &str) -> String {
    format!("{}-{}", scope, value.replace('/', "-").to_ascii_lowercase())
}

fn selected_resources(entries: &[(&str, &[&str])]) -> ResourceSelection {
    ResourceSelection {
        resource_ids: entries
            .iter()
            .flat_map(|(scope, values)| values.iter().map(move |value| resource_id(scope, value)))
            .collect(),
        resource_group_ids: vec![],
    }
}

/// Fixture resources by id prefix. `project-*` entries are projects of the
/// development `fake` service; `jira-project-*` entries are Jira projects.
fn fixture_resources(contexts: &[&str]) -> Vec<ResourceDefinition> {
    let entries: &[(&str, ResourceType, &[&str])] = &[
        (
            "project",
            FAKE_PROJECT_RESOURCE.id().clone(),
            &[
                "TEST", "PROJ", "OPS", "SVC", "PARTNER", "ENG", "SLUG", "EMPTY", "SUBJECTS",
            ],
        ),
        (
            "jira-project",
            JIRA_PROJECT_RESOURCE.id().clone(),
            &["TEST", "PROJ"],
        ),
        ("space", CONFLUENCE_SPACE_RESOURCE.id().clone(), &["ENG"]),
        (
            "repository",
            GIT_REPOSITORY_RESOURCE.id().clone(),
            &["sip/service", "sip/other", "other/project", "acme/portal"],
        ),
    ];
    entries
        .iter()
        .flat_map(|(scope, resource_type, values)| {
            values.iter().map(move |value| ResourceDefinition {
                id: resource_id(scope, value),
                display_name: None,
                resource_type: resource_type.clone(),
                selector: ResourceSelector::Exact {
                    value: (*value).to_string(),
                },
                allowed_execution_contexts: contexts
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                enabled: true,
            })
        })
        .collect()
}

/// The response presentation a real backend declares for `service.action`,
/// as a broker configured with every content format enabled advertises it.
/// Test providers that stand in for a backend reuse it.
fn backend_presentation(
    service: &str,
    action: &str,
) -> Option<agent_access_provider::presentation::ActionPresentation> {
    static CONFIG: std::sync::OnceLock<agent_access_core::BrokerConfig> =
        std::sync::OnceLock::new();
    let config = CONFIG.get_or_init(|| {
        agent_access_core::parse_broker_config_raw(
            "presentation.toml",
            r#"
[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"

[providers.jira]
tenant_host = "example.atlassian.net"
allowed_upstream_hosts = ["https://example.atlassian.net/rest/api/3/**"]
content.comment_formats = ["adf"]

[providers.confluence]
tenant_host = "example.atlassian.net"
allowed_upstream_hosts = ["https://example.atlassian.net/wiki/**"]
content.page_formats = ["atlas_doc_format", "storage"]

[providers.gitlab]
api_base_url = "https://gitlab.example.com/api/v4"
web_base_url = "https://gitlab.example.com"
allowed_upstream_hosts = ["https://gitlab.example.com/api/v4/**"]
"#,
            &std::sync::Arc::new(crate::backend_registry()),
        )
        .expect("presentation config parses")
    });
    config
        .providers
        .get_kind(service)
        .expect("backend is configured")
        .descriptor()
        .action(action)
        .and_then(|action| action.presentation)
}

fn fixture_scope_capabilities(
    scope: &str,
) -> BTreeMap<String, agent_access_provider::ResourceScopeCapabilities> {
    BTreeMap::from([(
        scope.to_string(),
        agent_access_provider::ResourceScopeCapabilities::new(
            match scope {
                "project" => JIRA_PROJECT_RESOURCE.id().clone(),
                "space" => CONFLUENCE_SPACE_RESOURCE.id().clone(),
                "repository" => GIT_REPOSITORY_RESOURCE.id().clone(),
                _ => panic!("no fixture resource type for scope {scope}"),
            },
            vec!["exact".to_string(), "all".to_string()],
        ),
    )])
}

fn seed_managed_fixture_resources(store: &agent_access_core::ManagedStore) {
    for resource in fixture_resources(&["default"]) {
        store
            .create_resource(
                agent_access_core::CreateResourceRequest {
                    id: Some(resource.id),
                    display_name: resource.display_name,
                    resource_type: resource.resource_type,
                    selector: resource.selector,
                    allowed_execution_contexts: resource.allowed_execution_contexts,
                    enabled: resource.enabled,
                    attributes: agent_access_provider::ResourceAttributes::default(),
                    created_by: "test".to_string(),
                },
                |_, _, _, _| Ok(()),
            )
            .unwrap();
    }
}

fn seeded_resource_generation() -> usize {
    fixture_resources(&["default"]).len()
}

#[tokio::test]
async fn fake_provider_smoke_exercises_discovery_invoke_and_audit() {
    let audit_path = temp_path("broker-smoke.audit.sqlite");
    let broker = TestBroker::start_config(&fake_config(audit_path.to_str().unwrap())).await;
    let app = broker.app();

    let services = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/services")
                .extension(ConnectInfo(
                    "127.0.0.1:39990".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-services")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(services.status(), StatusCode::OK);
    let body = axum::body::to_bytes(services.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value[0]["service"], "fake");
    assert_eq!(value[0]["actions"][0]["action"], "echo");

    let invoke = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/fake/echo")
                .extension(ConnectInfo(
                    "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-1")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"inputs":{"project":"TEST","message":"do not audit this body"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invoke.status(), StatusCode::OK);
    let body = axum::body::to_bytes(invoke.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["decision"], "allow");
    assert_eq!(value["result"]["credentialMode"], "service");
    assert_eq!(value["result"]["message"], "do not audit this body");

    let audit = read_audit_text(&audit_path);
    assert!(audit.contains("\"service\":\"fake\""));
    assert!(audit.contains("\"principal\":\"anonymous\""));
    assert!(audit.contains("\"groups\":[\"anonymous\"]"));
    assert!(audit.contains("\"source\":{\"listener\":\"http\",\"remote\":\"127.0.0.1:40000\"}"));
    assert!(audit.contains("\"credentialMode\":\"service\""));
    assert!(audit.contains("\"matchedGrant\""));
    assert!(!audit.contains("do not audit this body"));
}

#[tokio::test]
async fn broker_status_does_not_append_to_configured_audit_sink() {
    let audit_path = temp_path("broker-status-no-audit.audit.jsonl");
    let initial_audit = b"{\"sentinel\":\"preexisting\"}\n";
    std::fs::write(&audit_path, initial_audit).unwrap();
    let broker = TestBroker::start_config(&fake_config(audit_path.to_str().unwrap())).await;
    let app = broker.app();

    let response = governed_get(app, "/v1/broker/status", "broker-status-no-audit", &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(std::fs::read(&audit_path).unwrap(), initial_audit);
}

#[tokio::test]
async fn resource_types_route_requires_an_authenticated_caller_in_every_identity_mode() {
    let token_path = temp_path("resource-types.identity-token");
    std::fs::write(&token_path, "resource-types-user-token").unwrap();
    for mode in ["anonymous", "optional"] {
        let mut config = fake_config("");
        config.identity.mode = mode.to_string();
        if mode == "optional" {
            config.identity.sources = vec![IdentitySourceConfig {
                name: "local".to_string(),
                kind: "static_principals".to_string(),
                header: "Authorization".to_string(),
                scheme: "Bearer".to_string(),
                principals: vec![StaticPrincipalConfig {
                    principal: "resource-types-user".to_string(),
                    token_refs: vec![format!("file:{}", token_path.display())],
                }],
            }];
        }
        let broker = TestBroker::start_config(&config).await;
        let app = broker.app();
        if mode == "optional" {
            let authenticated = governed_get(
                app.clone(),
                "/v1/resource-types",
                "resource-types-authenticated",
                &[("authorization", "Bearer resource-types-user-token")],
            )
            .await;
            assert_eq!(authenticated.status(), StatusCode::OK);
        }

        let response = governed_get(
            app,
            "/v1/resource-types",
            &format!("resource-types-{mode}"),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{mode}");
        assert_eq!(
            response_json(response).await["reasonCode"],
            "identity_required",
            "{mode}"
        );
    }
}

#[tokio::test]
async fn execution_context_http_routes_fail_closed_and_filter_all_governed_surfaces() {
    let audit_path = temp_path("execution-context-http.audit.jsonl");
    let token_path = temp_path("execution-context-http.identity-token");
    std::fs::write(&token_path, "context-user-token").unwrap();
    let mut config = context_aware_fake_config(audit_path.to_str().unwrap());
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "local".to_string(),
            kind: "static_principals".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![StaticPrincipalConfig {
                principal: "context-user".to_string(),
                token_refs: vec![format!("file:{}", token_path.display())],
            }],
        }],
        groups: vec![],
    };
    install_context_caller(&mut config);
    config.policy.grants[0].subjects = vec!["user:context-user".to_string()];
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();

    let missing = governed_get(app.clone(), "/v1/capabilities", "context-missing", &[]).await;
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(missing).await["reasonCode"],
        "execution_context_required"
    );

    for (request_id, mut headers) in [
        (
            "context-malformed",
            vec![(EXECUTION_CONTEXT_HEADER, "Internal")],
        ),
        (
            "context-duplicate",
            vec![
                (EXECUTION_CONTEXT_HEADER, "internal"),
                (EXECUTION_CONTEXT_HEADER, "external"),
            ],
        ),
        (
            "context-unknown",
            vec![(EXECUTION_CONTEXT_HEADER, "workstation")],
        ),
    ] {
        headers.push((CONTEXT_CALLER_HEADER, CONTEXT_CALLER_AUTH));
        let denied = governed_get(app.clone(), "/v1/services", request_id, &headers).await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "{request_id}");
        assert_eq!(
            response_json(denied).await["reasonCode"],
            "execution_context_invalid",
            "{request_id}"
        );
    }

    let internal_headers = [
        (CONTEXT_CALLER_HEADER, CONTEXT_CALLER_AUTH),
        (EXECUTION_CONTEXT_HEADER, "internal"),
        ("Authorization", "Bearer context-user-token"),
    ];
    let external_headers = [
        (CONTEXT_CALLER_HEADER, CONTEXT_CALLER_AUTH),
        (EXECUTION_CONTEXT_HEADER, "external"),
        ("Authorization", "Bearer context-user-token"),
    ];

    let capabilities = response_json(
        governed_get(
            app.clone(),
            "/v1/capabilities",
            "context-capabilities-internal",
            &internal_headers,
        )
        .await,
    )
    .await;
    assert!(
        capabilities["services"]
            .as_array()
            .unwrap()
            .iter()
            .any(|service| service["service"] == "fake")
    );
    let external_capabilities = response_json(
        governed_get(
            app.clone(),
            "/v1/capabilities",
            "context-capabilities-external",
            &external_headers,
        )
        .await,
    )
    .await;
    assert!(
        !external_capabilities["services"]
            .as_array()
            .unwrap()
            .iter()
            .any(|service| service["service"] == "fake")
    );

    let services = response_json(
        governed_get(
            app.clone(),
            "/v1/services",
            "context-services-internal",
            &internal_headers,
        )
        .await,
    )
    .await;
    assert!(
        services
            .as_array()
            .unwrap()
            .iter()
            .any(|service| service["service"] == "fake")
    );
    let external_services = response_json(
        governed_get(
            app.clone(),
            "/v1/services",
            "context-services-external",
            &external_headers,
        )
        .await,
    )
    .await;
    assert!(
        !external_services
            .as_array()
            .unwrap()
            .iter()
            .any(|service| service["service"] == "fake")
    );

    let describe = governed_get(
        app.clone(),
        "/v1/services/fake",
        "context-service-internal",
        &internal_headers,
    )
    .await;
    assert_eq!(describe.status(), StatusCode::OK);
    let hidden_describe = governed_get(
        app.clone(),
        "/v1/services/fake",
        "context-service-external",
        &external_headers,
    )
    .await;
    assert_eq!(hidden_describe.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(hidden_describe).await["reasonCode"],
        "service_action_denied"
    );

    let catalog_response = governed_get(
        app.clone(),
        "/v1/spec/catalog",
        "context-catalog-internal",
        &internal_headers,
    )
    .await;
    assert_eq!(catalog_response.status(), StatusCode::OK);
    let vary = catalog_response.headers()[VARY]
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    assert!(vary.contains(&EXECUTION_CONTEXT_HEADER.to_ascii_lowercase()));
    let catalog = response_json(catalog_response).await;
    assert_eq!(catalog["executionContext"], "internal");
    assert!(catalog_has_service(&catalog, "fake"));

    let external_catalog = response_json(
        governed_get(
            app.clone(),
            "/v1/spec/catalog",
            "context-catalog-external",
            &external_headers,
        )
        .await,
    )
    .await;
    assert_eq!(external_catalog["executionContext"], "external");
    assert!(!catalog_has_service(&external_catalog, "fake"));

    let openapi = response_json(
        governed_get(
            app.clone(),
            "/v1/spec/openapi.json",
            "context-openapi-internal",
            &internal_headers,
        )
        .await,
    )
    .await;
    assert!(openapi["paths"].get("/v1/invoke/fake/echo").is_some());
    let external_openapi = response_json(
        governed_get(
            app.clone(),
            "/v1/spec/openapi.json",
            "context-openapi-external",
            &external_headers,
        )
        .await,
    )
    .await;
    assert!(
        external_openapi["paths"]
            .get("/v1/invoke/fake/echo")
            .is_none()
    );

    let send_schema = response_json(
        governed_get(
            app.clone(),
            "/v1/spec/send-schema.json",
            "context-send-schema-internal",
            &internal_headers,
        )
        .await,
    )
    .await;
    assert!(
        send_schema["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(|variant| variant["properties"]["service"]["const"] == "fake")
    );
    let external_send_schema = response_json(
        governed_get(
            app.clone(),
            "/v1/spec/send-schema.json",
            "context-send-schema-external",
            &external_headers,
        )
        .await,
    )
    .await;
    assert!(
        !external_send_schema["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(|variant| variant["properties"]["service"]["const"] == "fake")
    );

    let allowed = invoke_fake(
        app.clone(),
        "127.0.0.1:40001",
        "context-invoke-internal",
        &internal_headers,
    )
    .await;
    assert_eq!(allowed.status(), StatusCode::OK);
    let denied = invoke_fake(
        app,
        "127.0.0.1:40002",
        "context-invoke-external",
        &external_headers,
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let audit = read_audit_records(&audit_path);
    let missing_record = audit
        .iter()
        .find(|record| record["agentRequestId"] == "context-missing")
        .unwrap();
    assert_eq!(missing_record["reasonCode"], "execution_context_required");
    assert!(missing_record.get("executionContext").is_none());
    let unknown_record = audit
        .iter()
        .find(|record| record["agentRequestId"] == "context-unknown")
        .unwrap();
    assert_eq!(unknown_record["reasonCode"], "execution_context_invalid");
    assert!(unknown_record.get("executionContext").is_none());
    assert!(
        !serde_json::to_string(unknown_record)
            .unwrap()
            .contains("workstation")
    );
    assert_eq!(
        audit
            .iter()
            .find(|record| record["agentRequestId"] == "context-invoke-internal")
            .unwrap()["executionContext"],
        "internal"
    );
    assert_eq!(
        audit
            .iter()
            .find(|record| record["agentRequestId"] == "context-invoke-external")
            .unwrap()["executionContext"],
        "external"
    );
}

#[tokio::test]
async fn unattested_context_is_rejected_without_trusted_callers() {
    let broker = TestBroker::start_config(&fake_config("")).await;
    let app = broker.app();
    let response = governed_get(
        app,
        "/v1/services",
        "context-unexpected-compatible",
        &[(EXECUTION_CONTEXT_HEADER, "default")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "caller_authentication_required"
    );
}

#[tokio::test]
async fn spec_catalog_requires_auth_and_sets_no_store_headers() {
    let fixture = spec_agent_fixture(&["fake"], false).await;

    let denied = spec_get(
        fixture.app.clone(),
        "/v1/spec/catalog",
        "spec-auth-denied",
        None,
    )
    .await;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let allowed = spec_get(
        fixture.app,
        "/v1/spec/catalog",
        "spec-auth-allowed",
        Some(&fixture.agent_token),
    )
    .await;
    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(
        allowed
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let vary = allowed
        .headers()
        .get(VARY)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(vary.contains("authorization"));
    assert!(vary.contains("cookie"));
    let body = response_json(allowed).await;
    assert_eq!(body["version"], "agent-access.catalog.v2");
    assert_eq!(body["send"]["version"], "agent-access.send.v1");
}

#[tokio::test]
async fn spec_catalog_sanitizes_gateway_services_and_broker_hosts() {
    let fixture = spec_agent_fixture(&["fake", "gitlab_git"], true).await;
    let response = spec_get(
        fixture.app,
        "/v1/spec/catalog",
        "spec-gateway-sanitized",
        Some(&fixture.agent_token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let services = body["services"]
        .as_array()
        .unwrap()
        .iter()
        .map(|service| service["service"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(services.contains(&"fake"));
    assert!(!services.contains(&"gitlab_git"));
    let serialized = serde_json::to_string(&body).unwrap();
    assert!(!serialized.contains("brokerHosts"));
    assert!(!serialized.contains("gatewayKind"));
}

#[tokio::test]
async fn spec_catalog_agent_allowed_services_narrows_provider_visibility() {
    let fixture = spec_agent_fixture(&["gitlab"], false).await;
    let response = spec_get(
        fixture.app.clone(),
        "/v1/spec/catalog",
        "spec-allowed-services-narrowed",
        Some(&fixture.agent_token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert!(!catalog_has_service(&body, "fake"));

    let auth = format!("Bearer {}", fixture.agent_token);
    let invoke_denied = invoke_fake(
        fixture.app,
        "127.0.0.1:41081",
        "spec-allowed-services-invoke-denied",
        &[(AUTHORIZATION.as_str(), auth.as_str())],
    )
    .await;
    assert_eq!(invoke_denied.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn spec_catalog_visibility_all_requires_admin_and_exposes_admin_routes() {
    let agent = spec_agent_fixture(&["fake"], false).await;
    let denied = spec_get(
        agent.app,
        "/v1/spec/catalog?visibility=all",
        "spec-visibility-all-denied",
        Some(&agent.agent_token),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let denied_body = response_json(denied).await;
    assert_eq!(denied_body["reasonCode"], "management_denied");

    let admin =
        spec_token_fixture(&[], false, agent_access_core::BrokerTokenClass::Admin, true).await;
    let caller = spec_get(
        admin.app.clone(),
        "/v1/spec/catalog",
        "spec-admin-caller-visibility",
        Some(&admin.agent_token),
    )
    .await;
    assert_eq!(caller.status(), StatusCode::OK);
    let caller_body = response_json(caller).await;
    assert!(catalog_has_route(
        &caller_body,
        "GET",
        "/v1/admin/policy/grants"
    ));
    assert!(!catalog_has_service(&caller_body, "fake"));

    let allowed = spec_get(
        admin.app,
        "/v1/spec/catalog?visibility=all",
        "spec-visibility-all-allowed",
        Some(&admin.agent_token),
    )
    .await;
    assert_eq!(allowed.status(), StatusCode::OK);
    let allowed_body = response_json(allowed).await;
    assert!(catalog_has_route(
        &allowed_body,
        "GET",
        "/v1/admin/policy/grants"
    ));
    assert!(catalog_has_service(&allowed_body, "fake"));
}

#[tokio::test]
async fn spec_catalog_management_routes_follow_token_class() {
    let agent = spec_agent_fixture(&["fake"], false).await;
    let agent_response = spec_get(
        agent.app,
        "/v1/spec/catalog",
        "spec-agent-routes",
        Some(&agent.agent_token),
    )
    .await;
    assert_eq!(agent_response.status(), StatusCode::OK);
    let agent_body = response_json(agent_response).await;
    assert!(!catalog_has_route(&agent_body, "GET", "/v1/tokens"));
    assert!(!catalog_has_route(
        &agent_body,
        "GET",
        "/v1/admin/policy/grants"
    ));

    let user_manage = spec_token_fixture(
        &[],
        false,
        agent_access_core::BrokerTokenClass::UserManage,
        false,
    )
    .await;
    let user_response = spec_get(
        user_manage.app,
        "/v1/spec/catalog",
        "spec-user-manage-routes",
        Some(&user_manage.agent_token),
    )
    .await;
    assert_eq!(user_response.status(), StatusCode::OK);
    let user_body = response_json(user_response).await;
    assert!(catalog_has_route(&user_body, "GET", "/v1/credentials"));
    assert!(catalog_has_route(&user_body, "GET", "/v1/tokens"));
    assert!(!catalog_has_route(
        &user_body,
        "GET",
        "/v1/admin/policy/grants"
    ));
    assert!(!catalog_has_service(&user_body, "fake"));
}

#[tokio::test]
async fn spec_openapi_and_send_schema_endpoints_are_hosted_and_filtered() {
    let fixture = spec_agent_fixture(&["fake", "jira", "confluence", "gitlab"], false).await;

    let catalog = spec_get(
        fixture.app.clone(),
        "/v1/spec/catalog",
        "spec-catalog-jira-dependency",
        Some(&fixture.agent_token),
    )
    .await;
    assert_eq!(catalog.status(), StatusCode::OK);
    let catalog_body = response_json(catalog).await;
    assert!(catalog_has_action(
        &catalog_body,
        "jira",
        "issue.dependency.add"
    ));
    assert!(catalog_has_action(
        &catalog_body,
        "jira",
        "issue.child.create"
    ));
    assert!(catalog_has_action(
        &catalog_body,
        "jira",
        "issue.parent.set"
    ));
    for action_name in [
        "issue.create",
        "issue.child.create",
        "issue.update",
        "comment.add",
        "comment.reply",
        "comment.update",
    ] {
        assert_jira_normalized_content_schema(
            &catalog_action(&catalog_body, "jira", action_name)["inputSchema"],
            action_name.starts_with("comment."),
        );
    }
    for excluded_action in ["issue.view", "comment.view", "attachment.add"] {
        if catalog_has_action(&catalog_body, "jira", excluded_action) {
            let properties = &catalog_action(&catalog_body, "jira", excluded_action)["inputSchema"]
                ["properties"];
            assert!(properties.get("content").is_none());
            assert!(properties.get("contentFormat").is_none());
        }
    }
    for action_name in CONFLUENCE_NORMALIZED_WRITE_ACTIONS {
        let action = catalog_action(&catalog_body, "confluence", action_name);
        let schema = &action["inputSchema"];
        assert_confluence_normalized_content_schema(schema, action_name);
        if matches!(*action_name, "page.create" | "page.draft.create") {
            assert_eq!(action["lookupRequired"], true);
            assert_eq!(schema["properties"]["parentPageId"]["type"], "string");
            assert_eq!(schema["properties"]["parentUrl"]["type"], "string");
            assert_eq!(
                schema["not"]["required"],
                json!(["parentPageId", "parentUrl"])
            );
        }
    }
    for excluded_action in [
        "page.view",
        "page.draft.publish",
        "blog.draft.publish",
        "attachment.add",
    ] {
        if catalog_has_action(&catalog_body, "confluence", excluded_action) {
            let properties = &catalog_action(&catalog_body, "confluence", excluded_action)["inputSchema"]
                ["properties"];
            assert!(properties.get("content").is_none());
            assert!(properties.get("contentFormat").is_none());
        }
    }
    for action_name in GITLAB_NORMALIZED_WRITE_ACTIONS {
        assert_gitlab_normalized_content_schema(
            &catalog_action(&catalog_body, "gitlab", action_name)["inputSchema"],
            gitlab_content_is_required(action_name),
        );
    }
    for excluded_action in ["issue.view", "issue.note.delete", "branch.create"] {
        if catalog_has_action(&catalog_body, "gitlab", excluded_action) {
            let properties = &catalog_action(&catalog_body, "gitlab", excluded_action)["inputSchema"]
                ["properties"];
            assert!(properties.get("content").is_none());
            assert!(properties.get("contentFormat").is_none());
        }
    }
    let page_move = catalog_action(&catalog_body, "confluence", "page.move");
    assert_eq!(page_move["lookupRequired"], true);
    assert_eq!(page_move["inputSchema"]["additionalProperties"], false);
    assert_eq!(
        page_move["inputSchema"]["allOf"][1]["oneOf"],
        json!([
            { "required": ["targetPageId"] },
            { "required": ["targetUrl"] }
        ])
    );
    assert_eq!(
        page_move["inputSchema"]["properties"]["position"]["enum"],
        json!(["before", "after", "append"])
    );

    let openapi = spec_get(
        fixture.app.clone(),
        "/v1/spec/openapi.json",
        "spec-openapi",
        Some(&fixture.agent_token),
    )
    .await;
    assert_eq!(openapi.status(), StatusCode::OK);
    let openapi_body = response_json(openapi).await;
    assert_eq!(openapi_body["openapi"], "3.1.0");
    assert_eq!(
        openapi_body["components"]["securitySchemes"]["brokerIdentity"]["name"],
        "Authorization"
    );
    assert!(openapi_body["paths"].get("/v1/invoke/fake/echo").is_some());
    assert!(
        openapi_body["paths"]
            .get("/v1/invoke/jira/issue.dependency.add")
            .is_some()
    );
    assert!(
        openapi_body["paths"]
            .get("/v1/invoke/jira/issue.child.create")
            .is_some()
    );
    assert!(
        openapi_body["paths"]
            .get("/v1/invoke/jira/issue.parent.set")
            .is_some()
    );
    for action_name in [
        "issue.create",
        "issue.child.create",
        "issue.update",
        "comment.add",
        "comment.reply",
        "comment.update",
    ] {
        let openapi_inputs = &openapi_body["paths"][format!("/v1/invoke/jira/{action_name}")]["post"]
            ["requestBody"]["content"]["application/json"]["schema"]["properties"]["inputs"];
        assert_eq!(
            openapi_inputs,
            &catalog_action(&catalog_body, "jira", action_name)["inputSchema"],
            "catalog and OpenAPI diverged for jira.{action_name}"
        );
    }
    for action_name in CONFLUENCE_NORMALIZED_WRITE_ACTIONS {
        let openapi_inputs = &openapi_body["paths"][format!("/v1/invoke/confluence/{action_name}")]
            ["post"]["requestBody"]["content"]["application/json"]["schema"]["properties"]["inputs"];
        assert_eq!(
            openapi_inputs,
            &catalog_action(&catalog_body, "confluence", action_name)["inputSchema"],
            "catalog and OpenAPI diverged for confluence.{action_name}"
        );
    }
    for action_name in GITLAB_NORMALIZED_WRITE_ACTIONS {
        let openapi_inputs = &openapi_body["paths"][format!("/v1/invoke/gitlab/{action_name}")]["post"]
            ["requestBody"]["content"]["application/json"]["schema"]["properties"]["inputs"];
        assert_eq!(
            openapi_inputs,
            &catalog_action(&catalog_body, "gitlab", action_name)["inputSchema"],
            "catalog and OpenAPI diverged for gitlab.{action_name}"
        );
    }
    let page_move_operation = &openapi_body["paths"]["/v1/invoke/confluence/page.move"]["post"];
    assert_eq!(
        page_move_operation["operationId"],
        "invoke.confluence.page.move"
    );
    let page_move_openapi_inputs = &page_move_operation["requestBody"]["content"]["application/json"]
        ["schema"]["properties"]["inputs"];
    assert_eq!(page_move_openapi_inputs["additionalProperties"], false);
    assert_eq!(
        page_move_openapi_inputs["properties"]["targetPageId"]["type"],
        "string"
    );
    assert_eq!(
        page_move_openapi_inputs["properties"]["targetUrl"]["type"],
        "string"
    );

    let send_schema = spec_get(
        fixture.app,
        "/v1/spec/send-schema.json",
        "spec-send-schema",
        Some(&fixture.agent_token),
    )
    .await;
    assert_eq!(send_schema.status(), StatusCode::OK);
    let schema_body = response_json(send_schema).await;
    assert_eq!(schema_body["title"], "Agent Access CLI send request");
    assert!(
        schema_body["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(|variant| variant["properties"]["service"]["const"] == "fake")
    );
    let schema_text = schema_body.to_string();
    assert!(schema_text.contains("issue.dependency.add"));
    assert!(schema_text.contains("blockingIssue"));
    assert!(schema_text.contains("blockedIssue"));
    assert!(schema_text.contains("issue.child.create"));
    assert!(schema_text.contains("issueTypeId"));
    assert!(schema_text.contains("issue.parent.set"));
    assert!(schema_text.contains("parentIssue"));
    assert_jira_read_response_capability_matrix(&catalog_body, &openapi_body, &schema_body);
    assert_gitlab_read_response_capability_matrix(&catalog_body, &openapi_body, &schema_body);
    for action_name in [
        "issue.create",
        "issue.child.create",
        "issue.update",
        "comment.add",
        "comment.reply",
        "comment.update",
    ] {
        let send_inputs =
            &send_action_variant(&schema_body, "jira", action_name)["properties"]["inputs"];
        assert_eq!(
            send_inputs,
            &catalog_action(&catalog_body, "jira", action_name)["inputSchema"],
            "catalog and send schema diverged for jira.{action_name}"
        );
    }
    for action_name in CONFLUENCE_NORMALIZED_WRITE_ACTIONS {
        let variant = send_action_variant(&schema_body, "confluence", action_name);
        assert_eq!(
            &variant["properties"]["inputs"],
            &catalog_action(&catalog_body, "confluence", action_name)["inputSchema"],
            "catalog and send schema diverged for confluence.{action_name}"
        );
    }
    for action_name in GITLAB_NORMALIZED_WRITE_ACTIONS {
        let variant = send_action_variant(&schema_body, "gitlab", action_name);
        assert_eq!(
            &variant["properties"]["inputs"],
            &catalog_action(&catalog_body, "gitlab", action_name)["inputSchema"],
            "catalog and send schema diverged for gitlab.{action_name}"
        );
    }
    let page_move_variant = send_action_variant(&schema_body, "confluence", "page.move");
    let page_move_inputs = &page_move_variant["properties"]["inputs"];
    assert_eq!(page_move_inputs["additionalProperties"], false);
    assert_eq!(
        page_move_inputs["properties"]["position"]["enum"],
        json!(["before", "after", "append"])
    );
    assert_eq!(
        page_move_inputs["properties"]["targetPageId"]["type"],
        "string"
    );
    assert_eq!(
        page_move_inputs["properties"]["targetUrl"]["type"],
        "string"
    );

    let restricted = spec_agent_fixture_with_restrictions(
        &["confluence"],
        json!({
            "confluence": {
                "actions": ["page.create", "page.move"]
            }
        }),
    )
    .await;
    let restricted_catalog = response_json(
        spec_get(
            restricted.app.clone(),
            "/v1/spec/catalog",
            "spec-catalog-action-restricted",
            Some(&restricted.agent_token),
        )
        .await,
    )
    .await;
    assert!(catalog_has_action(
        &restricted_catalog,
        "confluence",
        "page.create"
    ));
    assert!(!catalog_has_action(
        &restricted_catalog,
        "confluence",
        "page.draft.create"
    ));

    let restricted_openapi = response_json(
        spec_get(
            restricted.app.clone(),
            "/v1/spec/openapi.json",
            "spec-openapi-action-restricted",
            Some(&restricted.agent_token),
        )
        .await,
    )
    .await;
    assert!(
        restricted_openapi["paths"]
            .get("/v1/invoke/confluence/page.create")
            .is_some()
    );
    assert!(
        restricted_openapi["paths"]
            .get("/v1/invoke/confluence/page.draft.create")
            .is_none()
    );

    let restricted_send_schema = response_json(
        spec_get(
            restricted.app,
            "/v1/spec/send-schema.json",
            "spec-send-schema-action-restricted",
            Some(&restricted.agent_token),
        )
        .await,
    )
    .await;
    assert!(send_schema_has_action(
        &restricted_send_schema,
        "confluence",
        "page.create"
    ));
    assert!(!send_schema_has_action(
        &restricted_send_schema,
        "confluence",
        "page.draft.create"
    ));

    let gitlab_restricted = spec_agent_fixture_with_restrictions(
        &["gitlab"],
        json!({
            "gitlab": {
                "actions": ["merge_request.discussion.inline.add"]
            }
        }),
    )
    .await;
    let gitlab_restricted_catalog = response_json(
        spec_get(
            gitlab_restricted.app.clone(),
            "/v1/spec/catalog",
            "spec-catalog-gitlab-review-action-restricted",
            Some(&gitlab_restricted.agent_token),
        )
        .await,
    )
    .await;
    assert!(catalog_has_action(
        &gitlab_restricted_catalog,
        "gitlab",
        "merge_request.discussion.inline.add"
    ));
    for adjacent_action in [
        "merge_request.discussion.note.add",
        "merge_request.draft_note.add",
        "merge_request.review.submit",
        "merge_request.approval.view",
        "merge_request.approve",
        "merge_request.suggestion.apply",
    ] {
        assert!(!catalog_has_action(
            &gitlab_restricted_catalog,
            "gitlab",
            adjacent_action
        ));
    }

    let gitlab_restricted_openapi = response_json(
        spec_get(
            gitlab_restricted.app.clone(),
            "/v1/spec/openapi.json",
            "spec-openapi-gitlab-review-action-restricted",
            Some(&gitlab_restricted.agent_token),
        )
        .await,
    )
    .await;
    assert!(
        gitlab_restricted_openapi["paths"]
            .get("/v1/invoke/gitlab/merge_request.discussion.inline.add")
            .is_some()
    );
    assert!(
        gitlab_restricted_openapi["paths"]
            .get("/v1/invoke/gitlab/merge_request.discussion.note.add")
            .is_none()
    );

    let gitlab_restricted_send_schema = response_json(
        spec_get(
            gitlab_restricted.app,
            "/v1/spec/send-schema.json",
            "spec-send-schema-gitlab-review-action-restricted",
            Some(&gitlab_restricted.agent_token),
        )
        .await,
    )
    .await;
    assert!(send_schema_has_action(
        &gitlab_restricted_send_schema,
        "gitlab",
        "merge_request.discussion.inline.add"
    ));
    assert!(!send_schema_has_action(
        &gitlab_restricted_send_schema,
        "gitlab",
        "merge_request.draft_note.add"
    ));
}

#[tokio::test]
async fn direct_http_jira_parent_set_invokes_route_policy_and_audit() {
    let audit_path = temp_path("direct-http-jira-parent.audit.jsonl");
    let service_username_path = temp_path("direct-http-jira-service-username");
    let service_token_path = temp_path("direct-http-jira-service-token");
    let lookup_username_path = temp_path("direct-http-jira-lookup-username");
    let lookup_token_path = temp_path("direct-http-jira-lookup-token");
    std::fs::write(&service_username_path, "service@example.com").unwrap();
    std::fs::write(&service_token_path, "service-token").unwrap();
    std::fs::write(&lookup_username_path, "lookup@example.com").unwrap();
    std::fs::write(&lookup_token_path, "lookup-token").unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.credentials.service.insert(
        "jira".to_string(),
        CredentialConfig {
            kind: "basic_api_token".to_string(),
            username_ref: Some(format!("file:{}", service_username_path.display())),
            token_ref: Some(format!("file:{}", service_token_path.display())),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config.credentials.lookup.insert(
        "jira".to_string(),
        CredentialConfig {
            kind: "basic_api_token".to_string(),
            username_ref: Some(format!("file:{}", lookup_username_path.display())),
            token_ref: Some(format!("file:{}", lookup_token_path.display())),
            provider: None,
            path: None,
            read_only: Some(true),
            credential_name: None,
            profile: None,
        },
    );
    config
        .providers
        .insert(agent_access_jira::JiraProviderConfig {
            tenant_host: "example.atlassian.net".to_string(),
            cloud_id: None,
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".to_string()],
            attachments: agent_access_provider::AttachmentLimitsConfig::default(),
            content: agent_access_jira::JiraContentConfig {
                comment_formats: vec!["adf".to_string()],
                ..agent_access_jira::JiraContentConfig::default()
            },
            search: agent_access_provider::SearchLimitsConfig::default(),
            comments: agent_access_jira::JiraCommentsConfig::default(),
            issue_links: agent_access_jira::JiraIssueLinksConfig::default(),
        });
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        execution_contexts: None,
        service: "jira".to_string(),
        actions: vec!["issue.parent.set".to_string()],
        resources: selected_resources(&[("jira-project", &["PROJ"])]),
        credential_mode: "service".to_string(),
        priority: None,
    }];
    let runtime_broker =
        TestBroker::start_with_providers(&config, vec![Arc::new(TestJiraParentInvokeProvider)])
            .await;
    let app = runtime_broker.app();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/issue.parent.set")
                .extension(ConnectInfo(
                    "127.0.0.1:43000".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "direct-http-jira-parent")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"inputs":{"issue":"PROJ-2","parentIssue":"PROJ-100"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["decision"], "allow");
    assert_eq!(body["result"]["operation"], "issue.parent.set");
    assert_eq!(body["result"]["issue"]["key"], "PROJ-2");
    assert_eq!(body["result"]["parentIssue"]["key"], "PROJ-100");
    assert_eq!(body["result"]["verification"]["status"], "matched");

    let audit = read_audit_records(&audit_path);
    let record = audit
        .iter()
        .find(|record| record["action"] == "issue.parent.set")
        .unwrap();
    assert_eq!(record["service"], "jira");
    assert_eq!(record["decision"], "allow");
    assert_eq!(record["providerAudit"]["operation"], "issue.parent.set");
    assert_eq!(record["providerAudit"]["verificationStatus"], "matched");
    assert_eq!(record["providerAudit"]["issueKey"], "PROJ-2");
    assert_eq!(record["providerAudit"]["parentIssueKey"], "PROJ-100");
}

#[tokio::test]
async fn direct_http_jira_child_create_invokes_route_policy_and_audit() {
    let audit_path = temp_path("direct-http-jira-child.audit.jsonl");
    let service_username_path = temp_path("direct-http-jira-child-service-username");
    let service_token_path = temp_path("direct-http-jira-child-service-token");
    let lookup_username_path = temp_path("direct-http-jira-child-lookup-username");
    let lookup_token_path = temp_path("direct-http-jira-child-lookup-token");
    std::fs::write(&service_username_path, "service@example.com").unwrap();
    std::fs::write(&service_token_path, "service-token").unwrap();
    std::fs::write(&lookup_username_path, "lookup@example.com").unwrap();
    std::fs::write(&lookup_token_path, "lookup-token").unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.credentials.service.insert(
        "jira".to_string(),
        CredentialConfig {
            kind: "basic_api_token".to_string(),
            username_ref: Some(format!("file:{}", service_username_path.display())),
            token_ref: Some(format!("file:{}", service_token_path.display())),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config.credentials.lookup.insert(
        "jira".to_string(),
        CredentialConfig {
            kind: "basic_api_token".to_string(),
            username_ref: Some(format!("file:{}", lookup_username_path.display())),
            token_ref: Some(format!("file:{}", lookup_token_path.display())),
            provider: None,
            path: None,
            read_only: Some(true),
            credential_name: None,
            profile: None,
        },
    );
    config
        .providers
        .insert(agent_access_jira::JiraProviderConfig {
            tenant_host: "example.atlassian.net".to_string(),
            cloud_id: None,
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".to_string()],
            attachments: agent_access_provider::AttachmentLimitsConfig::default(),
            content: agent_access_jira::JiraContentConfig {
                comment_formats: vec!["adf".to_string()],
                ..agent_access_jira::JiraContentConfig::default()
            },
            search: agent_access_provider::SearchLimitsConfig::default(),
            comments: agent_access_jira::JiraCommentsConfig::default(),
            issue_links: agent_access_jira::JiraIssueLinksConfig::default(),
        });
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        execution_contexts: None,
        service: "jira".to_string(),
        actions: vec!["issue.child.create".to_string()],
        resources: selected_resources(&[("jira-project", &["PROJ"])]),
        credential_mode: "service".to_string(),
        priority: None,
    }];
    let runtime_broker =
        TestBroker::start_with_providers(&config, vec![Arc::new(TestJiraParentInvokeProvider)])
            .await;
    let app = runtime_broker.app();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/issue.child.create")
                .extension(ConnectInfo(
                    "127.0.0.1:43001".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "direct-http-jira-child")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"inputs":{"project":"PROJ","issueTypeId":"10001","summary":"Child","parentIssue":"PROJ-100"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["decision"], "allow");
    assert_eq!(body["result"]["operation"], "issue.child.create");
    assert_eq!(body["result"]["issue"]["key"], "PROJ-2");
    assert_eq!(body["result"]["parentIssue"]["key"], "PROJ-100");
    assert_eq!(body["result"]["verification"]["status"], "matched");

    let audit = read_audit_records(&audit_path);
    let record = audit
        .iter()
        .find(|record| record["action"] == "issue.child.create")
        .unwrap();
    assert_eq!(record["service"], "jira");
    assert_eq!(record["decision"], "allow");
    assert_eq!(record["providerAudit"]["operation"], "issue.child.create");
    assert_eq!(record["providerAudit"]["verificationStatus"], "matched");
    assert_eq!(record["providerAudit"]["issueKey"], "PROJ-2");
    assert_eq!(record["providerAudit"]["parentIssueKey"], "PROJ-100");
}

#[tokio::test]
async fn gateway_execution_context_denial_precedes_basic_auth_and_upstream_work() {
    let fixture = test_gateway_router_with_config(false, &["repo.fetch"], |config| {
        config.execution_context = Some(ExecutionContextConfig {
            allowed_values: vec!["internal".to_string(), "external".to_string()],
            default_context: None,
        });
        config.policy.resources = fixture_resources(
            &config
                .execution_context
                .as_ref()
                .unwrap()
                .allowed_values
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        install_context_caller(config);
        for grant in &mut config.policy.grants {
            grant.execution_contexts = Some(vec!["internal".to_string()]);
        }
    })
    .await;

    let missing = gateway_get(
        fixture.app.clone(),
        "/sip/service.git/info/refs?service=git-upload-pack",
        "git.example.test",
        "gateway-context-missing",
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        missing.headers()[REASON_CODE_HEADER],
        "execution_context_required"
    );
    assert!(!missing.headers().contains_key(WWW_AUTHENTICATE));

    let audit_path = fixture.audit_path.clone();
    let unknown = gateway_request(GatewayRequestSpec {
        app: fixture.app,
        method: Method::GET,
        uri: "/sip/service.git/info/refs?service=git-upload-pack"
            .parse()
            .unwrap(),
        host: Some("git.example.test"),
        request_id: Some("gateway-context-unknown"),
        authorization: Some("Basic deliberately-not-a-token"),
        headers: &[
            (CONTEXT_CALLER_HEADER, CONTEXT_CALLER_AUTH),
            (EXECUTION_CONTEXT_HEADER, "workstation"),
        ],
        body: Body::empty(),
    })
    .await;
    assert_eq!(unknown.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        unknown.headers()[REASON_CODE_HEADER],
        "execution_context_invalid"
    );
    assert!(!unknown.headers().contains_key(WWW_AUTHENTICATE));

    let audit = read_audit_records(&audit_path);
    assert!(audit.iter().any(|record| {
        record["agentRequestId"] == "gateway-context-missing"
            && record["reasonCode"] == "execution_context_required"
    }));
    assert!(audit.iter().any(|record| {
        record["agentRequestId"] == "gateway-context-unknown"
            && record["reasonCode"] == "execution_context_invalid"
    }));
}

#[tokio::test]
async fn gateway_router_is_separate_and_requires_basic_broker_auth() {
    let fixture = test_gateway_router().await;
    let app = fixture.app.clone();

    let public_path = gateway_get(
        app.clone(),
        "/v1/services",
        "git.example.test",
        "gateway-public-path",
        None,
    )
    .await;
    assert_eq!(public_path.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        public_path.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayRuleNotFound.as_str()
    );

    let unknown_host = gateway_get(
        app.clone(),
        "/sip/service.git/info/refs?service=git-upload-pack",
        "unknown.example.test",
        "gateway-unknown-host",
        None,
    )
    .await;
    assert_eq!(unknown_host.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        unknown_host.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayHostUnmatched.as_str()
    );

    let missing_auth = gateway_get(
        app.clone(),
        "/sip/service.git/info/refs?service=git-upload-pack",
        "git.example.test:9443",
        "gateway-missing-auth",
        None,
    )
    .await;
    assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing_auth.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayAuthRequired.as_str()
    );
    assert_eq!(
        missing_auth.headers()[WWW_AUTHENTICATE],
        r#"Basic realm="Agent Access Broker""#
    );
    assert!(
        missing_auth
            .headers()
            .contains_key(BROKER_REQUEST_ID_HEADER)
    );

    let wrong_basic = format!("Basic {}", BASE64.encode("wrong-user:not-a-token"));
    let invalid_auth = gateway_get(
        app.clone(),
        "/sip/service.git/info/refs?service=git-upload-pack",
        "git.example.test",
        "gateway-invalid-auth",
        Some(&wrong_basic),
    )
    .await;
    assert_eq!(invalid_auth.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        invalid_auth.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayAuthInvalid.as_str()
    );

    let valid_basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", fixture.agent_token))
    );
    let authorized = gateway_get(
        app.clone(),
        "/sip/service.git/info/refs?service=git-upload-pack",
        "git.example.test",
        "gateway-authorized",
        Some(&valid_basic),
    )
    .await;
    assert_eq!(authorized.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        authorized.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayUpstreamDenied.as_str()
    );

    let generated_request_id = gateway_request(GatewayRequestSpec {
        app: app.clone(),
        method: Method::GET,
        uri: "/sip/service.git/info/refs?service=git-upload-pack"
            .parse()
            .unwrap(),
        host: Some("git.example.test"),
        request_id: None,
        authorization: Some(&valid_basic),
        headers: &[],
        body: Body::empty(),
    })
    .await;
    assert_eq!(generated_request_id.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        generated_request_id.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayUpstreamDenied.as_str()
    );

    let uppercase_host = gateway_get(
        app.clone(),
        "/sip/service.git/info/refs?service=git-upload-pack",
        "GIT.EXAMPLE.TEST",
        "gateway-uppercase-host",
        Some(&valid_basic),
    )
    .await;
    assert_eq!(uppercase_host.status(), StatusCode::BAD_GATEWAY);

    let unsupported_git_protocol = gateway_request(GatewayRequestSpec {
        app: app.clone(),
        method: Method::GET,
        uri: "/sip/service.git/info/refs?service=git-upload-pack"
            .parse()
            .unwrap(),
        host: Some("git.example.test"),
        request_id: Some("gateway-unsupported-git-protocol"),
        authorization: Some(&valid_basic),
        headers: &[("Git-Protocol", "version=1")],
        body: Body::empty(),
    })
    .await;
    assert_eq!(unsupported_git_protocol.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        unsupported_git_protocol.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayHeaderDenied.as_str()
    );

    let wrong_content_type = gateway_request(GatewayRequestSpec {
        app: app.clone(),
        method: Method::POST,
        uri: "/sip/service.git/git-upload-pack".parse().unwrap(),
        host: Some("git.example.test"),
        request_id: Some("gateway-wrong-git-content-type"),
        authorization: Some(&valid_basic),
        headers: &[(CONTENT_TYPE.as_str(), "text/plain")],
        body: Body::empty(),
    })
    .await;
    assert_eq!(
        wrong_content_type.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(
        wrong_content_type.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayContentTypeDenied.as_str()
    );

    let unsupported_method = gateway_request(GatewayRequestSpec {
        app: app.clone(),
        method: Method::PUT,
        uri: "/sip/service.git/info/refs?service=git-upload-pack"
            .parse()
            .unwrap(),
        host: Some("git.example.test"),
        request_id: Some("gateway-unsupported-method"),
        authorization: Some(&valid_basic),
        headers: &[],
        body: Body::empty(),
    })
    .await;
    assert_eq!(unsupported_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        unsupported_method.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayMethodDenied.as_str()
    );

    let invalid_query = gateway_get(
        app.clone(),
        "/sip/service.git/info/refs?not-service=git-upload-pack",
        "git.example.test",
        "gateway-invalid-query",
        Some(&valid_basic),
    )
    .await;
    assert_eq!(invalid_query.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid_query.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayQueryDenied.as_str()
    );

    let disabled_push = gateway_request(GatewayRequestSpec {
        app: app.clone(),
        method: Method::POST,
        uri: "/sip/service.git/git-receive-pack".parse().unwrap(),
        host: Some("git.example.test"),
        request_id: Some("gateway-disabled-push"),
        authorization: Some(&valid_basic),
        headers: &[(
            CONTENT_TYPE.as_str(),
            "application/x-git-receive-pack-request",
        )],
        body: Body::empty(),
    })
    .await;
    assert_eq!(disabled_push.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        disabled_push.headers()[REASON_CODE_HEADER],
        ReasonCode::GitServiceDenied.as_str()
    );

    let ambiguous_git_segment = gateway_get(
        app,
        "/sip.git/service.git/info/refs?service=git-upload-pack",
        "git.example.test",
        "gateway-ambiguous-git-segment",
        Some(&valid_basic),
    )
    .await;
    assert_eq!(ambiguous_git_segment.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        ambiguous_git_segment.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayRuleNotFound.as_str()
    );

    let records = read_audit_records(&fixture.audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-authorized"
            && record["source"]["agentRequestIdGenerated"] == false
    }));
    assert!(records.iter().any(|record| {
        record["agentRequestId"]
            .as_str()
            .is_some_and(|request_id| request_id.starts_with("gateway-"))
            && record["source"]["agentRequestIdGenerated"] == true
    }));
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-public-path"
            && record["service"] == "gitlab_git"
            && record["action"] == "gateway.classify"
            && record["principal"] == "anonymous"
            && record["reasonCode"] == ReasonCode::GatewayRuleNotFound.as_str()
    }));
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-unsupported-git-protocol"
            && record["service"] == "gitlab_git"
            && record["action"] == "gateway.classify"
            && record["principal"] == "anonymous"
            && record["reasonCode"] == ReasonCode::GatewayHeaderDenied.as_str()
    }));
    assert_eq!(
        records
            .iter()
            .filter(|record| record["agentRequestId"] == "gateway-unsupported-git-protocol")
            .count(),
        1
    );
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-wrong-git-content-type"
            && record["service"] == "gitlab_git"
            && record["action"] == "gateway.classify"
            && record["principal"] == "anonymous"
            && record["reasonCode"] == ReasonCode::GatewayContentTypeDenied.as_str()
    }));
    assert_eq!(
        records
            .iter()
            .filter(|record| record["agentRequestId"] == "gateway-wrong-git-content-type")
            .count(),
        1
    );
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-disabled-push"
            && record["service"] == "gitlab_git"
            && record["action"] == "gateway.classify"
            && record["principal"] == "anonymous"
            && record["reasonCode"] == ReasonCode::GitServiceDenied.as_str()
    }));
    assert_eq!(
        records
            .iter()
            .filter(|record| record["agentRequestId"] == "gateway-disabled-push")
            .count(),
        1
    );
}

#[tokio::test]
async fn gateway_authorized_push_denies_malformed_receive_pack_prefix() {
    let fixture = test_gateway_router_with_options(true, &["repo.push"]).await;
    let app = fixture.app.clone();
    let valid_basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", fixture.agent_token))
    );

    let response = gateway_request(GatewayRequestSpec {
        app,
        method: Method::POST,
        uri: "/sip/service.git/git-receive-pack".parse().unwrap(),
        host: Some("git.example.test"),
        request_id: Some("gateway-authorized-push"),
        authorization: Some(&valid_basic),
        headers: &[(
            CONTENT_TYPE.as_str(),
            "application/x-git-receive-pack-request",
        )],
        body: Body::empty(),
    })
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        ReasonCode::GitPktLineMalformed.as_str()
    );
    let records = read_audit_records(&fixture.audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-authorized-push"
            && record["service"] == "gitlab_git"
            && record["action"] == "repo.push"
            && record["decision"] == "deny"
            && record["reasonCode"] == ReasonCode::GitPktLineMalformed.as_str()
    }));
}

#[tokio::test]
async fn gateway_counts_only_pack_posts_and_rejects_with_retry_after_plain_text() {
    let fixture = test_gateway_router_with_config(false, &["repo.fetch"], |config| {
        config.limits.invocations.services.insert(
            "gitlab_git".to_string(),
            agent_access_core::InvocationLimitConfig {
                requests: 1,
                window: "1m".to_string(),
            },
        );
    })
    .await;
    let valid_basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", fixture.agent_token))
    );
    // Ref discovery never spends the invocation budget.
    for index in 0..3 {
        let discovery = gateway_get(
            fixture.app.clone(),
            "/sip/service.git/info/refs?service=git-upload-pack",
            "git.example.test",
            &format!("gateway-discovery-{index}"),
            Some(&valid_basic),
        )
        .await;
        assert_ne!(discovery.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    let pack_headers = [(
        CONTENT_TYPE.as_str(),
        "application/x-git-upload-pack-request",
    )];
    let upload_pack = |request_id: &'static str| {
        gateway_request(GatewayRequestSpec {
            app: fixture.app.clone(),
            method: Method::POST,
            uri: "/sip/service.git/git-upload-pack".parse().unwrap(),
            host: Some("git.example.test"),
            request_id: Some(request_id),
            authorization: Some(&valid_basic),
            headers: &pack_headers,
            body: Body::from("0000"),
        })
    };
    let first = upload_pack("gateway-pack-first").await;
    assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);
    let second = upload_pack("gateway-pack-second").await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        second.headers()[REASON_CODE_HEADER],
        ReasonCode::RateLimited.as_str()
    );
    let retry_after: u64 = second.headers()[RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=61).contains(&retry_after), "{retry_after}");
    let body = String::from_utf8(
        axum::body::to_bytes(second.into_body(), 4096)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body.starts_with(&format!(
            "Rate limit reached for service \"gitlab_git\": 1 request per 1m. Retry after {retry_after}s (at "
        )),
        "{body}"
    );
    assert!(
        body.ends_with("Z). The request was not executed.\n"),
        "{body}"
    );
    // Discovery stays available while pack transfers are limited.
    let discovery = gateway_get(
        fixture.app.clone(),
        "/sip/service.git/info/refs?service=git-upload-pack",
        "git.example.test",
        "gateway-discovery-after-limit",
        Some(&valid_basic),
    )
    .await;
    assert_ne!(discovery.status(), StatusCode::TOO_MANY_REQUESTS);

    let records = read_audit_records(&fixture.audit_path);
    let limited = records
        .iter()
        .find(|record| record["agentRequestId"] == "gateway-pack-second")
        .unwrap();
    assert_eq!(limited["service"], "gitlab_git");
    assert_eq!(limited["action"], "repo.fetch");
    assert_eq!(limited["principal"], "gateway-user");
    assert_eq!(limited["decision"], "error");
    assert_eq!(limited["reasonCode"], ReasonCode::RateLimited.as_str());
    assert_eq!(
        limited["providerAudit"]["rateLimit"],
        json!({
            "limitScope": "principal",
            "service": "gitlab_git",
            "limit": 1,
            "windowSeconds": 60,
            "retryAfterSeconds": retry_after
        })
    );
    assert!(limited.get("matchedGrant").is_none());
}

#[tokio::test]
async fn gateway_charges_protocol_v2_ls_refs_posts_like_any_pack_post() {
    // Documents why gateway limits need room for several POSTs per fetch: a
    // protocol v2 fetch sends `command=ls-refs` before `command=fetch`, and
    // each upload-pack POST is charged. A limit of 1 cannot complete a fetch.
    let fixture = test_gateway_router_with_config(false, &["repo.fetch"], |config| {
        config.limits.invocations.services.insert(
            "gitlab_git".to_string(),
            agent_access_core::InvocationLimitConfig {
                requests: 1,
                window: "1m".to_string(),
            },
        );
    })
    .await;
    let valid_basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", fixture.agent_token))
    );
    let v2_headers = [
        (
            CONTENT_TYPE.as_str(),
            "application/x-git-upload-pack-request",
        ),
        ("Git-Protocol", "version=2"),
    ];
    let v2_command = |request_id: &'static str, body: &'static str| {
        gateway_request(GatewayRequestSpec {
            app: fixture.app.clone(),
            method: Method::POST,
            uri: "/sip/service.git/git-upload-pack".parse().unwrap(),
            host: Some("git.example.test"),
            request_id: Some(request_id),
            authorization: Some(&valid_basic),
            headers: &v2_headers,
            body: Body::from(body),
        })
    };
    let ls_refs = v2_command("gateway-v2-ls-refs", "0014command=ls-refs\n0000").await;
    assert_ne!(ls_refs.status(), StatusCode::TOO_MANY_REQUESTS);
    let fetch = v2_command("gateway-v2-fetch", "0012command=fetch\n0000").await;
    assert_eq!(fetch.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        fetch.headers()[REASON_CODE_HEADER],
        ReasonCode::RateLimited.as_str()
    );

    let records = read_audit_records(&fixture.audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-v2-ls-refs"
            && record["reasonCode"] != ReasonCode::RateLimited.as_str()
    }));
    let limited = records
        .iter()
        .find(|record| record["agentRequestId"] == "gateway-v2-fetch")
        .unwrap();
    assert_eq!(limited["action"], "repo.fetch");
    assert_eq!(limited["reasonCode"], ReasonCode::RateLimited.as_str());
}

#[tokio::test]
async fn gateway_authorized_push_does_not_resolve_execution_credential() {
    let missing_token_path = temp_path("gateway-missing-service-token");
    let fixture = test_gateway_router_with_config(true, &["repo.push"], |config| {
        config
            .credentials
            .service
            .get_mut("gitlab_git")
            .unwrap()
            .token_ref = Some(format!("file:{}", missing_token_path.display()));
    })
    .await;
    let app = fixture.app.clone();
    let valid_basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", fixture.agent_token))
    );

    let response = gateway_request(GatewayRequestSpec {
        app,
        method: Method::POST,
        uri: "/sip/service.git/git-receive-pack".parse().unwrap(),
        host: Some("git.example.test"),
        request_id: Some("gateway-push-no-credential-resolution"),
        authorization: Some(&valid_basic),
        headers: &[(
            CONTENT_TYPE.as_str(),
            "application/x-git-receive-pack-request",
        )],
        body: Body::from(receive_pack_test_payload("report-status push-options")),
    })
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        ReasonCode::GitCapabilityDenied.as_str()
    );
    let records = read_audit_records(&fixture.audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-push-no-credential-resolution"
            && record["service"] == "gitlab_git"
            && record["action"] == "repo.push"
            && record["credentialMode"] == "service"
            && record["matchedGrant"]["subject"] == "user:gateway-user"
            && record["reasonCode"] == ReasonCode::GitCapabilityDenied.as_str()
            && record["providerAudit"]["git"]["updates"][0]["ref"] == "refs/heads/feature"
    }));
}

#[tokio::test]
async fn gateway_upload_pack_content_encoding_denial_does_not_resolve_execution_credential() {
    let missing_token_path = temp_path("gateway-upload-encoding-missing-service-token");
    let fixture = test_gateway_router_with_config(false, &["repo.fetch"], |config| {
        config
            .credentials
            .service
            .get_mut("gitlab_git")
            .unwrap()
            .token_ref = Some(format!("file:{}", missing_token_path.display()));
    })
    .await;
    let app = fixture.app.clone();
    let valid_basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", fixture.agent_token))
    );

    let response = gateway_request(GatewayRequestSpec {
        app,
        method: Method::POST,
        uri: "/sip/service.git/git-upload-pack".parse().unwrap(),
        host: Some("git.example.test"),
        request_id: Some("gateway-upload-encoding-denied-before-credential"),
        authorization: Some(&valid_basic),
        headers: &[
            (
                CONTENT_TYPE.as_str(),
                "application/x-git-upload-pack-request",
            ),
            (CONTENT_ENCODING.as_str(), "br"),
        ],
        body: Body::from("opaque-upload-pack"),
    })
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayHeaderDenied.as_str()
    );
    let records = read_audit_records(&fixture.audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-upload-encoding-denied-before-credential"
            && record["service"] == "gitlab_git"
            && record["action"] == "repo.fetch"
            && record["decision"] == "deny"
            && record["reasonCode"] == ReasonCode::GatewayHeaderDenied.as_str()
    }));
}

#[tokio::test]
async fn gateway_upload_pack_content_encoding_denial_honors_policy_denial_ordering() {
    let fixture = test_gateway_router_with_config(false, &["repo.fetch"], |config| {
        config
            .policy
            .grants
            .iter_mut()
            .find(|grant| grant.service == "gitlab_git")
            .unwrap()
            .resources = selected_resources(&[("repository", &["sip/other"])]);
    })
    .await;
    let app = fixture.app.clone();
    let valid_basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", fixture.agent_token))
    );

    let response = gateway_request(GatewayRequestSpec {
        app,
        method: Method::POST,
        uri: "/sip/service.git/git-upload-pack".parse().unwrap(),
        host: Some("git.example.test"),
        request_id: Some("gateway-upload-encoding-policy-denied-first"),
        authorization: Some(&valid_basic),
        headers: &[
            (
                CONTENT_TYPE.as_str(),
                "application/x-git-upload-pack-request",
            ),
            (CONTENT_ENCODING.as_str(), "br"),
        ],
        body: Body::from("opaque-upload-pack"),
    })
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        ReasonCode::ServiceActionDenied.as_str()
    );
    let records = read_audit_records(&fixture.audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-upload-encoding-policy-denied-first"
            && record["service"] == "gitlab_git"
            && record["action"] == "repo.fetch"
            && record["decision"] == "deny"
            && record["reasonCode"] == ReasonCode::ServiceActionDenied.as_str()
    }));
}

#[tokio::test]
async fn gateway_discovery_content_encoding_denial_is_action_scoped() {
    let fixture = test_gateway_router_with_config(true, &["repo.fetch", "repo.push"], |_| {}).await;
    let app = fixture.app.clone();
    let valid_basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", fixture.agent_token))
    );

    let fetch = gateway_request(GatewayRequestSpec {
        app: app.clone(),
        method: Method::GET,
        uri: "/sip/service.git/info/refs?service=git-upload-pack"
            .parse()
            .unwrap(),
        host: Some("git.example.test"),
        request_id: Some("gateway-fetch-discovery-encoding-denied"),
        authorization: Some(&valid_basic),
        headers: &[(CONTENT_ENCODING.as_str(), "gzip")],
        body: Body::empty(),
    })
    .await;
    assert_eq!(fetch.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        fetch.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayHeaderDenied.as_str()
    );

    let push = gateway_request(GatewayRequestSpec {
        app,
        method: Method::GET,
        uri: "/sip/service.git/info/refs?service=git-receive-pack"
            .parse()
            .unwrap(),
        host: Some("git.example.test"),
        request_id: Some("gateway-push-discovery-encoding-denied"),
        authorization: Some(&valid_basic),
        headers: &[(CONTENT_ENCODING.as_str(), "gzip")],
        body: Body::empty(),
    })
    .await;
    assert_eq!(push.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        push.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayHeaderDenied.as_str()
    );

    let records = read_audit_records(&fixture.audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-fetch-discovery-encoding-denied"
            && record["principal"] == "gateway-user"
            && record["service"] == "gitlab_git"
            && record["action"] == "repo.fetch"
            && record["decision"] == "deny"
            && record["reasonCode"] == ReasonCode::GatewayHeaderDenied.as_str()
    }));
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-push-discovery-encoding-denied"
            && record["principal"] == "gateway-user"
            && record["service"] == "gitlab_git"
            && record["action"] == "repo.push"
            && record["decision"] == "deny"
            && record["reasonCode"] == ReasonCode::GatewayHeaderDenied.as_str()
    }));
}

#[tokio::test]
async fn gateway_receive_pack_content_encoding_denial_does_not_parse_body_or_resolve_credential() {
    let missing_token_path = temp_path("gateway-receive-encoding-missing-service-token");
    let fixture = test_gateway_router_with_config(true, &["repo.push"], |config| {
        config
            .credentials
            .service
            .get_mut("gitlab_git")
            .unwrap()
            .token_ref = Some(format!("file:{}", missing_token_path.display()));
    })
    .await;
    let app = fixture.app.clone();
    let valid_basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", fixture.agent_token))
    );

    let response = gateway_request(GatewayRequestSpec {
        app,
        method: Method::POST,
        uri: "/sip/service.git/git-receive-pack".parse().unwrap(),
        host: Some("git.example.test"),
        request_id: Some("gateway-receive-encoding-denied-before-parse"),
        authorization: Some(&valid_basic),
        headers: &[
            (
                CONTENT_TYPE.as_str(),
                "application/x-git-receive-pack-request",
            ),
            (CONTENT_ENCODING.as_str(), "gzip"),
        ],
        body: Body::from("not-a-pkt-line"),
    })
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayHeaderDenied.as_str()
    );
    let records = read_audit_records(&fixture.audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-receive-encoding-denied-before-parse"
            && record["service"] == "gitlab_git"
            && record["action"] == "repo.push"
            && record["decision"] == "deny"
            && record["reasonCode"] == ReasonCode::GatewayHeaderDenied.as_str()
    }));
    assert!(!records.iter().any(|record| {
        record["agentRequestId"] == "gateway-receive-encoding-denied-before-parse"
            && record["reasonCode"] == ReasonCode::GitPktLineMalformed.as_str()
    }));
}

#[tokio::test]
async fn gateway_response_stream_completes_terminal_audit_with_byte_count() {
    let token_path = temp_path("gateway-stream-service-token");
    let identity_token_path = temp_path("gateway-stream-identity-token");
    let audit_path = temp_path("gateway-stream.audit.sqlite");
    std::fs::write(&token_path, "git-service-token").unwrap();
    std::fs::write(&identity_token_path, "gateway-identity-token").unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "local".to_string(),
            kind: "static_principals".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![StaticPrincipalConfig {
                principal: "gateway-user".to_string(),
                token_refs: vec![format!("file:{}", identity_token_path.display())],
            }],
        }],
        groups: vec![],
    };
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some(format!("file:{}", token_path.display())),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config
        .gateways
        .insert("gitlab_git".to_string(), test_git_gateway_config());
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:gateway-user".to_string()],
        execution_contexts: None,
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string()],
        resources: selected_resources(&[("repository", &["sip/service"])]),
        credential_mode: "service".to_string(),
        priority: None,
    });

    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        Some("gateway-user".to_string()),
        vec![],
        None,
        None,
    );
    let mut prepared = runtime
        .prepare_gateway_operation(
            agent_access_core::GovernedOperationContext {
                operation: agent_access_core::OperationContext {
                    agent_request_id: "gateway-stream-complete".to_string(),
                    broker_request_id: "gateway-stream-broker".to_string(),
                    identity,
                    service: "gitlab_git".to_string(),
                    action: "repo.fetch".to_string(),
                    source: SourceContext::unknown(),
                },
                execution_context: agent_access_core::ExecutionContext::new(
                    agent_access_core::DEFAULT_EXECUTION_CONTEXT,
                )
                .unwrap(),
            },
            ResourceScopes::from([
                ("repository".to_string(), vec!["sip/service".to_string()]),
                ("namespace".to_string(), vec!["sip".to_string()]),
            ]),
        )
        .await
        .unwrap();
    runtime
        .start_prepared_gateway_operation(
            &mut prepared,
            json!({
                "gateway": {
                    "kind": "git_http",
                    "method": "GET",
                    "upstreamOrigin": "https://gitlab.example.com",
                    "upstreamPath": "/sip/service.git/info/refs",
                    "responseBytes": 0
                }
            }),
        )
        .await
        .unwrap();

    let chunks: Vec<Bytes> = gateway_response_body_stream(GatewayResponseStreamInput {
        runtime: runtime.clone(),
        prepared,
        method: Method::GET,
        upstream_url: url::Url::parse("https://gitlab.example.com/sip/service.git/info/refs")
            .unwrap(),
        egress_proxy_audit: json!({"mode": "direct"}),
        upstream_status: 200,
        started: Instant::now(),
        limits: GatewayForwardLimits {
            request_body_max_bytes: 1024,
            response_body_max_bytes: 1024,
            idle_timeout: Duration::from_secs(1),
        },
        git_audit: None,
        body: Box::pin(stream::iter([
            Ok::<Bytes, reqwest::Error>(Bytes::from_static(b"abc")),
            Ok::<Bytes, reqwest::Error>(Bytes::from_static(b"def")),
        ])),
        permits: None,
    })
    .try_collect()
    .await
    .unwrap();
    assert_eq!(chunks.concat(), b"abcdef");

    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();
    let records = read_audit_records(&audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-stream-complete"
            && record["providerAudit"]["gateway"]["phase"] == "started"
            && record["providerAudit"]["gateway"]["responseBytes"] == 0
    }));
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-stream-complete"
            && record["providerAudit"]["gateway"]["phase"] == "completed"
            && record["providerAudit"]["gateway"]["responseBytes"] == 6
            && record["upstreamStatus"] == 200
    }));
}

#[tokio::test]
async fn gateway_response_stream_drop_records_partial_cancel_audit() {
    let token_path = temp_path("gateway-stream-cancel-service-token");
    let identity_token_path = temp_path("gateway-stream-cancel-identity-token");
    let audit_path = temp_path("gateway-stream-cancel.audit.sqlite");
    std::fs::write(&token_path, "git-service-token").unwrap();
    std::fs::write(&identity_token_path, "gateway-identity-token").unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "local".to_string(),
            kind: "static_principals".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![StaticPrincipalConfig {
                principal: "gateway-user".to_string(),
                token_refs: vec![format!("file:{}", identity_token_path.display())],
            }],
        }],
        groups: vec![],
    };
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some(format!("file:{}", token_path.display())),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config
        .gateways
        .insert("gitlab_git".to_string(), test_git_gateway_config());
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:gateway-user".to_string()],
        execution_contexts: None,
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string()],
        resources: selected_resources(&[("repository", &["sip/service"])]),
        credential_mode: "service".to_string(),
        priority: None,
    });

    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        Some("gateway-user".to_string()),
        vec![],
        None,
        None,
    );
    let mut prepared = runtime
        .prepare_gateway_operation(
            agent_access_core::GovernedOperationContext {
                operation: agent_access_core::OperationContext {
                    agent_request_id: "gateway-stream-cancel".to_string(),
                    broker_request_id: "gateway-stream-cancel-broker".to_string(),
                    identity,
                    service: "gitlab_git".to_string(),
                    action: "repo.fetch".to_string(),
                    source: SourceContext::unknown(),
                },
                execution_context: agent_access_core::ExecutionContext::new(
                    agent_access_core::DEFAULT_EXECUTION_CONTEXT,
                )
                .unwrap(),
            },
            ResourceScopes::from([
                ("repository".to_string(), vec!["sip/service".to_string()]),
                ("namespace".to_string(), vec!["sip".to_string()]),
            ]),
        )
        .await
        .unwrap();
    runtime
        .start_prepared_gateway_operation(
            &mut prepared,
            json!({
                "gateway": {
                    "kind": "git_http",
                    "method": "GET",
                    "upstreamOrigin": "https://gitlab.example.com",
                    "upstreamPath": "/sip/service.git/info/refs",
                    "responseBytes": 0
                }
            }),
        )
        .await
        .unwrap();

    let mut response_stream = Box::pin(gateway_response_body_stream(GatewayResponseStreamInput {
        runtime: runtime.clone(),
        prepared,
        method: Method::GET,
        upstream_url: url::Url::parse("https://gitlab.example.com/sip/service.git/info/refs")
            .unwrap(),
        egress_proxy_audit: json!({"mode": "direct"}),
        upstream_status: 200,
        started: Instant::now(),
        limits: GatewayForwardLimits {
            request_body_max_bytes: 1024,
            response_body_max_bytes: 1024,
            idle_timeout: Duration::from_secs(1),
        },
        git_audit: None,
        body: Box::pin(stream::iter([
            Ok::<Bytes, reqwest::Error>(Bytes::from_static(b"abc")),
            Ok::<Bytes, reqwest::Error>(Bytes::from_static(b"def")),
        ])),
        permits: None,
    }));
    let first = response_stream.as_mut().try_next().await.unwrap().unwrap();
    assert_eq!(&first[..], b"abc");
    drop(response_stream);

    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();
    let records = read_audit_records(&audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-stream-cancel"
            && record["providerAudit"]["gateway"]["phase"] == "started"
            && record["providerAudit"]["gateway"]["responseBytes"] == 0
    }));
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-stream-cancel"
            && record["providerAudit"]["gateway"]["phase"] == "canceled"
            && record["providerAudit"]["gateway"]["responseBytes"] == 3
            && record["upstreamStatus"] == 200
    }));
}

#[tokio::test]
async fn disabled_toml_group_does_not_authorize_invoke() {
    let token_path = temp_path("disabled-toml-group-token");
    std::fs::write(&token_path, "agent-token").unwrap();

    let mut config = fake_config("");
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "local".to_string(),
            kind: "static_principals".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![StaticPrincipalConfig {
                principal: "agent-one".to_string(),
                token_refs: vec![format!("file:{}", token_path.display())],
            }],
        }],
        groups: vec![IdentityGroupConfig {
            id: "agents".to_string(),
            status: "disabled".to_string(),
            members: vec!["agent-one".to_string()],
        }],
    };
    config.policy.grants[0].subjects = vec!["group:agents".to_string()];

    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();
    let response = authed_json_request(
        app,
        Method::POST,
        "/v1/invoke/fake/echo",
        "disabled-toml-group-invoke",
        "Authorization",
        "Bearer agent-token",
        Some(r#"{"inputs":{"project":"TEST","message":"denied"}}"#),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "service_action_denied"
    );
}

#[tokio::test]
async fn admin_reload_swaps_snapshot_for_new_requests_and_audits_generation() {
    let config_path = temp_path("reload-success.toml");
    let audit_path = temp_path("reload-success.audit.sqlite");
    let spool_dir = temp_path("reload-success-spool");
    let service_token = temp_path("reload-success-service-token");
    let admin_token = temp_path("reload-success-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );

    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();

    let public = state_broker.app();
    let admin = state_broker.app();

    let before = invoke_fake_project(
        public.clone(),
        "127.0.0.1:42000",
        "agent-req-before-reload",
        "TEST",
    )
    .await;
    assert_eq!(before.status(), StatusCode::OK);
    assert_eq!(response_json(before).await["result"]["project"], "TEST");

    write_reload_config(
        &config_path,
        "NEXT",
        &audit_path,
        &service_token,
        &spool_dir,
        1536,
    );
    let reload = admin_request(
        admin.clone(),
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-reload"),
        Some("admin-token"),
    )
    .await;
    let reload_status = reload.status();
    let reload_body = response_json(reload).await;
    assert_eq!(
        reload_status,
        StatusCode::OK,
        "reload response: {reload_body}"
    );
    let reload_result = &reload_body["result"];
    assert_eq!(reload_body["ok"], true);
    assert_eq!(reload_body["decision"], "allow");
    assert_eq!(reload_result["previousGeneration"], 1);
    assert_eq!(reload_result["generation"], 2);
    assert_eq!(reload_result["policyGeneration"], 2);
    assert_eq!(reload_result["identityAuthority"], "toml");
    assert_eq!(reload_result["policyAuthority"], "toml");
    assert_ne!(
        reload_result["previousConfigHash"],
        reload_result["configHash"]
    );

    let old_project = invoke_fake_project(
        public.clone(),
        "127.0.0.1:42001",
        "agent-req-old-project",
        "TEST",
    )
    .await;
    assert_eq!(old_project.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(old_project).await["reasonCode"],
        "service_action_denied"
    );

    let new_project =
        invoke_fake_project(public, "127.0.0.1:42002", "agent-req-new-project", "NEXT").await;
    assert_eq!(new_project.status(), StatusCode::OK);
    assert_eq!(
        response_json(new_project).await["result"]["project"],
        "NEXT"
    );

    let records = read_audit_records(&audit_path);
    let reload_allow_records = records
        .iter()
        .filter(|record| {
            record["service"] == "broker"
                && record["action"] == "config.reload"
                && record["decision"] == "allow"
        })
        .count();
    assert_eq!(reload_allow_records, 1);
    assert!(records.iter().any(|record| {
        record["service"] == "broker"
            && record["action"] == "config.reload"
            && record["decision"] == "allow"
            && record["configGeneration"] == 2
            && record["policyGeneration"] == 2
            && record.get("credentialMode") == Some(&Value::Null)
            && record["source"]["remote"] == "127.0.0.1:43000"
    }));
    assert!(records.iter().any(|record| {
        record["service"] == "fake"
            && record["agentRequestId"] == "agent-req-new-project"
            && record["configGeneration"] == 2
            && record["policyGeneration"] == 2
    }));
}

#[tokio::test]
async fn failed_admin_reload_leaves_active_snapshot_unchanged() {
    let config_path = temp_path("reload-failure.toml");
    let audit_path = temp_path("reload-failure.audit.jsonl");
    let spool_dir = temp_path("reload-failure-spool");
    let service_token = temp_path("reload-failure-service-token");
    let admin_token = temp_path("reload-failure-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );

    let state_broker = reload_test_broker(config_path.clone(), Some(1024))
        .await
        .unwrap();

    let public = state_broker.app();
    let admin = state_broker.app();

    write_reload_config(
        &config_path,
        "NEXT",
        &audit_path,
        &service_token,
        &spool_dir,
        2048,
    );
    let reload = admin_request(
        admin.clone(),
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-reload-failed"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(reload.status(), StatusCode::SERVICE_UNAVAILABLE);
    let reload_body = response_json(reload).await;
    assert_eq!(reload_body["ok"], false);
    assert_eq!(reload_body["decision"], "error");
    assert_eq!(reload_body["reasonCode"], "config_admission_failed");
    assert!(
        reload_body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("body hard cap")
    );

    let old_project = invoke_fake_project(
        public.clone(),
        "127.0.0.1:42003",
        "agent-req-still-old-project",
        "TEST",
    )
    .await;
    assert_eq!(old_project.status(), StatusCode::OK);

    let new_project = invoke_fake_project(
        public,
        "127.0.0.1:42004",
        "agent-req-denied-new-project",
        "NEXT",
    )
    .await;
    assert_eq!(new_project.status(), StatusCode::FORBIDDEN);

    let status = admin_request(
        admin,
        Method::GET,
        "/v1/admin/config/status",
        Some("agent-req-admin-status-after-failure"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(status.status(), StatusCode::OK);
    let status_body = response_json(status).await;
    let status_result = &status_body["result"];
    assert_eq!(status_result["generation"], 1);
    assert_eq!(
        status_result["lastReloadAttempt"]["reasonCode"],
        "config_admission_failed"
    );
    assert_eq!(status_result["lastReloadAttempt"]["activeGeneration"], 1);
}

#[tokio::test]
async fn outbound_tls_startup_and_reload_failures_preserve_diagnostics_and_active_runtime() {
    let config_path = temp_path("reload-tls.toml");
    let audit_path = temp_path("reload-tls.audit.jsonl");
    let spool_dir = temp_path("reload-tls-spool");
    let service_token = temp_path("reload-tls-service-token");
    let ca_path = temp_path("reload-tls-ca.pem");
    std::fs::write(&service_token, "service-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let raw = std::fs::read_to_string(&config_path).unwrap();
    std::fs::write(
        &config_path,
        format!(
            "{raw}\n[network.outbound_tls]\ntrust = \"custom\"\nca_certificate = \"{}\"\n",
            ca_path.display()
        ),
    )
    .unwrap();
    let error = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .err()
        .expect("startup must reject a missing CA bundle");
    assert!(
        error.to_string().contains("network.outbound_tls"),
        "{error:#}"
    );
    assert!(error.to_string().contains("ca_certificate"), "{error:#}");
    assert!(
        error
            .downcast_ref::<agent_access_core::RuntimeError>()
            .is_some()
    );

    std::fs::write(
        &ca_path,
        include_bytes!("../../../agent-access-core/tests/fixtures/outbound-tls/ca-a.pem"),
    )
    .unwrap();
    let state_broker = reload_test_broker(config_path, Some(4096)).await.unwrap();
    let state = state_broker.state();
    let active = state.current();
    let app = state_broker.app();
    for (request_id, contents) in [
        ("agent-req-tls-malformed", Some("not a PEM certificate")),
        ("agent-req-tls-missing", None),
    ] {
        match contents {
            Some(contents) => std::fs::write(&ca_path, contents).unwrap(),
            None => std::fs::remove_file(&ca_path).unwrap(),
        }
        let response = admin_request(
            app.clone(),
            Method::POST,
            "/v1/admin/config/reload",
            Some(request_id),
            Some("admin-token"),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["reasonCode"], "config_admission_failed");
        let message = body["error"]["message"].as_str().unwrap();
        assert!(message.contains("network.outbound_tls"), "{body}");
        assert!(message.contains("ca_certificate"), "{body}");
        assert!(Arc::ptr_eq(&active, &state.current()));
        assert_eq!(state.current().generation, 1);
        let records = read_audit_records(&audit_path);
        let record = records
            .iter()
            .find(|record| record["agentRequestId"] == request_id)
            .unwrap();
        assert_eq!(record["decision"], "error");
        assert_eq!(record["providerAudit"]["admin"]["activeGeneration"], 1);
        assert_eq!(record["providerAudit"]["admin"]["errors"][0], message);
    }
    let response =
        invoke_fake_project(app, "127.0.0.1:42010", "agent-req-tls-still-active", "TEST").await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn failed_parse_and_missing_secret_reloads_report_hash_and_keep_active_snapshot() {
    let config_path = temp_path("reload-invalid.toml");
    let audit_path = temp_path("reload-invalid.audit.jsonl");
    let spool_dir = temp_path("reload-invalid-spool");
    let service_token = temp_path("reload-invalid-service-token");
    let admin_token = temp_path("reload-invalid-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );

    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();

    let state = state_broker.state();
    let public = state_broker.app();
    let admin = state_broker.app();

    std::fs::write(&config_path, "[policy]\ndefault_decision = ").unwrap();
    let parse_failure = admin_request(
        admin.clone(),
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-parse-failed"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(parse_failure.status(), StatusCode::BAD_REQUEST);
    let parse_body = response_json(parse_failure).await;
    assert_eq!(parse_body["reasonCode"], "config_parse_failed");
    assert_eq!(state.current().generation, 1);

    let missing_service_token = temp_path("reload-invalid-missing-service-token");
    write_reload_config(
        &config_path,
        "NEXT",
        &audit_path,
        &missing_service_token,
        &spool_dir,
        1024,
    );
    let admission_failure = admin_request(
        admin,
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-secret-failed"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(admission_failure.status(), StatusCode::SERVICE_UNAVAILABLE);
    let admission_body = response_json(admission_failure).await;
    assert_eq!(admission_body["reasonCode"], "config_admission_failed");
    assert_eq!(state.current().generation, 1);

    let old_project = invoke_fake_project(
        public,
        "127.0.0.1:42005",
        "agent-req-still-active-after-invalid",
        "TEST",
    )
    .await;
    assert_eq!(old_project.status(), StatusCode::OK);
}

#[cfg(unix)]
#[tokio::test]
async fn failed_http_reload_returns_audit_unavailable_when_failure_audit_cannot_append() {
    use std::os::unix::fs::PermissionsExt;

    let config_path = temp_path("reload-failure-audit-unavailable.toml");
    let audit_path = temp_path("reload-failure-audit-unavailable.audit.jsonl");
    let spool_dir = temp_path("reload-failure-audit-unavailable-spool");
    let service_token = temp_path("reload-failure-audit-unavailable-service-token");
    std::fs::write(&service_token, "service-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );

    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();

    let admin = state_broker.app();

    std::fs::write(&config_path, "[policy]\ndefault_decision = ").unwrap();
    let audit_parent = audit_path.parent().unwrap();
    std::fs::set_permissions(audit_parent, std::fs::Permissions::from_mode(0o000)).unwrap();
    let response = admin_request(
        admin,
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-parse-audit-unavailable"),
        Some("admin-token"),
    )
    .await;
    std::fs::set_permissions(audit_parent, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(response).await;
    assert_eq!(body["operation"], "config.reload");
    assert_eq!(body["decision"], "error");
    assert_eq!(body["reasonCode"], "audit_unavailable");
}

#[tokio::test(flavor = "current_thread")]
async fn failed_admin_reload_emits_error_level_reload_event() {
    let captured = install_trace_capture().start();

    let config_path = temp_path("reload-trace-invalid.toml");
    let audit_path = temp_path("reload-trace-invalid.audit.jsonl");
    let spool_dir = temp_path("reload-trace-invalid-spool");
    let service_token = temp_path("reload-trace-invalid-service-token");
    let admin_token = temp_path("reload-trace-invalid-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );

    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();

    let admin = state_broker.app();

    std::fs::write(&config_path, "[policy]\ndefault_decision = ").unwrap();
    let response = captured
        .run(admin_request(
            admin,
            Method::POST,
            "/v1/admin/config/reload",
            Some("agent-req-admin-trace-parse-failed"),
            Some("admin-token"),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let events = captured.take_events();
    let failed = event_by_name_and_agent(
        &events,
        "config_reload_failed",
        "agent-req-admin-trace-parse-failed",
    );
    assert_eq!(string_field(failed, "level"), Some("ERROR"));
    assert_eq!(string_field(failed, "listener"), Some("public"));
    assert_eq!(string_field(failed, "operation"), Some("config.reload"));
    assert_eq!(
        string_field(failed, "agentRequestId"),
        Some("agent-req-admin-trace-parse-failed")
    );
    assert_eq!(
        string_field(failed, "reasonCode"),
        Some("config_parse_failed")
    );
    assert_eq!(number_field(failed, "http.statusCode"), Some(400));
    assert!(string_field(failed, "brokerRequestId").is_some());
}

#[tokio::test]
async fn concurrent_admin_reload_reports_reload_in_progress_without_swapping() {
    let config_path = temp_path("reload-concurrent.toml");
    let audit_path = temp_path("reload-concurrent.audit.jsonl");
    let spool_dir = temp_path("reload-concurrent-spool");
    let service_token = temp_path("reload-concurrent-service-token");
    let admin_token = temp_path("reload-concurrent-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();
    let state = state_broker.state();
    let observed_generation = state
        .managed_policy_mutation(|runtime| Ok(runtime.policy_generation()))
        .await
        .unwrap();
    assert_eq!(observed_generation, 1);
    let admin = state_broker.app();

    write_reload_config(
        &config_path,
        "NEXT",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let lock = state.reload_lock.lock().await;
    let reload = admin_request(
        admin,
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-reload-concurrent"),
        Some("admin-token"),
    )
    .await;
    drop(lock);

    assert_eq!(reload.status(), StatusCode::CONFLICT);
    let body = response_json(reload).await;
    assert_eq!(body["reasonCode"], "reload_in_progress");
    assert_eq!(state.current().generation, 1);

    let records = read_audit_records(&audit_path);
    assert!(records.iter().any(|record| {
        record["service"] == "broker"
            && record["action"] == "config.reload"
            && record["decision"] == "error"
            && record["providerAudit"]["admin"]["reasonCode"] == "reload_in_progress"
    }));
}

#[tokio::test]
async fn admin_reload_reports_reload_in_progress_when_policy_mutation_is_active() {
    let config_path = temp_path("reload-policy-mutation-concurrent.toml");
    let audit_path = temp_path("reload-policy-mutation-concurrent.audit.jsonl");
    let spool_dir = temp_path("reload-policy-mutation-concurrent-spool");
    let service_token = temp_path("reload-policy-mutation-concurrent-service-token");
    let admin_token = temp_path("reload-policy-mutation-concurrent-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();
    let state = state_broker.state();
    let admin = state_broker.app();

    write_reload_config(
        &config_path,
        "NEXT",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let lock = state.policy_mutation_lock.lock().await;
    let mutation = state
        .managed_policy_mutation(|runtime| Ok(runtime.policy_generation()))
        .await
        .unwrap_err();
    assert_eq!(mutation.reason_code(), ReasonCode::ReloadInProgress);
    let reload = admin_request(
        admin,
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-reload-policy-mutation"),
        Some("admin-token"),
    )
    .await;
    drop(lock);

    assert_eq!(reload.status(), StatusCode::CONFLICT);
    let body = response_json(reload).await;
    assert_eq!(body["reasonCode"], "reload_in_progress");
    assert_eq!(state.current().generation, 1);
}

#[tokio::test]
async fn admin_reload_rejects_non_empty_body_without_recording_attempt() {
    let config_path = temp_path("reload-non-empty-body.toml");
    let audit_path = temp_path("reload-non-empty-body.audit.jsonl");
    let spool_dir = temp_path("reload-non-empty-body-spool");
    let service_token = temp_path("reload-non-empty-body-service-token");
    std::fs::write(&service_token, "service-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let state_broker = reload_test_broker(config_path, Some(4096)).await.unwrap();
    let state = state_broker.state();
    let app = state_broker.app();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/admin/config/reload")
                .extension(ConnectInfo(
                    "127.0.0.1:43070".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-admin-reload-body")
                .header("Authorization", "Bearer admin-token")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await;
    assert_eq!(body["reasonCode"], "body_malformed");
    assert_eq!(state.current().generation, 1);
    assert!(state.last_reload_attempt().is_none());
}

#[tokio::test]
async fn signal_reload_uses_system_audit_identity() {
    let config_path = temp_path("reload-signal.toml");
    let audit_path = temp_path("reload-signal.audit.jsonl");
    let spool_dir = temp_path("reload-signal-spool");
    let service_token = temp_path("reload-signal-service-token");
    std::fs::write(&service_token, "service-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();
    let state = state_broker.state();
    let status = serde_json::to_value(&*state.build_status).unwrap();

    write_reload_config(
        &config_path,
        "NEXT",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let source = SourceContext {
        listener: "signal".to_string(),
        remote: "process".to_string(),
        proxy_chain: vec![],
        agent_request_id_generated: None,
    };
    let response = state
        .reload(
            ReloadTrigger::Signal,
            "signal".to_string(),
            "broker-req-signal".to_string(),
            source,
            None,
        )
        .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.result["generation"], 2);
    // The build status and its inventory fingerprint never change on reload.
    assert_eq!(serde_json::to_value(&*state.build_status).unwrap(), status);
    let records = read_audit_records(&audit_path);
    assert!(records.iter().any(|record| {
        record["service"] == "broker"
            && record["action"] == "config.reload"
            && record["principal"] == "system"
            && record["groups"] == json!(["system"])
            && record["source"]["listener"] == "signal"
            && record["source"]["remote"] == "process"
            && record["configGeneration"] == 2
    }));
}

#[tokio::test]
async fn reload_changing_audit_path_writes_new_generation_audit_to_new_file() {
    let config_path = temp_path("reload-audit-path.toml");
    let old_audit_path = temp_path("reload-audit-path-old.audit.jsonl");
    let new_audit_path = temp_path("reload-audit-path-new.audit.jsonl");
    let spool_dir = temp_path("reload-audit-path-spool");
    let service_token = temp_path("reload-audit-path-service-token");
    let admin_token = temp_path("reload-audit-path-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &old_audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();
    let state = state_broker.state();
    let public = state_broker.app();
    let admin = state_broker.app();

    write_reload_config(
        &config_path,
        "NEXT",
        &new_audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let reload = admin_request(
        admin,
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-reload-audit-path"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(reload.status(), StatusCode::OK);

    let new_project = invoke_fake_project(
        public,
        "127.0.0.1:42006",
        "agent-req-new-audit-path",
        "NEXT",
    )
    .await;
    assert_eq!(new_project.status(), StatusCode::OK);

    let new_records = read_audit_records(&new_audit_path);
    let old_records = read_audit_records(&old_audit_path);
    let old_reload_allow_records = old_records
        .iter()
        .filter(|record| {
            record["service"] == "broker"
                && record["action"] == "config.reload"
                && record["decision"] == "allow"
                && record["configGeneration"] == 1
        })
        .count();
    let new_reload_allow_records = new_records
        .iter()
        .filter(|record| {
            record["service"] == "broker"
                && record["action"] == "config.reload"
                && record["decision"] == "allow"
                && record["configGeneration"] == 2
        })
        .count();
    assert_eq!(old_reload_allow_records, 1);
    assert_eq!(new_reload_allow_records, 1);
    assert!(new_records.iter().any(|record| {
        record["service"] == "broker"
            && record["action"] == "config.reload"
            && record["decision"] == "allow"
            && record["configGeneration"] == 2
    }));
    assert!(new_records.iter().any(|record| {
        record["service"] == "fake"
            && record["agentRequestId"] == "agent-req-new-audit-path"
            && record["configGeneration"] == 2
    }));
    // The reload record written to both stores has a distinct auditId in each.
    let reload_record = |records: &[Value]| {
        records
            .iter()
            .find(|record| {
                record["action"] == "config.reload"
                    && record["agentRequestId"] == "agent-req-admin-reload-audit-path"
            })
            .cloned()
            .unwrap()
    };
    let old_reload = reload_record(&old_records);
    let new_reload = reload_record(&new_records);
    assert_eq!(old_reload["brokerRequestId"], new_reload["brokerRequestId"]);
    assert_ne!(old_reload["auditId"], new_reload["auditId"]);
    let node_id = state.current().runtime.node_id().to_string();
    for record in old_records.iter().chain(&new_records) {
        assert_eq!(record["nodeId"], node_id.as_str(), "{record}");
        let audit_id = uuid::Uuid::parse_str(record["auditId"].as_str().unwrap()).unwrap();
        assert_eq!(audit_id.get_version_num(), 7);
    }
}

type ConfigEdit<'a> = Box<dyn FnOnce(String) -> String + 'a>;

/// Rewrites a config written by [`write_reload_config`].
fn edit_reload_config(config_path: &Path, edit: impl FnOnce(String) -> String) {
    let raw = std::fs::read_to_string(config_path).unwrap();
    let edited = edit(raw.clone());
    assert_ne!(raw, edited, "the config edit must change the config");
    std::fs::write(config_path, edited).unwrap();
}

fn with_reload_node_id(raw: String, node_id: &str) -> String {
    raw.replacen(
        "[deployment]\n",
        &format!("[deployment]\nnode_id = \"{node_id}\"\n"),
        1,
    )
}

#[tokio::test]
async fn reload_rejects_audit_type_and_node_id_changes_until_restart() {
    let config_path = temp_path("reload-restart-only.toml");
    let audit_path = temp_path("reload-restart-only.audit.jsonl");
    let spool_dir = temp_path("reload-restart-only-spool");
    let service_token = temp_path("reload-restart-only-service-token");
    std::fs::write(&service_token, "service-token").unwrap();
    let write_base = |project: &str| {
        write_reload_config(
            &config_path,
            project,
            &audit_path,
            &service_token,
            &spool_dir,
            1024,
        );
        edit_reload_config(&config_path, |raw| {
            with_reload_node_id(raw, "reload-node-a")
        });
    };
    write_base("TEST");
    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();
    let state = state_broker.state();
    assert_eq!(state.current().runtime.node_id(), "reload-node-a");

    let sqlite_path = temp_path("reload-restart-only.audit.sqlite");
    let cases: [(&str, ConfigEdit<'_>, &str); 4] = [
        (
            "sqlite",
            Box::new(|raw| {
                raw.replace(
                    &format!("type = \"jsonl\"\npath = \"{}\"", audit_path.display()),
                    &format!("type = \"sqlite\"\npath = \"{}\"", sqlite_path.display()),
                )
            }),
            "changing audit.type from \"jsonl\" to \"sqlite\" requires a restart",
        ),
        (
            "disabled",
            Box::new(|raw| {
                raw.replace(
                    &format!(
                        "[audit]\ntype = \"jsonl\"\npath = \"{}\"\n",
                        audit_path.display()
                    ),
                    "",
                )
            }),
            "changing audit.type from \"jsonl\" to disabled (no [audit]) requires a restart",
        ),
        (
            "node-id",
            Box::new(|raw| raw.replace("reload-node-a", "reload-node-b")),
            "changing the effective node ID from \"reload-node-a\" to \"reload-node-b\" requires a restart",
        ),
        (
            "host-name-default",
            Box::new(|raw| raw.replace("node_id = \"reload-node-a\"\n", "")),
            "changing the effective node ID from \"reload-node-a\"",
        ),
    ];
    for (label, edit, expected) in cases {
        write_base("NEXT");
        edit_reload_config(&config_path, edit);
        let reload = admin_request(
            state_broker.app(),
            Method::POST,
            "/v1/admin/config/reload",
            Some(&format!("agent-req-admin-reload-restart-only-{label}")),
            Some("admin-token"),
        )
        .await;
        assert_eq!(reload.status(), StatusCode::SERVICE_UNAVAILABLE, "{label}");
        let body = response_json(reload).await;
        assert_eq!(body["reasonCode"], "config_admission_failed", "{label}");
        let message = body["error"]["message"].as_str().unwrap();
        assert!(message.contains(expected), "{label}: {message}");
        assert_eq!(state.current().generation, 1, "{label}");
        assert_eq!(state.current().runtime.node_id(), "reload-node-a");
    }
    assert!(!sqlite_path.exists());

    // The same type and node ID reload normally.
    write_base("NEXT");
    let reload = admin_request(
        state_broker.app(),
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-reload-restart-only-accepted"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(reload.status(), StatusCode::OK);
    assert_eq!(state.current().generation, 2);
    let records = read_audit_records(&audit_path);
    assert!(records.iter().any(|record| {
        record["action"] == "config.reload"
            && record["providerAudit"]["admin"]["reasonCode"] == "config_admission_failed"
            && record["agentRequestId"] == "agent-req-admin-reload-restart-only-node-id"
    }));
    assert!(
        records
            .iter()
            .all(|record| record["nodeId"] == "reload-node-a")
    );
}

#[tokio::test]
async fn startup_opens_the_sqlite_audit_database_and_reload_keeps_its_database_id() {
    let config_path = temp_path("startup-sqlite-audit.toml");
    let audit_path = temp_path("startup-sqlite-audit.audit.sqlite");
    let spool_dir = temp_path("startup-sqlite-audit-spool");
    let service_token = temp_path("startup-sqlite-audit-service-token");
    std::fs::write(&service_token, "service-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();
    let state = state_broker.state();
    let store = state.current().runtime.audit_store().cloned().unwrap();
    assert_eq!(
        store.store_type(),
        agent_access_core::AuditStoreType::Sqlite
    );
    let database_id = store.database_id().unwrap().to_string();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&audit_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let response = invoke_fake_project(
        state_broker.app(),
        "127.0.0.1:42016",
        "agent-req-sqlite-startup",
        "TEST",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // A reload of the same database opens its own writer without migrating.
    write_reload_config(
        &config_path,
        "NEXT",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let reload = admin_request(
        state_broker.app(),
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-sqlite-same-path-reload"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(reload.status(), StatusCode::OK);
    assert_eq!(state.current().generation, 2);
    assert_eq!(
        state
            .current()
            .runtime
            .audit_store()
            .and_then(|store| store.database_id()),
        Some(database_id.as_str())
    );
    let records = read_audit_records(&audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "agent-req-sqlite-startup" && record["decision"] == "allow"
    }));
    assert!(
        records.iter().any(|record| {
            record["action"] == "config.reload" && record["configGeneration"] == 2
        })
    );
}

#[tokio::test]
async fn reload_changing_the_sqlite_audit_path_requires_an_existing_database() {
    let config_path = temp_path("reload-sqlite-path.toml");
    let old_audit_path = temp_path("reload-sqlite-path-old.audit.sqlite");
    let new_audit_path = temp_path("reload-sqlite-path-new.audit.sqlite");
    let spool_dir = temp_path("reload-sqlite-path-spool");
    let service_token = temp_path("reload-sqlite-path-service-token");
    std::fs::write(&service_token, "service-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &old_audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();
    let state = state_broker.state();
    let old_database_id = state
        .current()
        .runtime
        .audit_store()
        .and_then(|store| store.database_id())
        .unwrap()
        .to_string();
    let reload = |request_id: &'static str| {
        admin_request(
            state_broker.app(),
            Method::POST,
            "/v1/admin/config/reload",
            Some(request_id),
            Some("admin-token"),
        )
    };

    // Reload never creates or migrates an audit database.
    write_reload_config(
        &config_path,
        "NEXT",
        &new_audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let rejected = reload("agent-req-sqlite-path-missing").await;
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(rejected).await;
    assert_eq!(body["reasonCode"], "config_admission_failed");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains("does not exist"), "{message}");
    assert_eq!(state.current().generation, 1);
    assert!(!new_audit_path.exists());

    // Once a startup has created it, the reload opens and validates it
    // before activation.
    let creator = BrokerRuntime::new(fake_config(new_audit_path.to_str().unwrap())).unwrap();
    let new_database_id = creator
        .audit_store()
        .and_then(|store| store.database_id())
        .unwrap()
        .to_string();
    creator
        .shutdown_own_audit(Duration::from_secs(5))
        .await
        .unwrap();
    drop(creator);
    let accepted = reload("agent-req-sqlite-path-accepted").await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(state.current().generation, 2);
    assert_eq!(
        state
            .current()
            .runtime
            .audit_store()
            .and_then(|store| store.database_id()),
        Some(new_database_id.as_str())
    );
    assert_ne!(new_database_id, old_database_id);

    let reload_record = |path: &Path| {
        read_audit_records(path).into_iter().find(|record| {
            record["action"] == "config.reload"
                && record["agentRequestId"] == "agent-req-sqlite-path-accepted"
        })
    };
    let new_reload = reload_record(&new_audit_path).expect("reload record in the new store");
    let old_reload = reload_record(&old_audit_path).expect("reload record in the old store");
    assert_eq!(new_reload["brokerRequestId"], old_reload["brokerRequestId"]);
    assert_ne!(new_reload["auditId"], old_reload["auditId"]);
    assert!(read_audit_records(&old_audit_path).iter().any(|record| {
        record["agentRequestId"] == "agent-req-sqlite-path-missing"
            && record["providerAudit"]["admin"]["reasonCode"] == "config_admission_failed"
    }));
}

/// Another process holding the state locks the tests contend for.
const TEST_LOCK_HOLDER: agent_access_core::StateLockHolder<'static> =
    agent_access_core::StateLockHolder::new("test-holder", "0.0.0", "test-holder-node");

#[tokio::test]
async fn admin_reload_candidate_state_lock_conflict_keeps_active_generation() {
    let config_path = temp_path("reload-lock-conflict.toml");
    let old_audit_path = temp_path("reload-lock-conflict-old.audit.jsonl");
    let new_audit_path = temp_path("reload-lock-conflict-new.audit.jsonl");
    let old_spool_dir = temp_path("reload-lock-conflict-old-spool");
    let hold_spool_dir = temp_path("reload-lock-conflict-hold-spool");
    let service_token = temp_path("reload-lock-conflict-service-token");
    let admin_token = temp_path("reload-lock-conflict-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &old_audit_path,
        &service_token,
        &old_spool_dir,
        1024,
    );

    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();

    let state = state_broker.state();
    let admin = state_broker.app();
    let mut holder_config = fake_config(new_audit_path.to_str().unwrap());
    holder_config.limits.upload_spool_dir = hold_spool_dir.display().to_string();
    let _held =
        StateLockSet::acquire_for_config(&holder_config, &config_path, &TEST_LOCK_HOLDER, None)
            .unwrap();

    write_reload_config(
        &config_path,
        "NEXT",
        &new_audit_path,
        &service_token,
        &old_spool_dir,
        1536,
    );
    let reload = admin_request_with_remote(
        admin,
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-reload-lock-conflict"),
        Some("admin-token"),
        "127.0.0.1:43060",
    )
    .await;

    assert_eq!(reload.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(reload).await;
    assert_eq!(body["reasonCode"], "config_admission_failed");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains("audit state lock is held"), "{message}");
    assert!(
        message.contains(r#""nodeId":"test-holder-node""#),
        "{message}"
    );
    assert_eq!(state.current().generation, 1);
}

#[tokio::test]
async fn admin_reload_candidate_upload_spool_lock_conflict_keeps_active_generation() {
    let config_path = temp_path("reload-spool-lock-conflict.toml");
    let audit_path = temp_path("reload-spool-lock-conflict.audit.jsonl");
    let old_spool_dir = temp_path("reload-spool-lock-conflict-old-spool");
    let new_spool_dir = temp_path("reload-spool-lock-conflict-new-spool");
    let service_token = temp_path("reload-spool-lock-conflict-service-token");
    let admin_token = temp_path("reload-spool-lock-conflict-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &old_spool_dir,
        1024,
    );

    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();

    let state = state_broker.state();
    let admin = state_broker.app();
    let mut holder_config = fake_config("");
    holder_config.limits.upload_spool_dir = new_spool_dir.display().to_string();
    let _held =
        StateLockSet::acquire_for_config(&holder_config, &config_path, &TEST_LOCK_HOLDER, None)
            .unwrap();

    write_reload_config(
        &config_path,
        "NEXT",
        &audit_path,
        &service_token,
        &new_spool_dir,
        1536,
    );
    let reload = admin_request_with_remote(
        admin,
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-reload-spool-lock-conflict"),
        Some("admin-token"),
        "127.0.0.1:43063",
    )
    .await;

    assert_eq!(reload.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(reload).await;
    assert_eq!(body["reasonCode"], "config_admission_failed");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("upload_spool state lock is held")
    );
    assert_eq!(state.current().generation, 1);
}

#[tokio::test]
async fn admin_reload_candidate_managed_store_lock_conflict_keeps_active_generation() {
    let config_path = temp_path("reload-store-lock-conflict.toml");
    let audit_path = temp_path("reload-store-lock-conflict.audit.jsonl");
    let spool_dir = temp_path("reload-store-lock-conflict-spool");
    let old_store_path = temp_path("reload-store-lock-conflict-old-store/managed.sqlite3");
    let new_store_path = temp_path("reload-store-lock-conflict-new-store/managed.sqlite3");
    let service_token = temp_path("reload-store-lock-conflict-service-token");
    let admin_token = temp_path("reload-store-lock-conflict-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config_with_managed_store(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
        &old_store_path,
    );

    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();

    let state = state_broker.state();
    let admin = state_broker.app();
    let mut holder_config = fake_config("");
    holder_config.managed_store = Some(agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: new_store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    let _held =
        StateLockSet::acquire_for_config(&holder_config, &config_path, &TEST_LOCK_HOLDER, None)
            .unwrap();

    write_reload_config_with_managed_store(
        &config_path,
        "NEXT",
        &audit_path,
        &service_token,
        &spool_dir,
        1536,
        &new_store_path,
    );
    let reload = admin_request_with_remote(
        admin,
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-reload-store-lock-conflict"),
        Some("admin-token"),
        "127.0.0.1:43064",
    )
    .await;

    assert_eq!(reload.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(reload).await;
    assert_eq!(body["reasonCode"], "config_admission_failed");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("managed_store state lock is held")
    );
    assert_eq!(state.current().generation, 1);
}

#[tokio::test]
async fn reload_changing_upload_spool_keeps_old_snapshot_lock_alive() {
    let config_path = temp_path("reload-spool-lock-retention.toml");
    let audit_path = temp_path("reload-spool-lock-retention.audit.jsonl");
    let old_spool_dir = temp_path("reload-spool-lock-retention-old-spool");
    let new_spool_dir = temp_path("reload-spool-lock-retention-new-spool");
    let service_token = temp_path("reload-spool-lock-retention-service-token");
    let admin_token = temp_path("reload-spool-lock-retention-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &old_spool_dir,
        1024,
    );

    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();

    let state = state_broker.state();
    let old_snapshot = state.current();
    let admin = state_broker.app();
    write_reload_config(
        &config_path,
        "NEXT",
        &audit_path,
        &service_token,
        &new_spool_dir,
        1536,
    );

    let reload = admin_request_with_remote(
        admin,
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-reload-spool-lock"),
        Some("admin-token"),
        "127.0.0.1:43061",
    )
    .await;

    assert_eq!(reload.status(), StatusCode::OK);
    assert_eq!(state.current().generation, 2);
    let mut old_spool_only = fake_config("");
    old_spool_only.limits.upload_spool_dir = old_spool_dir.display().to_string();
    let conflict =
        StateLockSet::acquire_for_config(&old_spool_only, &config_path, &TEST_LOCK_HOLDER, None)
            .unwrap_err();
    assert_eq!(conflict.kind(), StateLockFailureKind::Held);
    let old_spool_identity = old_snapshot
        .state_locks
        .infos()
        .into_iter()
        .find(|info| info.domains == vec![StateLockDomain::UploadSpool])
        .unwrap()
        .identity;

    let admin = state_broker.app();
    write_reload_config(
        &config_path,
        "BACK",
        &audit_path,
        &service_token,
        &old_spool_dir,
        1024,
    );
    let reload_back = admin_request_with_remote(
        admin,
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-reload-spool-lock-back"),
        Some("admin-token"),
        "127.0.0.1:43062",
    )
    .await;

    assert_eq!(reload_back.status(), StatusCode::OK);
    let back_snapshot = state.current();
    assert_eq!(back_snapshot.generation, 3);
    assert!(
        back_snapshot
            .state_locks
            .shares_identity_handle_with(old_snapshot.state_locks.as_ref(), &old_spool_identity)
    );

    drop(old_snapshot);
    let conflict =
        StateLockSet::acquire_for_config(&old_spool_only, &config_path, &TEST_LOCK_HOLDER, None)
            .unwrap_err();
    assert_eq!(conflict.kind(), StateLockFailureKind::Held);
}

#[tokio::test]
async fn reload_equivalent_audit_path_spelling_does_not_duplicate_success_audit() {
    let config_path = temp_path("reload-audit-path-equivalent.toml");
    let audit_dir = temp_path("reload-audit-path-equivalent-dir");
    create_private_dir(&audit_dir);
    let audit_path = audit_dir.join("audit.jsonl");
    let equivalent_audit_path = audit_dir.join(".").join("audit.jsonl");
    let spool_dir = temp_path("reload-audit-path-equivalent-spool");
    let service_token = temp_path("reload-audit-path-equivalent-service-token");
    let admin_token = temp_path("reload-audit-path-equivalent-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();
    let admin = state_broker.app();

    write_reload_config(
        &config_path,
        "NEXT",
        &equivalent_audit_path,
        &service_token,
        &spool_dir,
        1024,
    );
    let reload = admin_request(
        admin,
        Method::POST,
        "/v1/admin/config/reload",
        Some("agent-req-admin-reload-equivalent-audit-path"),
        Some("admin-token"),
    )
    .await;
    let reload_status = reload.status();
    let reload_body = response_json(reload).await;
    assert_eq!(
        reload_status,
        StatusCode::OK,
        "reload response: {reload_body}"
    );

    let records = read_audit_records(&audit_path);
    let reload_allow_records = records
        .iter()
        .filter(|record| {
            record["service"] == "broker"
                && record["action"] == "config.reload"
                && record["decision"] == "allow"
        })
        .count();
    assert_eq!(reload_allow_records, 1);
}

#[tokio::test]
async fn source_rate_buckets_survive_successful_reload() {
    let config_path = temp_path("reload-rate-bucket.toml");
    let audit_path = temp_path("reload-rate-bucket.audit.jsonl");
    let spool_dir = temp_path("reload-rate-bucket-spool");
    let service_token = temp_path("reload-rate-bucket-service-token");
    let admin_token = temp_path("reload-rate-bucket-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config_with_source_rate(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
        1,
    );
    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();
    let state = state_broker.state();
    let public = state_broker.app();

    let first = invoke_fake_project(
        public.clone(),
        "127.0.0.1:42007",
        "agent-req-rate-before-reload",
        "TEST",
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    write_reload_config_with_source_rate(
        &config_path,
        "NEXT",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
        1,
    );
    let source = SourceContext {
        listener: "signal".to_string(),
        remote: "process".to_string(),
        proxy_chain: vec![],
        agent_request_id_generated: None,
    };
    let reload = state
        .reload(
            ReloadTrigger::Signal,
            "signal-rate-bucket".to_string(),
            "broker-req-rate-bucket".to_string(),
            source,
            None,
        )
        .await;
    assert_eq!(reload.status, StatusCode::OK);

    let second = invoke_fake_project(
        public,
        "127.0.0.1:42008",
        "agent-req-rate-after-reload",
        "NEXT",
    )
    .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response_json(second).await["reasonCode"], "rate_limited");
}

#[tokio::test]
async fn admin_status_requires_request_id_and_bearer_token() {
    let config_path = temp_path("reload-auth.toml");
    let audit_path = temp_path("reload-auth.audit.jsonl");
    let spool_dir = temp_path("reload-auth-spool");
    let service_token = temp_path("reload-auth-service-token");
    let admin_token = temp_path("reload-auth-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );

    let broker = TestBroker::start_with(
        TestBroker::builder_at(config_path.clone())
            .reload_timeout(Duration::from_secs(1))
            .shutdown_timeout(Duration::from_secs(1)),
    )
    .await;
    let admin = broker.app();

    let missing_request_id = admin_request(
        admin.clone(),
        Method::GET,
        "/v1/admin/config/status",
        None,
        Some("admin-token"),
    )
    .await;
    assert_eq!(missing_request_id.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(missing_request_id).await["reasonCode"],
        "request_id_missing"
    );

    let missing_auth = admin_request(
        admin.clone(),
        Method::GET,
        "/v1/admin/config/status",
        Some("agent-req-admin-missing-auth"),
        None,
    )
    .await;
    assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);
    let missing_auth_body = response_json(missing_auth).await;
    assert_eq!(missing_auth_body["operation"], "config.status");
    assert_eq!(missing_auth_body["reasonCode"], "identity_required");

    let invalid_auth = admin_request(
        admin.clone(),
        Method::GET,
        "/v1/admin/config/status",
        Some("agent-req-admin-invalid-auth"),
        Some("wrong-token"),
    )
    .await;
    assert_eq!(invalid_auth.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(invalid_auth).await["reasonCode"],
        "identity_invalid"
    );

    let status = admin_request(
        admin,
        Method::GET,
        "/v1/admin/config/status",
        Some("agent-req-admin-status"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(status.status(), StatusCode::OK);
    let status_body = response_json(status).await;
    assert_eq!(status_body["operation"], "config.status");
    assert_eq!(status_body["decision"], "allow");
    assert_eq!(status_body["result"]["generation"], 1);
    assert_eq!(status_body["result"]["policyGeneration"], 1);
    assert_eq!(status_body["result"]["identityAuthority"], "toml");
    assert_eq!(status_body["result"]["policyAuthority"], "toml");
    assert!(status_body["result"].get("configHash").is_some());
    assert!(status_body["result"].get("configPath").is_none());
    assert_eq!(status_body["result"]["bodyHardCapBytes"], 1024);
    assert_eq!(status_body["result"]["reloadTimeoutMs"], 1000);
    assert_eq!(status_body["result"]["shutdownTimeoutMs"], 1000);
}

#[tokio::test]
async fn storeless_classless_admin_store_routes_fail_closed() {
    let config_path = temp_path("reload-storeless-admin.toml");
    let audit_path = temp_path("reload-storeless-admin.audit.jsonl");
    let spool_dir = temp_path("reload-storeless-admin-spool");
    let service_token = temp_path("reload-storeless-admin-service-token");
    std::fs::write(&service_token, "service-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        1024,
    );

    let broker = TestBroker::start_with(
        TestBroker::builder_at(config_path.clone())
            .reload_timeout(Duration::from_secs(1))
            .shutdown_timeout(Duration::from_secs(1)),
    )
    .await;
    let admin = broker.app();

    let response = admin_request(
        admin,
        Method::GET,
        "/v1/admin/store/status",
        Some("agent-req-storeless-admin-store-status"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(response).await;
    assert_eq!(body["operation"], "admin.store.status");
    assert_eq!(body["reasonCode"], "managed_store_unavailable");
}

#[tokio::test]
async fn reload_startup_validates_body_hard_cap_and_timeout() {
    let config_path = temp_path("reload-startup-validation.toml");
    let audit_path = temp_path("reload-startup-validation.audit.jsonl");
    let spool_dir = temp_path("reload-startup-validation-spool");
    let service_token = temp_path("reload-startup-validation-service-token");
    std::fs::write(&service_token, "service-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool_dir,
        2048,
    );

    let hard_cap_error = match TestBroker::try_start_with(
        TestBroker::builder_at(config_path)
            .body_hard_cap(1024)
            .reload_timeout(Duration::from_secs(1))
            .shutdown_timeout(Duration::from_secs(1)),
    )
    .await
    {
        Ok(_) => panic!("expected hard cap validation to fail"),
        Err(error) => error.to_string(),
    };
    assert!(hard_cap_error.contains("max_http_body_bytes"));

    assert!(validate_reload_timeout(Duration::from_millis(0)).is_err());
    assert!(validate_reload_timeout(Duration::from_millis(300_001)).is_err());
    assert!(validate_reload_timeout(Duration::from_millis(300_000)).is_ok());
    assert!(validate_shutdown_timeout(Duration::from_millis(0)).is_err());
    assert!(validate_shutdown_timeout(Duration::from_millis(300_001)).is_err());
    assert!(validate_shutdown_timeout(Duration::from_millis(300_000)).is_ok());
}

#[tokio::test]
async fn invoke_download_can_return_raw_stream_with_metadata_header() {
    let audit_path = temp_path("broker-download.audit.sqlite");
    let invocations = Arc::new(AtomicUsize::new(0));
    let runtime_broker = TestBroker::start_with_providers(
        &download_config(audit_path.to_str().unwrap()),
        vec![Arc::new(TestDownloadProvider {
            invocations: invocations.clone(),
            with_stream: true,
            live_stream: false,
        })],
    )
    .await;
    let app = runtime_broker.app();

    let raw = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/attachment.download")
                .extension(ConnectInfo(
                    "127.0.0.1:40009".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-download-raw")
                .header(ACCEPT, RAW_RESULT_MIME)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"inputs":{"project":"TEST"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(raw.status(), StatusCode::OK);
    assert_eq!(
        raw.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
        "text/plain"
    );
    let metadata_header = raw
        .headers()
        .get(RESULT_METADATA_HEADER)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let raw_body = axum::body::to_bytes(raw.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&raw_body[..], b"download bytes");
    let metadata_bytes = BASE64.decode(metadata_header).unwrap();
    let metadata: Value = serde_json::from_slice(&metadata_bytes).unwrap();
    assert_eq!(metadata["decision"], "allow");
    assert_eq!(metadata["result"]["filename"], "evidence.txt");
    assert!(metadata["result"].get("contentBase64").is_none());
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let repeated_accept = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/attachment.download")
                .extension(ConnectInfo(
                    "127.0.0.1:40010".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-download-raw-2")
                .header(ACCEPT, "application/json")
                .header(ACCEPT, RAW_RESULT_MIME)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"inputs":{"project":"TEST"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(repeated_accept.status(), StatusCode::OK);
    let repeated_body = axum::body::to_bytes(repeated_accept.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&repeated_body[..], b"download bytes");
    assert_eq!(invocations.load(Ordering::SeqCst), 2);

    let live_invocations = Arc::new(AtomicUsize::new(0));
    // A second broker locks its own audit store.
    let live_audit_path = temp_path("broker-download-live.audit.sqlite");
    let live_raw_broker = TestBroker::start_with_providers(
        &download_config(live_audit_path.to_str().unwrap()),
        vec![Arc::new(TestDownloadProvider {
            invocations: live_invocations.clone(),
            with_stream: true,
            live_stream: true,
        })],
    )
    .await;
    let live_app = live_raw_broker.app();
    let live_response = live_app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/attachment.download")
                .extension(ConnectInfo(
                    "127.0.0.1:40011".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-download-live-raw")
                .header(ACCEPT, RAW_RESULT_MIME)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"inputs":{"project":"TEST"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(live_response.status(), StatusCode::OK);
    let live_body = axum::body::to_bytes(live_response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&live_body[..], b"download bytes");
    assert_eq!(live_invocations.load(Ordering::SeqCst), 1);

    let json_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/attachment.download")
                .extension(ConnectInfo(
                    "127.0.0.1:40011".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-download-json")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"inputs":{"project":"TEST"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json_response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let json_body = axum::body::to_bytes(json_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&json_body).unwrap();
    assert_eq!(value["decision"], "deny");
    assert_eq!(value["reasonCode"], "body_format_unsupported");
    assert!(!String::from_utf8_lossy(&json_body).contains("download bytes"));
    assert_eq!(invocations.load(Ordering::SeqCst), 2);

    let q_zero = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/attachment.download")
                .extension(ConnectInfo(
                    "127.0.0.1:40012".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-download-q-zero")
                .header(ACCEPT, "application/octet-stream;q=0")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"inputs":{"project":"TEST"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(q_zero.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(invocations.load(Ordering::SeqCst), 2);

    let multipart = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/attachment.download")
                .extension(ConnectInfo(
                    "127.0.0.1:40014".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-download-multipart")
                .header(ACCEPT, RAW_RESULT_MIME)
                .header("Content-Type", "multipart/form-data; boundary=ignored")
                .body(Body::from("this body must not be inspected"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(multipart.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(invocations.load(Ordering::SeqCst), 2);

    let audit = read_audit_text(&audit_path) + &read_audit_text(&live_audit_path);
    assert!(audit.contains("\"service\":\"jira\""));
    assert!(audit.contains("\"action\":\"attachment.download\""));
    assert!(audit.contains("\"reasonCode\":\"body_format_unsupported\""));
    assert!(!audit.contains("download bytes"));
}

#[tokio::test]
async fn raw_live_download_holds_concurrency_permits_until_body_drops() {
    let audit_path = temp_path("broker-download-permits.audit.jsonl");
    let mut config = download_config(audit_path.to_str().unwrap());
    config.limits.max_concurrent_requests = 1;
    config.limits.max_concurrent_requests_per_principal = 1;
    let runtime_broker = TestBroker::start_with_providers(
        &config,
        vec![Arc::new(TestDownloadProvider {
            invocations: Arc::new(AtomicUsize::new(0)),
            with_stream: true,
            live_stream: true,
        })],
    )
    .await;
    let app = runtime_broker.app();

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/attachment.download")
                .extension(ConnectInfo(
                    "127.0.0.1:40020".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-download-held")
                .header(ACCEPT, RAW_RESULT_MIME)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"inputs":{"project":"TEST"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/attachment.download")
                .extension(ConnectInfo(
                    "127.0.0.1:40021".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-download-rejected")
                .header(ACCEPT, RAW_RESULT_MIME)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"inputs":{"project":"TEST"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let second_json = response_json(second).await;
    assert_eq!(second_json["reasonCode"], "concurrency_limited");

    drop(first);

    let third = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/attachment.download")
                .extension(ConnectInfo(
                    "127.0.0.1:40022".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-download-after-drop")
                .header(ACCEPT, RAW_RESULT_MIME)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"inputs":{"project":"TEST"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(third.status(), StatusCode::OK);
    let third_body = axum::body::to_bytes(third.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&third_body[..], b"download bytes");
}

#[tokio::test]
async fn missing_required_download_stream_is_audited_as_error() {
    let audit_path = temp_path("broker-download-missing-stream.audit.jsonl");
    let invocations = Arc::new(AtomicUsize::new(0));
    let runtime_broker = TestBroker::start_with_providers(
        &download_config(audit_path.to_str().unwrap()),
        vec![Arc::new(TestDownloadProvider {
            invocations: invocations.clone(),
            with_stream: false,
            live_stream: false,
        })],
    )
    .await;
    let app = runtime_broker.app();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/attachment.download")
                .extension(ConnectInfo(
                    "127.0.0.1:40013".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-download-missing-stream")
                .header(ACCEPT, RAW_RESULT_MIME)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"inputs":{"project":"TEST"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["decision"], "error");
    assert_eq!(value["reasonCode"], "upstream_protocol_failed");
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let audit = std::fs::read_to_string(audit_path).unwrap();
    assert!(audit.contains("\"decision\":\"error\""));
    assert!(audit.contains("\"reasonCode\":\"upstream_protocol_failed\""));
    assert!(!audit.contains("\"decision\":\"allow\""));
}

#[tokio::test]
async fn non_health_routes_require_valid_agent_request_id() {
    let broker = TestBroker::start_config(&fake_config("")).await;
    let app = broker.app();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/services")
                .extension(ConnectInfo(
                    "127.0.0.1:39991".parse::<SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["reasonCode"], "request_id_missing");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/fake/echo")
                .extension(ConnectInfo(
                    "127.0.0.1:40001".parse::<SocketAddr>().unwrap(),
                ))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"inputs":{"project":"TEST","message":"hello"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["reasonCode"], "request_id_missing");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/services")
                .extension(ConnectInfo(
                    "127.0.0.1:39992".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "bad id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["reasonCode"], "request_id_invalid");

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/services")
                .extension(ConnectInfo(
                    "127.0.0.1:39993".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, " agent-req ")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["reasonCode"], "request_id_invalid");
}

#[tokio::test]
async fn service_and_action_path_segments_are_validated_at_ingress() {
    let broker = TestBroker::start_config(&fake_config("")).await;
    let app = broker.app();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/services/Fake")
                .extension(ConnectInfo(
                    "127.0.0.1:39994".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-service")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["reasonCode"], "input_invalid");

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/fake/BadAction")
                .extension(ConnectInfo(
                    "127.0.0.1:40003".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-action")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"inputs":{"project":"TEST","message":"hello"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["reasonCode"], "input_invalid");
}

#[tokio::test]
async fn malformed_invoke_body_returns_envelope_and_audit() {
    let audit_path = temp_path("malformed-body.audit.jsonl");
    let broker = TestBroker::start_config(&fake_config(audit_path.to_str().unwrap())).await;
    let app = broker.app();
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/fake/echo")
                .extension(ConnectInfo(
                    "127.0.0.1:40002".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-bad-json")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"inputs":"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["decision"], "deny");
    assert_eq!(value["reasonCode"], "input_invalid");
    let audit = std::fs::read_to_string(audit_path).unwrap();
    assert!(audit.contains("\"reasonCode\":\"input_invalid\""));
}

#[tokio::test]
async fn admin_principals_patch_distinguishes_null_from_omitted_fields() {
    let admin_token = temp_path("principal-patch-admin-token");
    let store_path = temp_path("principal-patch-store.sqlite");
    let audit_path = temp_path("principal-patch.audit.jsonl");
    std::fs::write(&admin_token, "admin-token").unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "bootstrap-admin".to_string(),
            kind: "static_principals".to_string(),
            header: "X-Agent-Access-Identity-Token".to_string(),
            scheme: "raw".to_string(),
            principals: vec![StaticPrincipalConfig {
                principal: "admin".to_string(),
                token_refs: vec![format!("file:{}", admin_token.display())],
            }],
        }],
        groups: vec![],
    };
    config.managed_store = Some(agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.management = agent_access_core::ManagementConfig {
        enabled: true,
        admin_principals: vec!["admin".to_string()],
        admin_groups: vec![],
        allow_classless_admin_identities: true,
        allow_classless_user_management: false,
        initial_admin: agent_access_core::InitialAdminConfig::default(),
    };
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();

    let create = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals",
        "principal-patch-create",
        "X-Agent-Access-Identity-Token",
        "admin-token",
        Some(
            r#"{"principalId":"alice","kind":"user","displayName":"Alice","email":"alice@example.com"}"#,
        ),
    )
    .await;
    assert_eq!(create.status(), StatusCode::OK);

    let update_display_only = authed_json_request(
        app.clone(),
        Method::PATCH,
        "/v1/admin/principals/alice",
        "principal-patch-display-only",
        "X-Agent-Access-Identity-Token",
        "admin-token",
        Some(r#"{"displayName":"Alice Example"}"#),
    )
    .await;
    assert_eq!(update_display_only.status(), StatusCode::OK);
    let update_display_only_body = response_json(update_display_only).await;
    assert_eq!(
        update_display_only_body["result"]["displayName"],
        "Alice Example"
    );
    assert_eq!(
        update_display_only_body["result"]["email"],
        "alice@example.com"
    );

    let clear_email_only = authed_json_request(
        app.clone(),
        Method::PATCH,
        "/v1/admin/principals/alice",
        "principal-patch-clear-email-only",
        "X-Agent-Access-Identity-Token",
        "admin-token",
        Some(r#"{"email":null}"#),
    )
    .await;
    assert_eq!(clear_email_only.status(), StatusCode::OK);
    let clear_email_only_body = response_json(clear_email_only).await;
    assert_eq!(
        clear_email_only_body["result"]["displayName"],
        "Alice Example"
    );
    assert!(clear_email_only_body["result"]["email"].is_null());

    let clear = authed_json_request(
        app.clone(),
        Method::PATCH,
        "/v1/admin/principals/alice",
        "principal-patch-clear",
        "X-Agent-Access-Identity-Token",
        "admin-token",
        Some(r#"{"displayName":null,"email":null}"#),
    )
    .await;
    assert_eq!(clear.status(), StatusCode::OK);
    let clear_body = response_json(clear).await;
    assert!(clear_body["result"]["displayName"].is_null());
    assert!(clear_body["result"]["email"].is_null());

    let create_service_account = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals",
        "principal-create-service-account",
        "X-Agent-Access-Identity-Token",
        "admin-token",
        Some(
            r#"{"principalId":"svc-reporter","kind":"service_account","displayName":"Reporting Service"}"#,
        ),
    )
    .await;
    assert_eq!(create_service_account.status(), StatusCode::OK);
    let create_service_account = response_json(create_service_account).await;
    assert_eq!(create_service_account["result"]["kind"], "service_account");
    assert_eq!(
        create_service_account["result"]["displayName"],
        "Reporting Service"
    );

    let service_account_admin_role = authed_json_request(
        app.clone(),
        Method::PATCH,
        "/v1/admin/principals/svc-reporter/access",
        "principal-service-account-admin-denied",
        "X-Agent-Access-Identity-Token",
        "admin-token",
        Some(r#"{"role":"admin"}"#),
    )
    .await;
    assert_eq!(service_account_admin_role.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(service_account_admin_role).await["reasonCode"],
        "input_invalid"
    );

    let inspect = authed_json_request(
        app,
        Method::GET,
        "/v1/admin/principals/alice",
        "principal-patch-inspect",
        "X-Agent-Access-Identity-Token",
        "admin-token",
        None,
    )
    .await;
    assert_eq!(inspect.status(), StatusCode::OK);
    let inspect_body = response_json(inspect).await;
    assert!(inspect_body["result"]["displayName"].is_null());
    assert!(inspect_body["result"]["email"].is_null());
}

#[tokio::test]
async fn management_sqlite_failure_is_logged_but_not_returned() {
    let captured = install_trace_capture().start();
    let fixture = token_context_fixture().await;
    let snapshot = fixture.state.current();
    let conn =
        rusqlite::Connection::open(snapshot.runtime.managed_store().unwrap().path()).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_security_test_token BEFORE INSERT ON broker_tokens BEGIN SELECT RAISE(ABORT, 'private-sqlite-security-marker'); END;").unwrap();
    let response = captured
        .run(authed_json_request(
            fixture.app,
            Method::POST,
            "/v1/admin/principals/alice/tokens",
            "security-store-error",
            "Authorization",
            format!("Bearer {}", fixture.admin_token),
            Some(r#"{"name":"test","tokenClass":"user_manage","ttl":"2h"}"#),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers()[axum::http::header::CACHE_CONTROL],
        "no-store"
    );
    let body = response_json(response).await;
    assert_eq!(body["reasonCode"], "managed_store_unavailable");
    assert_eq!(body["error"]["message"], "managed store is unavailable");
    assert!(!body.to_string().contains("private-sqlite-security-marker"));
    let events = captured.take_events();
    assert!(events.iter().any(|event| {
        event
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|error| error.contains("private-sqlite-security-marker"))
            && event.get("request_id").and_then(Value::as_str) == Some("security-store-error")
    }));
}

#[tokio::test]
async fn token_context_options_issuance_projection_and_fail_closed_http_contract() {
    let fixture = token_context_fixture().await;

    let unauthenticated = admin_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/tokens/options",
        Some("token-options-unauthenticated"),
        None,
    )
    .await;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let alice_options = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/tokens/options",
        "token-options-alice",
        "Authorization",
        format!("Bearer {}", fixture.alice_user_token),
        None,
    )
    .await;
    assert_eq!(alice_options.status(), StatusCode::OK);
    let alice_options = response_json(alice_options).await;
    assert_eq!(
        alice_options["result"]["executionContexts"],
        json!(["external", "internal", "partner"])
    );
    assert_eq!(
        alice_options["result"]["services"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(alice_options["result"]["services"][0]["service"], "fake");
    assert_eq!(
        alice_options["result"]["services"][0]["executionContexts"],
        json!(["external", "internal", "partner"])
    );
    let echo = &alice_options["result"]["services"][0]["actions"][0];
    assert_eq!(echo["action"], "echo");
    assert_eq!(echo["requiredScopeTypes"], json!(["project"]));
    assert_eq!(
        echo["executionContexts"],
        json!(["external", "internal", "partner"])
    );
    assert_eq!(echo["resourceType"], "fake_project");
    for (context, project) in [
        ("external", "TEST"),
        ("internal", "OPS"),
        ("partner", "PARTNER"),
    ] {
        assert_eq!(
            echo["effectiveAccessByExecutionContext"][context],
            json!([{ "included": [{"kind":"exact", "value": project}], "excluded": [] }])
        );
    }

    let bob_options = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/tokens/options",
        "token-options-bob-empty",
        "Authorization",
        format!("Bearer {}", fixture.bob_user_token),
        None,
    )
    .await;
    assert_eq!(bob_options.status(), StatusCode::OK);
    let bob_options = response_json(bob_options).await;
    assert_eq!(bob_options["result"]["executionContexts"], json!([]));
    assert_eq!(bob_options["result"]["services"], json!([]));

    let bob_issue_without_invocation_grant = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/tokens",
        "token-issue-bob-no-invocation-grant",
        "Authorization",
        format!("Bearer {}", fixture.bob_user_token),
        Some(r#"{"name":"dormant","allowedExecutionContexts":["external"]}"#),
    )
    .await;
    assert_eq!(
        bob_issue_without_invocation_grant.status(),
        StatusCode::FORBIDDEN
    );
    let bob_issue_without_invocation_grant =
        response_json(bob_issue_without_invocation_grant).await;
    assert_eq!(
        bob_issue_without_invocation_grant["reasonCode"],
        "service_action_denied"
    );
    assert_eq!(
        bob_issue_without_invocation_grant["error"]["message"],
        "agent token issuance requires at least one effective invocation grant"
    );

    let non_admin_options = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/principals/alice/agent-token-options",
        "token-options-admin-denied",
        "Authorization",
        format!("Bearer {}", fixture.alice_user_token),
        None,
    )
    .await;
    assert_eq!(non_admin_options.status(), StatusCode::FORBIDDEN);
    let admin_options = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/principals/alice/agent-token-options",
        "token-options-admin-alice",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        None,
    )
    .await;
    assert_eq!(admin_options.status(), StatusCode::OK);
    assert_eq!(
        response_json(admin_options).await["result"]["executionContexts"],
        json!(["external", "internal", "partner"])
    );
    let actor_options = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/principals/admin/agent-token-options",
        "token-options-admin-actor-empty",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        None,
    )
    .await;
    assert_eq!(actor_options.status(), StatusCode::OK);
    assert_eq!(
        response_json(actor_options).await["result"]["services"],
        json!([])
    );

    for (request_id, body, expected_message) in [
        (
            "self-context-missing",
            r#"{"name":"missing"}"#,
            "missing field `allowedExecutionContexts`",
        ),
        (
            "self-context-zero",
            r#"{"name":"zero","allowedExecutionContexts":[]}"#,
            "allowedExecutionContexts must not be empty",
        ),
        (
            "self-context-duplicate",
            r#"{"name":"duplicate","allowedExecutionContexts":["external","external"]}"#,
            "allowedExecutionContexts contains duplicate context external",
        ),
        (
            "self-context-unavailable",
            r#"{"name":"unknown","allowedExecutionContexts":["workstation"]}"#,
            "allowedExecutionContexts context is not available to the principal: workstation",
        ),
        (
            "self-context-unconfigured",
            r#"{"name":"unknown","allowedExecutionContexts":["retired"]}"#,
            "allowedExecutionContexts references unconfigured context retired",
        ),
        (
            "self-device-name-removed",
            r#"{"name":"legacy","deviceName":"workstation","allowedExecutionContexts":["external"]}"#,
            "unknown field `deviceName`",
        ),
    ] {
        let response = authed_json_request(
            fixture.app.clone(),
            Method::POST,
            "/v1/tokens",
            request_id,
            "Authorization",
            format!("Bearer {}", fixture.alice_user_token),
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{request_id}");
        let response = response_json(response).await;
        assert_eq!(response["reasonCode"], "input_invalid");
        assert!(
            response["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(expected_message)),
            "unexpected {request_id} response: {response:#}"
        );
    }

    let self_multiple = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/tokens",
        "self-context-multiple",
        "Authorization",
        format!("Bearer {}", fixture.alice_user_token),
        Some(r#"{"name":"multiple","allowedExecutionContexts":["internal","external"]}"#),
    )
    .await;
    assert_eq!(self_multiple.status(), StatusCode::OK);
    let self_multiple = response_json(self_multiple).await;
    assert_eq!(
        self_multiple["result"]["record"]["scopes"]["allowedExecutionContexts"],
        json!(["internal", "external"])
    );
    let self_multiple_token_id = self_multiple["result"]["record"]["tokenId"]
        .as_str()
        .unwrap()
        .to_string();
    let self_multiple_secret = self_multiple["result"]["token"]
        .as_str()
        .unwrap()
        .to_string();

    let self_finite = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/tokens",
        "self-restriction-finite",
        "Authorization",
        format!("Bearer {}", fixture.alice_user_token),
        Some(
            r#"{"name":"finite","allowedServices":["fake"],"allowedExecutionContexts":["external"],"serviceRestrictions":{"fake":{"actions":["echo"],"resources":{"resourceIds":["project-test"],"resourceGroupIds":[]}}}}"#,
        ),
    )
    .await;
    assert_eq!(self_finite.status(), StatusCode::OK);
    let self_finite = response_json(self_finite).await;
    assert_eq!(
        self_finite["result"]["record"]["scopes"]["serviceRestrictions"],
        json!({
            "fake": {
                "actions": ["echo"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]}
            }
        })
    );
    let self_finite_token_id = self_finite["result"]["record"]["tokenId"]
        .as_str()
        .unwrap()
        .to_string();
    let self_finite_secret = self_finite["result"]["token"].as_str().unwrap().to_string();

    let self_group_subset = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/tokens",
        "self-restriction-group-subset",
        "Authorization",
        format!("Bearer {}", fixture.alice_user_token),
        Some(
            r#"{"name":"group subset","allowedServices":["fake"],"allowedExecutionContexts":["internal"],"serviceRestrictions":{"fake":{"actions":["echo"],"resources":{"resourceIds":["project-ops"],"resourceGroupIds":[]}}}}"#,
        ),
    )
    .await;
    assert_eq!(self_group_subset.status(), StatusCode::OK);

    let ineffective = authed_json_request(
        fixture.app.clone(), Method::POST, "/v1/tokens", "self-restriction-currently-empty",
        "Authorization", format!("Bearer {}", fixture.alice_user_token),
        Some(r#"{"name":"currently empty","allowedServices":["fake"],"allowedExecutionContexts":["external"],"serviceRestrictions":{"fake":{"actions":["echo"],"resources":{"resourceIds":["project-ops"],"resourceGroupIds":[]}}}}"#),
    ).await;
    assert_eq!(ineffective.status(), StatusCode::OK);
    let ineffective = response_json(ineffective).await;
    let ineffective_token = ineffective["result"]["token"].as_str().unwrap();
    let denied = authed_context_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/invoke/fake/echo",
        "self-restriction-empty-denied",
        ineffective_token,
        "external",
        Some(r#"{"inputs":{"project":"OPS","message":"denied"}}"#),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    for (request_id, body, expected_message) in [
        (
            "self-restriction-unavailable-action",
            r#"{"name":"unavailable action","allowedServices":["fake"],"allowedExecutionContexts":["external"],"serviceRestrictions":{"fake":{"actions":["missing"]}}}"#,
            "action is not available to the principal",
        ),
        (
            "self-restriction-unknown-resource",
            r#"{"name":"unknown resource","allowedServices":["fake"],"allowedExecutionContexts":["external"],"serviceRestrictions":{"fake":{"actions":["echo"],"resources":{"resourceIds":["issue-test-1"],"resourceGroupIds":[]}}}}"#,
            "resource is not available to the principal",
        ),
        (
            "self-restriction-service-not-selected",
            r#"{"name":"service not selected","allowedServices":["fake"],"allowedExecutionContexts":["external"],"serviceRestrictions":{"jira":{"actions":["issue.view"]}}}"#,
            "is not present in allowedServices",
        ),
    ] {
        let response = authed_json_request(
            fixture.app.clone(),
            Method::POST,
            "/v1/tokens",
            request_id,
            "Authorization",
            format!("Bearer {}", fixture.alice_user_token),
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{request_id}");
        let response = response_json(response).await;
        assert_eq!(response["reasonCode"], "input_invalid");
        assert!(
            response["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(expected_message)),
            "unexpected {request_id} response: {response:#}"
        );
    }

    for (request_id, body) in [
        (
            "admin-specialized-zero",
            r#"{"name":"zero","allowedExecutionContexts":[]}"#,
        ),
        (
            "admin-specialized-ineffective",
            r#"{"name":"ineffective","allowedExecutionContexts":["workstation"]}"#,
        ),
        (
            "admin-specialized-device-name-removed",
            r#"{"name":"legacy","allowedExecutionContexts":["external"],"deviceName":"workstation"}"#,
        ),
    ] {
        let response = authed_json_request(
            fixture.app.clone(),
            Method::POST,
            "/v1/admin/principals/alice/agent-tokens",
            request_id,
            "Authorization",
            format!("Bearer {}", fixture.admin_token),
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{request_id}");
    }

    let specialized = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/agent-tokens",
        "admin-specialized-multiple",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        Some(
            r#"{"name":"specialized","allowedServices":["fake"],"allowedExecutionContexts":["external","internal"],"serviceRestrictions":{"fake":{"actions":["echo"],"resources":{"resourceIds":["project-test"],"resourceGroupIds":[]}}},"never":true}"#,
        ),
    )
    .await;
    let specialized_status = specialized.status();
    let specialized = response_json(specialized).await;
    assert_eq!(specialized_status, StatusCode::OK, "{specialized:#}");
    assert_eq!(
        specialized["result"]["record"]["scopes"],
        json!({
            "allowedServices": ["fake"],
            "allowedExecutionContexts": ["external", "internal"],
            "serviceRestrictions": {
                "fake": {
                    "actions": ["echo"],
                    "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]}
                }
            }
        })
    );
    let specialized_token = specialized["result"]["token"].as_str().unwrap().to_string();
    let specialized_token_id = specialized["result"]["record"]["tokenId"]
        .as_str()
        .unwrap()
        .to_string();

    let generic_missing = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/tokens",
        "admin-generic-context-missing",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        Some(r#"{"name":"missing","tokenClass":"agent_invoke","never":true,"scopes":{}}"#),
    )
    .await;
    assert_eq!(generic_missing.status(), StatusCode::BAD_REQUEST);
    let generic_device_name = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/tokens",
        "admin-generic-device-name-removed",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        Some(
            r#"{"name":"legacy","tokenClass":"agent_invoke","never":true,"deviceName":"workstation","scopes":{"allowedExecutionContexts":["external"]}}"#,
        ),
    )
    .await;
    assert_eq!(
        generic_device_name.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let generic = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/tokens",
        "admin-generic-context-multiple",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        Some(
            r#"{"name":"generic","tokenClass":"agent_invoke","never":true,"scopes":{"allowedServices":["fake"],"allowedExecutionContexts":["external","internal"],"serviceRestrictions":{"fake":{"actions":["echo"],"resources":{"resourceIds":["project-test"],"resourceGroupIds":[]}}}}}"#,
        ),
    )
    .await;
    assert_eq!(generic.status(), StatusCode::OK);
    let generic = response_json(generic).await;
    assert_eq!(
        generic["result"]["record"]["scopes"],
        specialized["result"]["record"]["scopes"]
    );
    let generic_token = generic["result"]["token"].as_str().unwrap().to_string();
    let generic_token_id = generic["result"]["record"]["tokenId"]
        .as_str()
        .unwrap()
        .to_string();
    let service_account_options = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/principals/svc-app/agent-token-options",
        "token-options-service-account",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        None,
    )
    .await;
    assert_eq!(service_account_options.status(), StatusCode::OK);
    let service_account_options = response_json(service_account_options).await;
    assert_eq!(
        service_account_options["result"]["executionContexts"],
        json!(["external"])
    );
    assert_eq!(
        service_account_options["result"]["services"][0]["actions"][0]["action"],
        "echo"
    );
    let service_account_issue = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals/svc-app/agent-tokens",
        "admin-service-account-restriction",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        Some(
            r#"{"name":"service account","allowedServices":["fake"],"allowedExecutionContexts":["external"],"serviceRestrictions":{"fake":{"actions":["echo"],"resources":{"resourceIds":["project-svc"],"resourceGroupIds":[]}}},"never":true}"#,
        ),
    )
    .await;
    assert_eq!(service_account_issue.status(), StatusCode::OK);
    let service_account_issue = response_json(service_account_issue).await;
    assert_eq!(
        service_account_issue["result"]["record"]["principalId"],
        "svc-app"
    );
    assert_eq!(
        service_account_issue["result"]["record"]["scopes"]["serviceRestrictions"]["fake"]["resources"]
            ["resourceIds"],
        json!(["project-svc"])
    );
    let service_account_management_token = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals/svc-app/tokens",
        "admin-service-account-management-token-denied",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        Some(r#"{"name":"service setup","tokenClass":"user_manage","ttl":"8h","scopes":{}}"#),
    )
    .await;
    assert_eq!(
        service_account_management_token.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        response_json(service_account_management_token).await["reasonCode"],
        "input_invalid"
    );
    let management = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/tokens",
        "admin-generic-management-scopes",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        Some(
            r#"{"name":"management","tokenClass":"user_manage","ttl":"8h","scopes":{"existingRestriction":"retained"}}"#,
        ),
    )
    .await;
    assert_eq!(management.status(), StatusCode::OK);
    assert_eq!(
        response_json(management).await["result"]["record"]["scopes"],
        json!({"existingRestriction": "retained"})
    );
    let management_with_agent_restriction = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/tokens",
        "admin-generic-management-agent-restriction",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        Some(
            r#"{"name":"management restricted","tokenClass":"user_manage","ttl":"8h","scopes":{"serviceRestrictions":{"fake":{"actions":["echo"]}}}}"#,
        ),
    )
    .await;
    assert_eq!(
        management_with_agent_restriction.status(),
        StatusCode::BAD_REQUEST
    );
    let management_with_agent_restriction = response_json(management_with_agent_restriction).await;
    assert_eq!(
        management_with_agent_restriction["reasonCode"],
        "input_invalid"
    );
    assert!(
        management_with_agent_restriction["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("only valid for agent_invoke"))
    );
    let admin_with_agent_restriction = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals/admin/tokens",
        "admin-generic-admin-agent-restriction",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        Some(
            r#"{"name":"admin restricted","tokenClass":"admin","ttl":"2h","scopes":{"serviceRestrictions":{"fake":{"actions":["echo"]}}}}"#,
        ),
    )
    .await;
    assert_eq!(
        admin_with_agent_restriction.status(),
        StatusCode::BAD_REQUEST
    );
    let admin_with_agent_restriction = response_json(admin_with_agent_restriction).await;
    assert_eq!(admin_with_agent_restriction["reasonCode"], "input_invalid");
    assert!(
        admin_with_agent_restriction["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("only valid for agent_invoke"))
    );

    let list = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/tokens",
        "token-context-list-raw-scopes",
        "Authorization",
        format!("Bearer {}", fixture.alice_user_token),
        None,
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);
    let list = response_json(list).await;
    let records = list["result"].as_array().unwrap();
    assert_eq!(
        records
            .iter()
            .find(|record| record["tokenId"].as_str() == Some(self_multiple_token_id.as_str()))
            .unwrap()["scopes"]["allowedExecutionContexts"],
        json!(["internal", "external"])
    );
    assert_eq!(
        records
            .iter()
            .find(|record| record["name"] == "currently empty")
            .unwrap()["scopes"]["serviceRestrictions"]["fake"]["resources"],
        json!({"resourceIds":["project-ops"],"resourceGroupIds":[]})
    );
    for rejected_name in [
        "unavailable action",
        "unknown resource",
        "service not selected",
    ] {
        assert!(
            records.iter().all(|record| record["name"] != rejected_name),
            "rejected issuance unexpectedly stored {rejected_name}"
        );
    }
    assert_eq!(
        records
            .iter()
            .find(|record| record["name"] == "legacy agent")
            .unwrap()["scopes"],
        json!({})
    );
    assert_eq!(
        records
            .iter()
            .find(|record| record["name"] == "stale agent")
            .unwrap()["scopes"],
        json!({"allowedExecutionContexts": ["retired"]})
    );
    assert_eq!(
        records
            .iter()
            .find(|record| record["name"] == "corrupt agent")
            .unwrap()["scopes"],
        json!({
            "allowedServices": ["fake"],
            "allowedExecutionContexts": ["internal"],
            "serviceRestrictions": {
                "fake": {"actions": "echo"}
            }
        })
    );
    let legacy_get = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/tokens/11111111-1111-4111-8111-111111111111",
        "token-context-get-legacy",
        "Authorization",
        format!("Bearer {}", fixture.alice_user_token),
        None,
    )
    .await;
    assert_eq!(legacy_get.status(), StatusCode::OK);
    assert_eq!(
        response_json(legacy_get).await["result"]["scopes"],
        json!({})
    );

    let allowed = authed_context_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/invoke/fake/echo",
        "token-context-invoke-allowed",
        &specialized_token,
        "external",
        Some(r#"{"inputs":{"project":"TEST","message":"allowed"}}"#),
    )
    .await;
    assert_eq!(allowed.status(), StatusCode::OK);
    let legacy_denied = authed_context_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/invoke/fake/echo",
        "token-context-legacy-coarse-denied",
        "aab_ai_legacy_fixture",
        "external",
        Some(r#"{"inputs":{"project":"TEST","message":"legacy"}}"#),
    )
    .await;
    assert_eq!(legacy_denied.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(legacy_denied).await["reasonCode"],
        "identity_invalid"
    );
    for (request_id, context, project) in [
        ("token-context-self-multiple-external", "external", "TEST"),
        ("token-context-self-multiple-internal", "internal", "OPS"),
    ] {
        let response = authed_context_json_request(
            fixture.app.clone(),
            Method::POST,
            "/v1/invoke/fake/echo",
            request_id,
            &self_multiple_secret,
            context,
            Some(&format!(
                r#"{{"inputs":{{"project":"{project}","message":"allowed"}}}}"#
            )),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{request_id}");
    }
    let self_multiple_unselected = authed_context_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/invoke/fake/echo",
        "token-context-self-multiple-unselected",
        &self_multiple_secret,
        "partner",
        Some(r#"{"inputs":{"project":"PARTNER","message":"blocked"}}"#),
    )
    .await;
    assert_eq!(self_multiple_unselected.status(), StatusCode::FORBIDDEN);
    for (path, request_id) in [
        ("/v1/services", "token-context-discovery-denied"),
        ("/v1/spec/catalog", "token-context-catalog-denied"),
        ("/v1/spec/openapi.json", "token-context-openapi-denied"),
        (
            "/v1/spec/send-schema.json",
            "token-context-send-schema-denied",
        ),
    ] {
        let denied = authed_context_json_request(
            fixture.app.clone(),
            Method::GET,
            path,
            request_id,
            &specialized_token,
            "workstation",
            None,
        )
        .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "{path}");
        let body = response_json(denied).await;
        assert_eq!(body["service"], "broker");
        assert_eq!(body["action"], "context.authorize");
        assert_eq!(body["reasonCode"], "execution_context_denied");
        assert!(body.get("result").is_none());
        let records = read_audit_records(&fixture.audit_path);
        let record = records
            .iter()
            .find(|record| record["agentRequestId"] == request_id)
            .unwrap();
        assert_eq!(record["executionContext"], "workstation", "{path}");
        assert_eq!(record["principal"], "alice");
        assert_eq!(record["reasonCode"], "execution_context_denied");
        assert_eq!(record["brokerRequestId"], body["brokerRequestId"]);
    }

    let corrupt = authed_context_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/invoke/fake/echo",
        "token-context-corrupt-fails-closed",
        &fixture.corrupt_agent_token,
        "internal",
        Some(r#"{"inputs":{"project":"TEST","message":"blocked"}}"#),
    )
    .await;
    assert_eq!(corrupt.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(corrupt).await["reasonCode"],
        "identity_invalid"
    );

    let audit = read_audit_text(&fixture.audit_path);
    assert!(audit.contains("\"serviceRestrictions\""));
    let self_success_audit = audit
        .lines()
        .find(|line| line.contains(&self_finite_token_id) && line.contains("\"phase\":\"success\""))
        .expect("self-service token success audit");
    assert!(self_success_audit.contains("\"boundary\""));
    assert!(self_success_audit.contains("\"serviceRestrictions\""));
    assert!(self_success_audit.contains("\"name\":\"finite\""));
    assert!(self_success_audit.contains("\"expiresAt\""));
    let self_multiple_success_audit = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|record| {
            record["providerAudit"]["management"]["phase"] == "success"
                && record["providerAudit"]["management"]["target"]["tokenId"].as_str()
                    == Some(self_multiple_token_id.as_str())
        })
        .expect("multi-context self-service token success audit");
    assert_eq!(
        self_multiple_success_audit["providerAudit"]["management"]["target"]["boundary"]["allowedExecutionContexts"],
        json!(["internal", "external"])
    );
    let specialized_success_audit = audit
        .lines()
        .find(|line| line.contains(&specialized_token_id) && line.contains("\"phase\":\"success\""))
        .expect("specialized admin token success audit");
    assert!(specialized_success_audit.contains("\"tokenClass\":\"agent_invoke\""));
    assert!(specialized_success_audit.contains("\"name\":\"specialized\""));
    assert!(specialized_success_audit.contains("\"expiresAt\""));
    assert!(specialized_success_audit.contains("\"boundary\""));
    let generic_success_audit = audit
        .lines()
        .find(|line| line.contains(&generic_token_id) && line.contains("\"phase\":\"success\""))
        .expect("generic admin token success audit");
    assert!(generic_success_audit.contains("\"tokenClass\":\"agent_invoke\""));
    assert!(generic_success_audit.contains("\"name\":\"generic\""));
    assert!(generic_success_audit.contains("\"expiresAt\""));
    assert!(generic_success_audit.contains("\"boundary\""));
    assert!(audit.contains("\"principal\":\"admin\""));
    assert!(audit.contains("\"principal\":\"svc-app\""));
    assert!(!audit.contains("\"deviceName\""));
    assert!(!audit.contains(&specialized_token));
    assert!(!audit.contains(&generic_token));
    assert!(!audit.contains(&self_finite_secret));
    assert!(!audit.contains(&self_multiple_secret));
}

#[tokio::test]
async fn managed_policy_changes_remain_authoritative_over_immutable_token_boundaries() {
    let fixture = managed_policy_admin_fixture().await;
    let authorization = format!("Bearer {}", fixture.admin_token);
    let grant_id = "fake-admin-eng";

    let create_eng = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants",
        "token-boundary-create-eng-grant",
        "Authorization",
        authorization.clone(),
        Some(&format!(
            r#"{{
                "grantId":"{grant_id}",
                "subjects":["user:admin"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{{"resourceIds":["project-eng"],"resourceGroupIds":[]}},
                "credentialMode":"service"
            }}"#
        )),
    )
    .await;
    assert_eq!(create_eng.status(), StatusCode::OK);

    let finite = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals/admin/agent-tokens",
        "token-boundary-issue-finite",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{"name":"finite ENG","allowedServices":["fake"],"allowedExecutionContexts":["default"],"serviceRestrictions":{"fake":{"actions":["echo"],"resources":{"resourceIds":["project-eng"],"resourceGroupIds":[]}}},"never":true}"#,
        ),
    )
    .await;
    assert_eq!(finite.status(), StatusCode::OK);
    let finite_token = response_json(finite).await["result"]["token"]
        .as_str()
        .unwrap()
        .to_string();

    let resource_omitted = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals/admin/agent-tokens",
        "token-boundary-issue-resource-omitted",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{"name":"policy-following resources","allowedServices":["fake"],"allowedExecutionContexts":["default"],"serviceRestrictions":{"fake":{"actions":["echo"]}},"never":true}"#,
        ),
    )
    .await;
    assert_eq!(resource_omitted.status(), StatusCode::OK);
    let resource_omitted_token = response_json(resource_omitted).await["result"]["token"]
        .as_str()
        .unwrap()
        .to_string();

    for (request_id, token) in [
        ("token-boundary-finite-eng-initial", finite_token.as_str()),
        (
            "token-boundary-omitted-eng-initial",
            resource_omitted_token.as_str(),
        ),
    ] {
        assert_eq!(
            invoke_fake_project_with_token(fixture.app.clone(), request_id, token, "ENG")
                .await
                .status(),
            StatusCode::OK,
            "{request_id}"
        );
    }

    let disable_eng = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{grant_id}/disable"),
        "token-boundary-disable-eng-grant",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":1}"#),
    )
    .await;
    assert_eq!(disable_eng.status(), StatusCode::OK);
    for (request_id, token) in [
        ("token-boundary-finite-disabled", finite_token.as_str()),
        (
            "token-boundary-omitted-disabled",
            resource_omitted_token.as_str(),
        ),
    ] {
        assert_eq!(
            invoke_fake_project_with_token(fixture.app.clone(), request_id, token, "ENG")
                .await
                .status(),
            StatusCode::FORBIDDEN,
            "{request_id}"
        );
    }

    let enable_eng = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{grant_id}/enable"),
        "token-boundary-enable-eng-grant",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":2}"#),
    )
    .await;
    assert_eq!(enable_eng.status(), StatusCode::OK);
    assert_eq!(
        invoke_fake_project_with_token(
            fixture.app.clone(),
            "token-boundary-finite-eng-restored",
            &finite_token,
            "ENG"
        )
        .await
        .status(),
        StatusCode::OK
    );

    let add_ops = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants",
        "token-boundary-add-ops-grant",
        "Authorization",
        authorization,
        Some(
            r#"{
                "grantId":"fake-admin-ops",
                "subjects":["user:admin"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-ops"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(add_ops.status(), StatusCode::OK);
    assert_eq!(
        invoke_fake_project_with_token(
            fixture.app.clone(),
            "token-boundary-finite-ops-denied",
            &finite_token,
            "OPS"
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        invoke_fake_project_with_token(
            fixture.app,
            "token-boundary-omitted-ops-follows-policy",
            &resource_omitted_token,
            "OPS"
        )
        .await
        .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn managed_store_admin_and_user_token_smoke() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mixed_service_token = temp_path("managed-mixed-service-token");
    let key_path = temp_path("managed-credential-key");
    let hash_key_path = temp_path("managed-hash-key");
    let csrf_key_path = temp_path("managed-csrf-key");
    let password_pepper_path = temp_path("managed-password-pepper");
    let store_path = temp_path("managed-store.sqlite");
    let audit_path = temp_path("managed-store.audit.jsonl");
    std::fs::write(&mixed_service_token, "mixed-token").unwrap();
    std::fs::write(&key_path, URL_SAFE_NO_PAD.encode([3_u8; 32])).unwrap();
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([4_u8; 32])).unwrap();
    std::fs::write(&csrf_key_path, URL_SAFE_NO_PAD.encode([5_u8; 32])).unwrap();
    std::fs::write(&password_pepper_path, URL_SAFE_NO_PAD.encode([6_u8; 32])).unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    config.managed_store = Some(agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.credential_encryption = Some(agent_access_core::CredentialEncryptionConfig {
        active_key: "k1".to_string(),
        keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
            id: "k1".to_string(),
            provider: "file".to_string(),
            env: None,
            path: Some(key_path.display().to_string()),
        }],
    });
    config.management = agent_access_core::ManagementConfig {
        enabled: true,
        initial_admin: agent_access_core::InitialAdminConfig {
            mode: "create_if_empty".to_string(),
            principal_id: Some("admin".to_string()),
            initial_password: Some("admin-password".to_string()),
        },
        ..agent_access_core::ManagementConfig::default()
    };
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        default_agent_invoke_ttl: None,
        default_user_manage_ttl: Some("8h".to_string()),
        default_admin_ttl: None,
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    config.browser_auth = agent_access_core::BrowserAuthConfig {
        enabled: true,
        public_origin: Some("http://localhost".to_string()),
        session_cookie_name: "aab_session".to_string(),
        csrf_header: "X-Agent-Access-CSRF".to_string(),
        csrf_key_ref: Some(format!("file:{}", csrf_key_path.display())),
        session_ttl: "8h".to_string(),
        allowed_return_paths: vec!["/ui".to_string()],
        local_password: agent_access_core::LocalPasswordConfig {
            enabled: true,
            pepper_ref: Some(format!("file:{}", password_pepper_path.display())),
            min_password_length: 8,
            max_failed_attempts: 3,
            lockout_ttl: "15m".to_string(),
        },
        oidc: Default::default(),
    };
    config.providers.insert(
        serde_json::from_value::<agent_access_gitlab::GitlabProviderConfig>(json!({
            "api_base_url": "https://gitlab.example.com/api/v4",
            "web_base_url": "https://gitlab.example.com",
            "allowed_upstream_hosts": ["https://gitlab.example.com/api/v4/**"]
        }))
        .unwrap(),
    );
    config.providers.insert(
        serde_json::from_value::<agent_access_jira::JiraProviderConfig>(json!({
            "tenant_host": "example.atlassian.net",
            "allowed_upstream_hosts": ["https://example.atlassian.net/rest/api/3/**"]
        }))
        .unwrap(),
    );
    config.credentials.lookup.insert(
        "gitlab".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some(format!("file:{}", mixed_service_token.display())),
            provider: None,
            path: None,
            read_only: Some(true),
            credential_name: None,
            profile: None,
        },
    );
    let mut mixed_gateway = test_git_gateway_config();
    mixed_gateway.credential_modes = vec!["service".to_string(), "per_user".to_string()];
    config
        .gateways
        .insert("gitlab_git".to_string(), mixed_gateway);
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some(format!("file:{}", mixed_service_token.display())),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config.credentials.per_user.insert(
        "gitlab".to_string(),
        CredentialConfig {
            kind: "managed_store".to_string(),
            username_ref: None,
            token_ref: None,
            provider: None,
            path: None,
            read_only: None,
            credential_name: Some("default".to_string()),
            profile: Some("gitlab-access-token".to_string()),
        },
    );
    config.credentials.per_user.insert(
        "gitlab_git".to_string(),
        CredentialConfig {
            kind: "managed_store".to_string(),
            username_ref: None,
            token_ref: None,
            provider: None,
            path: None,
            read_only: None,
            credential_name: Some("default".to_string()),
            profile: Some("git-bearer-token".to_string()),
        },
    );
    config.credentials.per_user.insert(
        "jira".to_string(),
        CredentialConfig {
            kind: "managed_store".to_string(),
            username_ref: None,
            token_ref: None,
            provider: None,
            path: None,
            read_only: None,
            credential_name: Some("default".to_string()),
            profile: Some("jira-cloud-api-token".to_string()),
        },
    );
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:users".to_string()],
        execution_contexts: None,
        service: "fake".to_string(),
        actions: vec!["echo".to_string()],
        resources: selected_resources(&[("project", &["TEST"])]),
        credential_mode: "service".to_string(),
        priority: None,
    });
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:users".to_string()],
        execution_contexts: None,
        service: "gitlab".to_string(),
        actions: vec!["issue.view".to_string()],
        resources: selected_resources(&[("repository", &["acme/portal"])]),
        credential_mode: "per_user".to_string(),
        priority: None,
    });
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:users".to_string()],
        execution_contexts: None,
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string()],
        resources: selected_resources(&[("repository", &["acme/portal"])]),
        credential_mode: "service".to_string(),
        priority: None,
    });
    let managed_store = agent_access_core::ManagedStore::open(
        config.managed_store.as_ref().unwrap(),
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    managed_store
        .create_group(agent_access_core::GroupWriteRequest {
            group_id: "users".to_string(),
            display_name: Some("Users".to_string()),
            description: Some("Policy users".to_string()),
            created_by: "system".to_string(),
        })
        .unwrap();
    let browser_token_hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let gitlab_descriptor = agent_access_gitlab::gitlab_descriptor(
        config
            .providers
            .get::<agent_access_gitlab::GitlabProviderConfig>()
            .unwrap(),
    );
    let broker = TestBroker::start_with_providers(
        &config,
        vec![
            agent_access_fake::fake_service_provider(),
            agent_access_provider::ServiceProvider::from(Arc::new(
                TestManagedGitlabCredentialProvider {
                    descriptor: gitlab_descriptor,
                },
            )),
        ],
    )
    .await;
    let app = broker.app();
    // Startup reconciles OIDC provider state with the configuration, which
    // enables no provider, so the store's provider state is seeded afterwards.
    let oidc_provider = managed_store
        .reconcile_oidc_provider_state(agent_access_core::OidcProviderStateReconcileRequest {
            tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
            client_id: "11111111-2222-3333-4444-555555555555".to_string(),
            enabled: true,
            config_fingerprint: "sha256:test-provider".to_string(),
            external_membership_ttl_seconds: 8 * 60 * 60,
            invalidate_existing_evidence: false,
            actor: "system".to_string(),
        })
        .unwrap();

    let admin_login = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(
                    "127.0.0.1:40090".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-admin-browser-login")
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"principalId":"admin","password":"admin-password","returnTo":"/ui"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_login.status(), StatusCode::OK);
    let admin_session_cookie = admin_login
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let admin_login_body = response_json(admin_login).await;
    assert_eq!(admin_login_body["result"]["principal"], "admin");
    assert_eq!(admin_login_body["result"]["passwordChangeRequired"], true);
    assert_eq!(
        admin_login_body["result"]["tokenIssuancePolicy"]["selfAgentInvoke"],
        json!({"defaultTtl":"30d","maxTtl":"30d","options":["8h","7d","30d"]})
    );
    assert_eq!(
        admin_login_body["result"]["tokenIssuancePolicy"]["administered"],
        json!({
            "agentInvoke":{"defaultTtl":null,"maxTtl":null,"options":["8h","7d","30d","never"]},
            "userManage":{"defaultTtl":"8h","maxTtl":null,"options":["30m","2h","8h","1d"]},
            "admin":{"defaultTtl":null,"maxTtl":null,"options":["30m","2h","8h","1d"]}
        })
    );
    let admin_initial_csrf_token = admin_login_body["result"]["csrfToken"]
        .as_str()
        .unwrap()
        .to_string();

    let admin_password_change = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/password/change")
                .extension(ConnectInfo(
                    "127.0.0.1:40091".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-admin-browser-password-change")
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header("Cookie", &admin_session_cookie)
                .header("X-Agent-Access-CSRF", &admin_initial_csrf_token)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"currentPassword":"admin-password","newPassword":"admin-password-updated"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_password_change.status(), StatusCode::OK);
    let admin_session_cookie = admin_password_change
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let admin_password_change_body = response_json(admin_password_change).await;
    assert_eq!(
        admin_password_change_body["result"]["passwordChangeRequired"],
        false
    );
    let admin_csrf_token = admin_password_change_body["result"]["csrfToken"]
        .as_str()
        .unwrap()
        .to_string();

    let cookie_group_create_without_csrf = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/groups",
        "managed-cookie-group-create-no-csrf",
        "Cookie",
        admin_session_cookie.clone(),
        Some(r#"{"groupId":"cookie-write-denied"}"#),
    )
    .await;
    assert_eq!(
        cookie_group_create_without_csrf.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response_json(cookie_group_create_without_csrf).await["reasonCode"],
        "csrf_invalid"
    );

    let cookie_token_issue_without_csrf = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals/admin/tokens",
        "managed-cookie-admin-token-issue-no-csrf",
        "Cookie",
        admin_session_cookie.clone(),
        Some(r#"{"name":"admin no csrf","tokenClass":"admin","ttl":"2h"}"#),
    )
    .await;
    assert_eq!(
        cookie_token_issue_without_csrf.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response_json(cookie_token_issue_without_csrf).await["reasonCode"],
        "csrf_invalid"
    );

    let admin_bearer_issue = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/admin/principals/admin/tokens")
                .extension(ConnectInfo(
                    "127.0.0.1:40092".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-admin-issue-admin-token")
                .header("Cookie", &admin_session_cookie)
                .header("X-Agent-Access-CSRF", &admin_csrf_token)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"name":"admin bearer","tokenClass":"admin","ttl":"2h"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_bearer_issue.status(), StatusCode::OK);
    let admin_bearer_issue_body = response_json(admin_bearer_issue).await;
    let admin_bearer_token_id = admin_bearer_issue_body["result"]["record"]["tokenId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        admin_bearer_issue_body["result"]["record"]["browserSession"],
        false
    );
    let admin_authorization = format!(
        "Bearer {}",
        admin_bearer_issue_body["result"]["token"].as_str().unwrap()
    );

    let admin_broker_tokens = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/tokens?principal=admin",
        "managed-admin-token-browser-session-marker",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(admin_broker_tokens.status(), StatusCode::OK);
    let admin_broker_tokens_body = response_json(admin_broker_tokens).await;
    let admin_tokens = admin_broker_tokens_body["result"].as_array().unwrap();
    let browser_session_token_id = admin_tokens
        .iter()
        .find(|token| token["tokenClass"] == "user_manage" && token["browserSession"] == true)
        .and_then(|token| token["tokenId"].as_str())
        .unwrap()
        .to_string();
    assert!(
        admin_tokens.iter().any(|token| {
            token["tokenClass"] == "user_manage" && token["browserSession"] == true
        })
    );
    assert!(admin_tokens.iter().any(|token| {
        token["tokenId"] == admin_bearer_token_id && token["browserSession"] == false
    }));
    let admin_browser_session_token = authed_json_request(
        app.clone(),
        Method::GET,
        format!("/v1/admin/tokens/{browser_session_token_id}"),
        "managed-admin-token-inspect-browser-session-marker",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(admin_browser_session_token.status(), StatusCode::OK);
    assert_eq!(
        response_json(admin_browser_session_token).await["result"]["browserSession"],
        true
    );

    let managed_config_status = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/config/status",
        "managed-admin-config-status",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(managed_config_status.status(), StatusCode::OK);
    let managed_config_status_body = response_json(managed_config_status).await;
    assert_eq!(
        managed_config_status_body["result"]["identityAuthority"],
        "managed"
    );
    assert_eq!(
        managed_config_status_body["result"]["policyAuthority"],
        "toml"
    );

    let initial_groups = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/groups",
        "managed-groups-list-initial",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(initial_groups.status(), StatusCode::OK);
    let initial_groups_body = response_json(initial_groups).await;
    assert_eq!(initial_groups_body["result"][0]["groupId"], "users");
    assert_eq!(initial_groups_body["result"][0]["memberCount"], 0);

    let create_reviewers_group = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/groups",
        "managed-create-reviewers-group",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"groupId":"reviewers","displayName":"Reviewers","description":"Review users"}"#),
    )
    .await;
    assert_eq!(create_reviewers_group.status(), StatusCode::OK);
    let reviewers_body = response_json(create_reviewers_group).await;
    assert_eq!(reviewers_body["result"]["groupId"], "reviewers");
    assert_eq!(reviewers_body["result"]["status"], "active");

    let cookie_binding_list = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/groups/reviewers/external-group-bindings",
        "managed-cookie-binding-list-no-csrf",
        "Cookie",
        admin_session_cookie.clone(),
        None,
    )
    .await;
    assert_eq!(cookie_binding_list.status(), StatusCode::OK);
    assert!(
        response_json(cookie_binding_list).await["result"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let cookie_binding_create_without_csrf = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/groups/reviewers/external-group-bindings",
        "managed-cookie-binding-create-no-csrf",
        "Cookie",
        admin_session_cookie.clone(),
        Some(r#"{"externalGroupId":"99999999-8888-7777-6666-555555555555"}"#),
    )
    .await;
    assert_eq!(
        cookie_binding_create_without_csrf.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response_json(cookie_binding_create_without_csrf).await["reasonCode"],
        "csrf_invalid"
    );

    let create_binding = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/admin/groups/reviewers/external-group-bindings")
                .extension(ConnectInfo(
                    "127.0.0.1:40098".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-cookie-binding-create")
                .header("Cookie", &admin_session_cookie)
                .header("X-Agent-Access-CSRF", &admin_csrf_token)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"externalGroupId":"99999999-8888-7777-6666-555555555555"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_binding.status(), StatusCode::OK);
    let create_binding_body = response_json(create_binding).await;
    assert_eq!(create_binding_body["result"]["groupId"], "reviewers");
    assert_eq!(create_binding_body["result"]["status"], "active");
    let reviewer_binding_id = create_binding_body["result"]["bindingId"]
        .as_str()
        .unwrap()
        .to_string();

    let delete_active_binding = authed_json_request(
        app.clone(),
        Method::DELETE,
        format!("/v1/admin/groups/reviewers/external-group-bindings/{reviewer_binding_id}"),
        "managed-binding-delete-active",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(delete_active_binding.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(delete_active_binding).await["reasonCode"],
        "external_group_binding_conflict"
    );

    for method in [Method::PATCH, Method::DELETE] {
        let request_id = if method == Method::PATCH {
            "managed-binding-mismatch-patch"
        } else {
            "managed-binding-mismatch-delete"
        };
        let mismatch = authed_json_request(
            app.clone(),
            method.clone(),
            format!("/v1/admin/groups/users/external-group-bindings/{reviewer_binding_id}"),
            request_id,
            "Authorization",
            admin_authorization.clone(),
            (method == Method::PATCH).then_some(r#"{"status":"disabled"}"#),
        )
        .await;
        assert_eq!(mismatch.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response_json(mismatch).await["reasonCode"],
            "external_group_binding_not_found"
        );
    }

    let cookie_inspect_reviewers_group = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/groups/reviewers",
        "managed-cookie-inspect-reviewers-group-no-csrf",
        "Cookie",
        admin_session_cookie.clone(),
        None,
    )
    .await;
    assert_eq!(cookie_inspect_reviewers_group.status(), StatusCode::OK);
    let cookie_inspect_reviewers_body = response_json(cookie_inspect_reviewers_group).await;
    assert_eq!(
        cookie_inspect_reviewers_body["result"]["groupId"],
        "reviewers"
    );

    let cookie_reviewer_members = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/groups/reviewers/members",
        "managed-cookie-reviewer-members-list-no-csrf",
        "Cookie",
        admin_session_cookie.clone(),
        None,
    )
    .await;
    assert_eq!(cookie_reviewer_members.status(), StatusCode::OK);
    assert!(
        response_json(cookie_reviewer_members).await["result"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let inspect_reviewers_group = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/groups/reviewers",
        "managed-inspect-reviewers-group",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(inspect_reviewers_group.status(), StatusCode::OK);
    let inspect_reviewers_body = response_json(inspect_reviewers_group).await;
    assert_eq!(inspect_reviewers_body["result"]["groupId"], "reviewers");
    assert_eq!(
        inspect_reviewers_body["result"]["policyReferenceSections"][0]["references"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    let create_alice = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/admin/principals")
                .extension(ConnectInfo(
                    "127.0.0.1:40100".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-create-alice")
                .header("Authorization", &admin_authorization)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"principalId":"alice","kind":"user"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_alice.status(), StatusCode::OK);

    let cookie_oidc_link_without_csrf = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/admin/principals/alice/login-methods/oidc/microsoft",
        "managed-cookie-oidc-link-no-csrf",
        "Cookie",
        admin_session_cookie.clone(),
        Some(r#"{"userObjectId":"12345678-1234-1234-1234-123456789abc"}"#),
    )
    .await;
    assert_eq!(
        cookie_oidc_link_without_csrf.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response_json(cookie_oidc_link_without_csrf).await["reasonCode"],
        "csrf_invalid"
    );

    let link_oidc = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/v1/admin/principals/alice/login-methods/oidc/microsoft")
                .extension(ConnectInfo(
                    "127.0.0.1:40099".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-cookie-oidc-link")
                .header("Cookie", &admin_session_cookie)
                .header("X-Agent-Access-CSRF", &admin_csrf_token)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"userObjectId":"12345678-1234-1234-1234-123456789abc"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(link_oidc.status(), StatusCode::OK);
    let link_oidc_body = response_json(link_oidc).await;
    assert_eq!(link_oidc_body["result"]["method"], "oidc");
    assert_eq!(
        link_oidc_body["result"]["oidc"],
        json!({
            "provider": "microsoft",
            "tenantId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "userObjectId": "12345678-1234-1234-1234-123456789abc",
        })
    );
    assert!(link_oidc_body["result"].get("externalSubject").is_none());

    let login_methods = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/principals/alice/login-methods",
        "managed-oidc-login-method-list",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(login_methods.status(), StatusCode::OK);
    let login_methods_body = response_json(login_methods).await;
    assert_eq!(
        login_methods_body["result"][0]["oidc"]["provider"],
        "microsoft"
    );
    assert!(
        login_methods_body["result"][0]
            .get("externalSubject")
            .is_none()
    );

    let observed_at = chrono::Utc::now().to_rfc3339();
    let completion = managed_store
        .complete_oidc_login(
            &browser_token_hasher,
            agent_access_core::OidcCompleteLoginRequest {
                flow_sequence: 1,
                provider_generation: oidc_provider.config_generation,
                external_subject: concat!(
                    "entra:v1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:",
                    "12345678-1234-1234-1234-123456789abc"
                )
                .to_string(),
                external_group_ids: std::collections::BTreeSet::from([
                    "99999999-8888-7777-6666-555555555555".to_string(),
                ]),
                jit_provisioning: false,
                jit_principal_id: "unused-jit-principal".to_string(),
                display_name: None,
                email: None,
                evidence_at: observed_at.clone(),
                callback_now: observed_at,
                session_ttl_seconds: 60 * 60,
                created_by: "admin".to_string(),
            },
        )
        .unwrap();
    assert!(matches!(
        completion,
        agent_access_core::OidcCompletionOutcome::Succeeded {
            jit_created: false,
            ..
        }
    ));

    let add_local_reviewer = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/admin/principals/alice/groups/reviewers",
        "managed-add-local-reviewer-with-microsoft",
        "Authorization",
        admin_authorization.clone(),
        Some("{}"),
    )
    .await;
    assert_eq!(add_local_reviewer.status(), StatusCode::OK);

    let inspect_alice_membership = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/principals/alice",
        "managed-inspect-alice-membership",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(inspect_alice_membership.status(), StatusCode::OK);
    let inspect_alice_membership_body = response_json(inspect_alice_membership).await;
    let reviewer_membership = inspect_alice_membership_body["result"]["groupMemberships"]
        .as_array()
        .unwrap()
        .iter()
        .find(|membership| membership["groupId"] == "reviewers")
        .unwrap();
    assert_eq!(reviewer_membership["source"], "local_and_microsoft");
    assert!(reviewer_membership["local"].is_object());
    assert_eq!(reviewer_membership["microsoft"][0]["current"], true);

    let remove_local_reviewer = authed_json_request(
        app.clone(),
        Method::DELETE,
        "/v1/admin/principals/alice/groups/reviewers",
        "managed-remove-local-reviewer-with-microsoft",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(remove_local_reviewer.status(), StatusCode::OK);
    assert_eq!(
        response_json(remove_local_reviewer).await["result"],
        json!({"removed": true, "effectiveMembershipRemains": true})
    );

    let add_reviewer_member = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/admin/groups/reviewers/members/alice",
        "managed-add-reviewer-member",
        "Authorization",
        admin_authorization.clone(),
        Some("{}"),
    )
    .await;
    assert_eq!(add_reviewer_member.status(), StatusCode::OK);

    let reviewer_members = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/groups/reviewers/members",
        "managed-reviewer-members-list",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(reviewer_members.status(), StatusCode::OK);
    let reviewer_members_body = response_json(reviewer_members).await;
    assert_eq!(reviewer_members_body["result"][0]["principalId"], "alice");
    assert_eq!(
        reviewer_members_body["result"][0]["membership"]["source"],
        "local_and_microsoft"
    );
    assert_eq!(
        reviewer_members_body["result"][0]["membership"]["microsoft"][0]["externalGroupId"],
        "99999999-8888-7777-6666-555555555555"
    );

    let remove_reviewer_member = authed_json_request(
        app.clone(),
        Method::DELETE,
        "/v1/admin/groups/reviewers/members/alice",
        "managed-remove-reviewer-member",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(remove_reviewer_member.status(), StatusCode::OK);
    assert_eq!(
        response_json(remove_reviewer_member).await["result"],
        json!({"removed": true, "effectiveMembershipRemains": true})
    );

    let unlink_oidc = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/v1/admin/principals/alice/login-methods/oidc/microsoft")
                .extension(ConnectInfo(
                    "127.0.0.1:40101".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-cookie-oidc-unlink")
                .header("Cookie", &admin_session_cookie)
                .header("X-Agent-Access-CSRF", &admin_csrf_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unlink_oidc.status(), StatusCode::OK);
    assert_eq!(
        response_json(unlink_oidc).await["result"],
        json!({"unlinked": true})
    );

    let disable_binding = authed_json_request(
        app.clone(),
        Method::PATCH,
        format!("/v1/admin/groups/reviewers/external-group-bindings/{reviewer_binding_id}"),
        "managed-binding-disable",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"status":"disabled"}"#),
    )
    .await;
    assert_eq!(disable_binding.status(), StatusCode::OK);
    assert_eq!(
        response_json(disable_binding).await["result"]["status"],
        "disabled"
    );

    let delete_binding = authed_json_request(
        app.clone(),
        Method::DELETE,
        format!("/v1/admin/groups/reviewers/external-group-bindings/{reviewer_binding_id}"),
        "managed-binding-delete",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(delete_binding.status(), StatusCode::OK);
    assert_eq!(
        response_json(delete_binding).await["result"],
        json!({"deleted": true})
    );

    let add_alice_group = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/admin/principals/alice/groups/users",
        "managed-add-alice-group",
        "Authorization",
        admin_authorization.clone(),
        Some("{}"),
    )
    .await;
    assert_eq!(add_alice_group.status(), StatusCode::OK);

    let persistent_agent = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/agent-tokens",
        "managed-admin-issue-persistent-agent",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"name":"persistent agent","never":true,"allowedExecutionContexts":["default"]}"#),
    )
    .await;
    assert_eq!(persistent_agent.status(), StatusCode::OK);
    assert_eq!(
        persistent_agent.headers()[axum::http::header::CACHE_CONTROL],
        "no-store"
    );
    let persistent_agent_body = response_json(persistent_agent).await;
    assert!(persistent_agent_body["result"]["record"]["expiresAt"].is_null());
    let persistent_agent_id = persistent_agent_body["result"]["record"]["tokenId"]
        .as_str()
        .unwrap();
    let revoke_persistent_agent = authed_json_request(
        app.clone(),
        Method::DELETE,
        format!("/v1/admin/principals/alice/agent-tokens/{persistent_agent_id}"),
        "managed-admin-revoke-persistent-agent",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(revoke_persistent_agent.status(), StatusCode::OK);
    assert!(response_json(revoke_persistent_agent).await["result"]["revokedAt"].is_string());

    let set_alice_password = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/login-methods/local-password/enable",
        "managed-set-alice-password",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"password":"alice-password","acknowledgeSeparateSignIn":true}"#),
    )
    .await;
    assert_eq!(set_alice_password.status(), StatusCode::OK);
    assert!(
        response_json(set_alice_password)
            .await
            .get("result")
            .unwrap()
            .get("passwordHashPhc")
            .is_none()
    );

    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(
                    "127.0.0.1:40110".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-login")
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"principalId":"alice","password":"alice-password","returnTo":"/ui"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let session_cookie = login
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(
        login
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("HttpOnly")
    );
    let login_body = response_json(login).await;
    assert_eq!(login_body["result"]["authenticated"], true);
    assert_eq!(login_body["result"]["principal"], "alice");
    assert_eq!(login_body["result"]["tokenClass"], "user_manage");
    assert_eq!(login_body["result"]["loginMethod"], "local_password");
    assert_eq!(login_body["result"]["passwordChangeRequired"], true);
    assert_eq!(
        login_body["result"]["tokenIssuancePolicy"]["selfAgentInvoke"],
        json!({"defaultTtl":"30d","maxTtl":"30d","options":["8h","7d","30d"]})
    );
    assert!(
        login_body["result"]["tokenIssuancePolicy"]
            .get("administered")
            .is_none()
    );
    assert!(login_body["result"].get("token").is_none());
    let initial_csrf_token = login_body["result"]["csrfToken"]
        .as_str()
        .unwrap()
        .to_string();

    let cookie_session = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/auth/session")
                .extension(ConnectInfo(
                    "127.0.0.1:40111".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-session")
                .header("Cookie", &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cookie_session.status(), StatusCode::OK);
    assert_eq!(
        response_json(cookie_session).await["result"]["passwordChangeRequired"],
        true
    );

    let required_change_token_denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/tokens")
                .extension(ConnectInfo(
                    "127.0.0.1:40112".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-token-password-required")
                .header("Cookie", &session_cookie)
                .header("X-Agent-Access-CSRF", &initial_csrf_token)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"name":"browser-token","allowedExecutionContexts":["default"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(required_change_token_denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(required_change_token_denied).await["reasonCode"],
        "password_change_required"
    );

    let required_change_services_denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/services")
                .extension(ConnectInfo(
                    "127.0.0.1:40116".parse::<SocketAddr>().unwrap(),
                ))
                .header(
                    REQUEST_ID_HEADER,
                    "managed-browser-services-password-required",
                )
                .header("Cookie", &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        required_change_services_denied.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response_json(required_change_services_denied).await["reasonCode"],
        "password_change_required"
    );

    let required_change_status_denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/broker/status")
                .extension(ConnectInfo(
                    "127.0.0.1:40118".parse::<SocketAddr>().unwrap(),
                ))
                .header(
                    REQUEST_ID_HEADER,
                    "managed-browser-status-password-required",
                )
                .header("Cookie", &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        required_change_status_denied.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response_json(required_change_status_denied).await["reasonCode"],
        "password_change_required"
    );

    let password_change = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/password/change")
                .extension(ConnectInfo(
                    "127.0.0.1:40113".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-password-change")
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header("Cookie", &session_cookie)
                .header("X-Agent-Access-CSRF", &initial_csrf_token)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"currentPassword":"alice-password","newPassword":"alice-password-updated"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(password_change.status(), StatusCode::OK);
    let changed_session_cookie = password_change
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let password_change_body = response_json(password_change).await;
    assert_eq!(
        password_change_body["result"]["passwordChangeRequired"],
        false
    );
    let csrf_token = password_change_body["result"]["csrfToken"]
        .as_str()
        .unwrap()
        .to_string();

    let changed_cookie_session = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/auth/session")
                .extension(ConnectInfo(
                    "127.0.0.1:40114".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-session-changed")
                .header("Cookie", &changed_session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(changed_cookie_session.status(), StatusCode::OK);
    let changed_cookie_session_body = response_json(changed_cookie_session).await;
    assert_eq!(changed_cookie_session_body["result"]["principal"], "alice");
    assert_eq!(
        changed_cookie_session_body["result"]["passwordChangeRequired"],
        false
    );

    let cookie_me = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/me")
                .extension(ConnectInfo(
                    "127.0.0.1:40115".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-me")
                .header("Cookie", &changed_session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cookie_me.status(), StatusCode::OK);
    let cookie_me_body = response_json(cookie_me).await;
    assert_eq!(cookie_me_body["principal"], "alice");
    assert_eq!(cookie_me_body["authenticated"], true);

    let cookie_status = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/broker/status")
                .extension(ConnectInfo(
                    "127.0.0.1:40118".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-status")
                .header("Cookie", &changed_session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cookie_status.status(), StatusCode::OK);
    assert_eq!(
        cookie_status.headers().get(CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        response_json(cookie_status).await,
        serde_json::to_value(broker_build_status()).unwrap()
    );

    let cookie_services = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/services")
                .extension(ConnectInfo(
                    "127.0.0.1:40116".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-services")
                .header("Cookie", &changed_session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cookie_services.status(), StatusCode::OK);
    let cookie_services_body = response_json(cookie_services).await;
    assert!(
        cookie_services_body
            .as_array()
            .unwrap()
            .iter()
            .any(|service| service["service"] == "fake")
    );

    let cookie_capabilities = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/capabilities")
                .extension(ConnectInfo(
                    "127.0.0.1:40117".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-capabilities")
                .header("Cookie", &changed_session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cookie_capabilities.status(), StatusCode::OK);
    let cookie_capabilities_body = response_json(cookie_capabilities).await;
    assert_eq!(cookie_capabilities_body["identity"]["principal"], "alice");
    assert!(
        cookie_capabilities_body["services"]
            .as_array()
            .unwrap()
            .iter()
            .any(|service| service["service"] == "fake")
    );

    let cookie_credential_targets = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/credentials/targets")
                .extension(ConnectInfo(
                    "127.0.0.1:40118".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-credential-targets")
                .header("Cookie", &changed_session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cookie_credential_targets.status(), StatusCode::OK);
    let cookie_credential_targets_body = response_json(cookie_credential_targets).await;
    let cookie_credential_targets = cookie_credential_targets_body["result"]
        .as_array()
        .expect("credential targets result must be an array");
    assert_eq!(cookie_credential_targets.len(), 1);
    assert_eq!(cookie_credential_targets[0]["service"], "gitlab");
    assert_eq!(cookie_credential_targets[0]["credentialName"], "default");
    assert_eq!(
        cookie_credential_targets[0]["inputSchema"]["fields"][0]["name"],
        "token"
    );

    let cookie_unconfigured_credential_name = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/v1/credentials/gitlab/other")
                .extension(ConnectInfo(
                    "127.0.0.1:40119".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-wrong-credential-name")
                .header("Cookie", &changed_session_cookie)
                .header("X-Agent-Access-CSRF", &csrf_token)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"profile":"gitlab-access-token","secret":{"token":"alice-token"},"metadata":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        cookie_unconfigured_credential_name.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        response_json(cookie_unconfigured_credential_name).await["reasonCode"],
        "input_invalid"
    );

    let cookie_mixed_service_credential = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/v1/credentials/gitlab_git/default")
                .extension(ConnectInfo(
                    "127.0.0.1:40120".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-mixed-service-credential")
                .header("Cookie", &changed_session_cookie)
                .header("X-Agent-Access-CSRF", &csrf_token)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"profile":"git-bearer-token","secret":{"token":"mixed-user-token"},"metadata":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        cookie_mixed_service_credential.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response_json(cookie_mixed_service_credential).await["reasonCode"],
        "service_action_denied"
    );

    let cookie_token_without_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/tokens")
                .extension(ConnectInfo(
                    "127.0.0.1:40112".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-token-no-csrf")
                .header("Cookie", &changed_session_cookie)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"name":"browser-token","allowedExecutionContexts":["default"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cookie_token_without_csrf.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(cookie_token_without_csrf).await["reasonCode"],
        "csrf_invalid"
    );

    let cookie_token_with_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/tokens")
                .extension(ConnectInfo(
                    "127.0.0.1:40113".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-token-with-csrf")
                .header("Cookie", &changed_session_cookie)
                .header("X-Agent-Access-CSRF", &csrf_token)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"name":"browser-token","allowedExecutionContexts":["default"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cookie_token_with_csrf.status(), StatusCode::OK);
    let cookie_token_with_csrf = response_json(cookie_token_with_csrf).await;
    assert!(cookie_token_with_csrf["result"]["token"].is_string());
    let cookie_agent_token_id = cookie_token_with_csrf["result"]["record"]["tokenId"]
        .as_str()
        .unwrap()
        .to_string();

    let cookie_pause_without_csrf = authed_json_request(
        app.clone(),
        Method::POST,
        format!("/v1/tokens/{cookie_agent_token_id}/pause"),
        "managed-browser-pause-token-no-csrf",
        "Cookie",
        changed_session_cookie.clone(),
        None,
    )
    .await;
    assert_eq!(cookie_pause_without_csrf.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(cookie_pause_without_csrf).await["reasonCode"],
        "csrf_invalid"
    );

    let cookie_pause_with_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/tokens/{cookie_agent_token_id}/pause"))
                .extension(ConnectInfo(
                    "127.0.0.1:40113".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-pause-token-with-csrf")
                .header("Cookie", &changed_session_cookie)
                .header("X-Agent-Access-CSRF", &csrf_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cookie_pause_with_csrf.status(), StatusCode::OK);
    assert!(response_json(cookie_pause_with_csrf).await["result"]["pausedAt"].is_string());

    let cookie_resume_with_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/tokens/{cookie_agent_token_id}/resume"))
                .extension(ConnectInfo(
                    "127.0.0.1:40113".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-resume-token-with-csrf")
                .header("Cookie", &changed_session_cookie)
                .header("X-Agent-Access-CSRF", &csrf_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cookie_resume_with_csrf.status(), StatusCode::OK);
    assert!(response_json(cookie_resume_with_csrf).await["result"]["pausedAt"].is_null());

    let cookie_admin_denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/admin/store/status")
                .extension(ConnectInfo(
                    "127.0.0.1:40114".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-browser-admin-denied")
                .header("Cookie", &changed_session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cookie_admin_denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(cookie_admin_denied).await["reasonCode"],
        "management_denied"
    );

    let create_mallory = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals",
        "managed-create-mallory",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"principalId":"mallory","kind":"user"}"#),
    )
    .await;
    assert_eq!(create_mallory.status(), StatusCode::OK);

    let admin_put_mallory_credential = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/admin/principals/mallory/credentials/gitlab/default",
        "managed-put-mallory-credential",
        "Authorization",
        admin_authorization.clone(),
        Some(
            r#"{"profile":"gitlab-access-token","secret":{"token":"mallory-token"},"metadata":{}}"#,
        ),
    )
    .await;
    assert_eq!(admin_put_mallory_credential.status(), StatusCode::OK);

    let mallory_token_issue = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals/mallory/tokens",
        "managed-issue-mallory-token",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"name":"mallory setup","tokenClass":"user_manage"}"#),
    )
    .await;
    assert_eq!(mallory_token_issue.status(), StatusCode::OK);
    let mallory_token = response_json(mallory_token_issue).await["result"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let mallory_authorization = format!("Bearer {mallory_token}");

    let mallory_list_without_policy = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/credentials",
        "managed-token-list-without-policy",
        "Authorization",
        mallory_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(mallory_list_without_policy.status(), StatusCode::OK);
    let mallory_list_without_policy_body = response_json(mallory_list_without_policy).await;
    assert_eq!(
        mallory_list_without_policy_body["result"][0]["service"],
        "gitlab"
    );
    assert_no_secret_storage_fields(&mallory_list_without_policy_body);

    let mallory_inspect_without_policy = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/credentials/gitlab/default",
        "managed-token-inspect-without-policy",
        "Authorization",
        mallory_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(
        mallory_inspect_without_policy.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response_json(mallory_inspect_without_policy).await["reasonCode"],
        "service_action_denied"
    );

    let mallory_schema_without_policy = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/credentials/gitlab/default/input-schema?profile=gitlab-access-token",
        "managed-token-schema-without-policy",
        "Authorization",
        mallory_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(
        mallory_schema_without_policy.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response_json(mallory_schema_without_policy).await["reasonCode"],
        "service_action_denied"
    );

    let mallory_put_without_policy = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/credentials/gitlab/default",
        "managed-token-put-without-policy",
        "Authorization",
        mallory_authorization.clone(),
        Some(r#"{"profile":"gitlab-access-token","secret":{"token":"mallory-token-rotated"},"metadata":{}}"#),
    )
    .await;
    assert_eq!(mallory_put_without_policy.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(mallory_put_without_policy).await["reasonCode"],
        "service_action_denied"
    );

    let mallory_verify_without_policy = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/credentials/gitlab/default/verify",
        "managed-token-verify-without-policy",
        "Authorization",
        mallory_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(
        mallory_verify_without_policy.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response_json(mallory_verify_without_policy).await["reasonCode"],
        "service_action_denied"
    );

    let mallory_delete_without_policy = authed_json_request(
        app.clone(),
        Method::DELETE,
        "/v1/credentials/gitlab/default",
        "managed-token-delete-without-policy",
        "Authorization",
        mallory_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(
        mallory_delete_without_policy.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response_json(mallory_delete_without_policy).await["reasonCode"],
        "service_action_denied"
    );

    let add_mallory_group = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/admin/principals/mallory/groups/users",
        "managed-add-mallory-group",
        "Authorization",
        admin_authorization.clone(),
        Some("{}"),
    )
    .await;
    assert_eq!(add_mallory_group.status(), StatusCode::OK);

    let mallory_list_with_policy = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/credentials",
        "managed-token-list-with-policy",
        "Authorization",
        mallory_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(mallory_list_with_policy.status(), StatusCode::OK);
    let mallory_list_body = response_json(mallory_list_with_policy).await;
    assert_eq!(mallory_list_body["result"][0]["service"], "gitlab");
    assert_eq!(mallory_list_body["result"][0]["name"], "default");
    assert_no_secret_storage_fields(&mallory_list_body);
    assert!(!mallory_list_body.to_string().contains("mallory-token"));

    let mallory_inspect_with_policy = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/credentials/gitlab/default",
        "managed-token-inspect-with-policy",
        "Authorization",
        mallory_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(mallory_inspect_with_policy.status(), StatusCode::OK);
    let mallory_inspect_body = response_json(mallory_inspect_with_policy).await;
    assert_no_secret_storage_fields(&mallory_inspect_body);

    let mallory_schema_with_policy = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/credentials/gitlab/default/input-schema?profile=gitlab-access-token",
        "managed-token-schema-with-policy",
        "Authorization",
        mallory_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(mallory_schema_with_policy.status(), StatusCode::OK);

    let mallory_put_with_policy = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/credentials/gitlab/default",
        "managed-token-put-with-policy",
        "Authorization",
        mallory_authorization.clone(),
        Some(r#"{"profile":"gitlab-access-token","secret":{"token":"mallory-token-rotated"},"metadata":{}}"#),
    )
    .await;
    assert_eq!(mallory_put_with_policy.status(), StatusCode::OK);
    let mallory_put_body = response_json(mallory_put_with_policy).await;
    assert_no_secret_storage_fields(&mallory_put_body);

    let mallory_verify_with_policy = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/credentials/gitlab/default/verify",
        "managed-token-verify-with-policy",
        "Authorization",
        mallory_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(mallory_verify_with_policy.status(), StatusCode::OK);
    let mallory_verify_body = response_json(mallory_verify_with_policy).await;
    assert_no_secret_storage_fields(&mallory_verify_body);

    let mallory_delete_with_policy = authed_json_request(
        app.clone(),
        Method::DELETE,
        "/v1/credentials/gitlab/default",
        "managed-token-delete-with-policy",
        "Authorization",
        mallory_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(mallory_delete_with_policy.status(), StatusCode::OK);
    let mallory_delete_body = response_json(mallory_delete_with_policy).await;
    assert_no_secret_storage_fields(&mallory_delete_body);

    let admin_input_schema = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(
                    "/v1/admin/principals/alice/credentials/gitlab/default/input-schema?profile=gitlab-access-token",
                )
                .extension(ConnectInfo(
                    "127.0.0.1:40116".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-admin-input-schema")
                .header("Authorization", admin_authorization.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_input_schema.status(), StatusCode::OK);
    let admin_input_schema_body = response_json(admin_input_schema).await;
    assert_eq!(admin_input_schema_body["result"]["service"], "gitlab");
    assert_eq!(
        admin_input_schema_body["result"]["profile"],
        "gitlab-access-token"
    );
    assert_eq!(
        admin_input_schema_body["result"]["credentialKind"],
        "bearer_token"
    );
    assert_eq!(
        admin_input_schema_body["result"]["fields"][0]["name"],
        "token"
    );
    assert_eq!(
        admin_input_schema_body["result"]["fields"][0]["secret"],
        true
    );

    let admin_input_schema_wrong_profile = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(
                    "/v1/admin/principals/alice/credentials/gitlab/default/input-schema?profile=unsupported-profile",
                )
                .extension(ConnectInfo(
                    "127.0.0.1:40118".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-admin-input-schema-wrong-profile")
                .header("Authorization", admin_authorization.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        admin_input_schema_wrong_profile.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        response_json(admin_input_schema_wrong_profile).await["reasonCode"],
        "input_invalid"
    );

    let admin_put_wrong_profile = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/v1/admin/principals/alice/credentials/gitlab/default")
                .extension(ConnectInfo(
                    "127.0.0.1:40120".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-admin-put-wrong-profile")
                .header("Authorization", admin_authorization.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"profile":"unsupported-profile","secret":{"token":"gitlab-token"},"metadata":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_put_wrong_profile.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(admin_put_wrong_profile).await["reasonCode"],
        "input_invalid"
    );

    let admin_input_schema_bad_query = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(
                    "/v1/admin/principals/alice/credentials/gitlab/default/input-schema?unknown=value",
                )
                .extension(ConnectInfo(
                    "127.0.0.1:40119".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-admin-input-schema-bad-query")
                .header("Authorization", admin_authorization.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        admin_input_schema_bad_query.status(),
        StatusCode::BAD_REQUEST
    );
    let admin_input_schema_bad_query_body = response_json(admin_input_schema_bad_query).await;
    assert_eq!(
        admin_input_schema_bad_query_body["reasonCode"],
        "input_invalid"
    );
    assert_eq!(
        admin_input_schema_bad_query_body["requestId"],
        "managed-admin-input-schema-bad-query"
    );

    let put_credential = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/v1/admin/principals/alice/credentials/gitlab/default")
                .extension(ConnectInfo("127.0.0.1:40101".parse::<SocketAddr>().unwrap()))
                .header(REQUEST_ID_HEADER, "managed-put-credential")
                .header("Authorization", admin_authorization.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"profile":"gitlab-access-token","secret":{"token":"gitlab-token"},"metadata":{"displayName":"GitLab"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_credential.status(), StatusCode::OK);
    let put_body = response_json(put_credential).await;
    assert_eq!(put_body["result"]["credentialKind"], "bearer_token");
    let credential_id = put_body["result"]["credentialId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_no_secret_storage_fields(&put_body);
    assert!(!put_body.to_string().contains("gitlab-token"));

    let inspect_by_id = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/admin/credentials/{credential_id}"))
                .extension(ConnectInfo(
                    "127.0.0.1:40111".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-inspect-credential-id")
                .header("Authorization", admin_authorization.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inspect_by_id.status(), StatusCode::OK);
    let inspect_by_id_body = response_json(inspect_by_id).await;
    assert_no_secret_storage_fields(&inspect_by_id_body);

    let update_by_id = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v1/admin/credentials/{credential_id}"))
                .extension(ConnectInfo(
                    "127.0.0.1:40112".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-update-credential-id")
                .header("Authorization", admin_authorization.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"profile":"gitlab-access-token","secret":{"token":"gitlab-token-rotated"},"metadata":{"displayName":"GitLab rotated"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_by_id.status(), StatusCode::OK);
    let update_body = response_json(update_by_id).await;
    assert_no_secret_storage_fields(&update_body);
    assert!(!update_body.to_string().contains("gitlab-token-rotated"));

    let grant = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/admin/rights")
                .extension(ConnectInfo("127.0.0.1:40102".parse::<SocketAddr>().unwrap()))
                .header(REQUEST_ID_HEADER, "managed-grant-right")
                .header("Authorization", admin_authorization.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"principalId":"alice","right":"credentials:self:read_metadata","service":"gitlab","credentialName":"default"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(grant.status(), StatusCode::OK);

    let grant_verify = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/admin/rights")
                .extension(ConnectInfo(
                    "127.0.0.1:40114".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-grant-verify-right")
                .header("Authorization", admin_authorization.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"principalId":"alice","right":"credentials:self:verify","service":"gitlab","credentialName":"default"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(grant_verify.status(), StatusCode::OK);

    let issue_token = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/admin/principals/alice/tokens")
                .extension(ConnectInfo(
                    "127.0.0.1:40103".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-issue-token")
                .header("Authorization", admin_authorization.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"name":"alice setup","tokenClass":"user_manage"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(issue_token.status(), StatusCode::OK);
    let issued = response_json(issue_token).await;
    let raw_token = issued["result"]["token"].as_str().unwrap().to_string();
    let token_id = issued["result"]["record"]["tokenId"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(issued["result"]["record"]["expiresAt"].is_string());
    assert!(raw_token.starts_with("aab_um_"));

    let user_input_schema_without_write = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/credentials/gitlab/default/input-schema?profile=gitlab-access-token")
                .extension(ConnectInfo(
                    "127.0.0.1:40117".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-user-schema-no-write")
                .header("Authorization", format!("Bearer {raw_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(user_input_schema_without_write.status(), StatusCode::OK);
    let user_input_schema_body = response_json(user_input_schema_without_write).await;
    assert_eq!(
        user_input_schema_body["result"]["profile"],
        "gitlab-access-token"
    );

    let self_issue_token = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/tokens",
        "managed-self-issue-agent-token",
        "Authorization",
        format!("Bearer {raw_token}"),
        Some(r#"{"name":"alice self invoke","ttl":"30d","allowedServices":["fake"],"allowedExecutionContexts":["default"]}"#),
    )
    .await;
    assert_eq!(self_issue_token.status(), StatusCode::OK);
    let self_issued = response_json(self_issue_token).await;
    let self_agent_token = self_issued["result"]["token"].as_str().unwrap().to_string();
    let self_agent_token_id = self_issued["result"]["record"]["tokenId"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(self_agent_token.starts_with("aab_ai_"));
    assert_eq!(
        self_issued["result"]["record"]["scopes"]["allowedServices"],
        json!(["fake"])
    );
    assert_eq!(
        self_issued["result"]["record"]["scopes"]["allowedExecutionContexts"],
        json!(["default"])
    );
    assert!(!self_issued.to_string().contains("tokenHash"));

    let self_issue_smuggled_class = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/tokens",
        "managed-self-issue-smuggled-class",
        "Authorization",
        format!("Bearer {raw_token}"),
        Some(r#"{"name":"bad","tokenClass":"admin"}"#),
    )
    .await;
    assert_eq!(self_issue_smuggled_class.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(self_issue_smuggled_class).await["reasonCode"],
        "input_invalid"
    );

    let self_issue_unknown_service = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/tokens",
        "managed-self-issue-unknown-service",
        "Authorization",
        format!("Bearer {raw_token}"),
        Some(r#"{"name":"bad service","allowedServices":["missing"],"allowedExecutionContexts":["default"]}"#),
    )
    .await;
    assert_eq!(self_issue_unknown_service.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(self_issue_unknown_service).await["reasonCode"],
        "input_invalid"
    );

    for (request_id, body) in [
        (
            "managed-self-issue-zero-ttl",
            r#"{"name":"bad ttl","ttl":"0d","allowedExecutionContexts":["default"]}"#,
        ),
        (
            "managed-self-issue-both-expiry-inputs",
            r#"{"name":"bad ttl","ttl":"1d","expiresAt":"2999-01-01T00:00:00Z","allowedExecutionContexts":["default"]}"#,
        ),
        (
            "managed-self-issue-past-expiry",
            r#"{"name":"bad expiry","expiresAt":"2000-01-01T00:00:00Z","allowedExecutionContexts":["default"]}"#,
        ),
        (
            "managed-self-issue-never",
            r#"{"name":"bad never","never":true,"allowedExecutionContexts":["default"]}"#,
        ),
        (
            "managed-self-issue-expiry-beyond-max",
            r#"{"name":"bad max","expiresAt":"2999-01-01T00:00:00Z","allowedExecutionContexts":["default"]}"#,
        ),
        (
            "managed-self-issue-smuggled-principal",
            r#"{"name":"bad","principalId":"bob"}"#,
        ),
        (
            "managed-self-issue-smuggled-scopes",
            r#"{"name":"bad","scopes":{"allowedServices":["fake"]},"allowedExecutionContexts":["default"]}"#,
        ),
        (
            "managed-self-issue-unknown-field",
            r#"{"name":"bad","surprise":true}"#,
        ),
        (
            "managed-self-issue-empty-services",
            r#"{"name":"bad","allowedServices":[],"allowedExecutionContexts":["default"]}"#,
        ),
        (
            "managed-self-issue-duplicate-services",
            r#"{"name":"bad","allowedServices":["fake","fake"],"allowedExecutionContexts":["default"]}"#,
        ),
        (
            "managed-self-issue-non-array-services",
            r#"{"name":"bad","allowedServices":"fake","allowedExecutionContexts":["default"]}"#,
        ),
        (
            "managed-self-issue-non-string-service",
            r#"{"name":"bad","allowedServices":["fake",5],"allowedExecutionContexts":["default"]}"#,
        ),
    ] {
        let response = authed_json_request(
            app.clone(),
            Method::POST,
            "/v1/tokens",
            request_id,
            "Authorization",
            format!("Bearer {raw_token}"),
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{request_id}");
        assert_eq!(response_json(response).await["reasonCode"], "input_invalid");
    }

    let self_tokens_list = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/tokens",
        "managed-self-tokens-list",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(self_tokens_list.status(), StatusCode::OK);
    let self_tokens = response_json(self_tokens_list).await;
    assert_eq!(self_tokens["result"][0]["tokenId"], self_agent_token_id);
    assert!(!self_tokens.to_string().contains(&self_agent_token));
    assert!(!self_tokens.to_string().contains("tokenHash"));

    let self_token_inspect = authed_json_request(
        app.clone(),
        Method::GET,
        format!("/v1/tokens/{self_agent_token_id}"),
        "managed-self-token-inspect",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(self_token_inspect.status(), StatusCode::OK);
    let self_token_inspect_body = response_json(self_token_inspect).await;
    assert_eq!(
        self_token_inspect_body["result"]["tokenId"],
        self_agent_token_id
    );
    assert!(
        !self_token_inspect_body
            .to_string()
            .contains(&self_agent_token)
    );

    let self_agent_on_tokens = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/tokens",
        "managed-agent-token-self-tokens-denied",
        "Authorization",
        format!("Bearer {self_agent_token}"),
        None,
    )
    .await;
    assert_eq!(self_agent_on_tokens.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(self_agent_on_tokens).await["reasonCode"],
        "broker_token_class_denied"
    );

    let self_agent_invoke = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/invoke/fake/echo",
        "managed-self-agent-invoke-fake",
        "Authorization",
        format!("Bearer {self_agent_token}"),
        Some(r#"{"inputs":{"project":"TEST","message":"self agent"}}"#),
    )
    .await;
    assert_eq!(self_agent_invoke.status(), StatusCode::OK);
    assert_eq!(
        response_json(self_agent_invoke).await["result"]["message"],
        "self agent"
    );

    let self_agent_after_first_use = authed_json_request(
        app.clone(),
        Method::GET,
        format!("/v1/tokens/{self_agent_token_id}"),
        "managed-self-token-after-first-use",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(self_agent_after_first_use.status(), StatusCode::OK);
    let self_agent_after_first_use = response_json(self_agent_after_first_use).await;
    let last_used_before_pause = self_agent_after_first_use["result"]["lastUsedAt"]
        .as_str()
        .expect("successful invocation must update lastUsedAt")
        .to_string();

    let self_pause_agent = authed_json_request(
        app.clone(),
        Method::POST,
        format!("/v1/tokens/{self_agent_token_id}/pause"),
        "managed-self-pause-agent-token",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(self_pause_agent.status(), StatusCode::OK);
    let self_pause_agent = response_json(self_pause_agent).await;
    assert!(self_pause_agent["result"]["pausedAt"].is_string());
    assert_eq!(self_pause_agent["result"]["pausedBy"], "alice");
    let paused_at = self_pause_agent["result"]["pausedAt"]
        .as_str()
        .unwrap()
        .to_string();

    let self_pause_agent_again = authed_json_request(
        app.clone(),
        Method::POST,
        format!("/v1/tokens/{self_agent_token_id}/pause"),
        "managed-self-pause-agent-token-idempotent",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(self_pause_agent_again.status(), StatusCode::OK);
    assert_eq!(
        response_json(self_pause_agent_again).await["result"]["pausedAt"],
        paused_at
    );

    let paused_self_agent_use = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/invoke/fake/echo",
        "managed-paused-self-agent-use",
        "Authorization",
        format!("Bearer {self_agent_token}"),
        Some(r#"{"inputs":{"project":"TEST","message":"paused"}}"#),
    )
    .await;
    assert_eq!(paused_self_agent_use.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(paused_self_agent_use).await["reasonCode"],
        "broker_token_paused"
    );

    let self_agent_while_paused = authed_json_request(
        app.clone(),
        Method::GET,
        format!("/v1/tokens/{self_agent_token_id}"),
        "managed-self-token-while-paused",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(self_agent_while_paused.status(), StatusCode::OK);
    let self_agent_while_paused = response_json(self_agent_while_paused).await;
    assert_eq!(
        self_agent_while_paused["result"]["lastUsedAt"],
        last_used_before_pause
    );
    let self_tokens_while_paused = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/tokens",
        "managed-self-tokens-list-while-paused",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(self_tokens_while_paused.status(), StatusCode::OK);
    assert!(
        response_json(self_tokens_while_paused).await["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|token| {
                token["tokenId"] == self_agent_token_id && token["pausedAt"].is_string()
            })
    );

    let self_resume_agent = authed_json_request(
        app.clone(),
        Method::POST,
        format!("/v1/tokens/{self_agent_token_id}/resume"),
        "managed-self-resume-agent-token",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(self_resume_agent.status(), StatusCode::OK);
    let self_resume_agent = response_json(self_resume_agent).await;
    assert!(self_resume_agent["result"]["pausedAt"].is_null());
    assert!(self_resume_agent["result"]["pausedBy"].is_null());

    let self_resume_agent_again = authed_json_request(
        app.clone(),
        Method::POST,
        format!("/v1/tokens/{self_agent_token_id}/resume"),
        "managed-self-resume-agent-token-idempotent",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(self_resume_agent_again.status(), StatusCode::OK);
    assert!(response_json(self_resume_agent_again).await["result"]["pausedAt"].is_null());

    let resumed_self_agent_use = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/invoke/fake/echo",
        "managed-resumed-self-agent-use",
        "Authorization",
        format!("Bearer {self_agent_token}"),
        Some(r#"{"inputs":{"project":"TEST","message":"resumed"}}"#),
    )
    .await;
    assert_eq!(resumed_self_agent_use.status(), StatusCode::OK);
    assert_eq!(
        response_json(resumed_self_agent_use).await["result"]["message"],
        "resumed"
    );

    for (pause_uri, resume_uri, prefix) in [
        (
            format!("/v1/admin/principals/alice/agent-tokens/{self_agent_token_id}/pause"),
            format!("/v1/admin/principals/alice/agent-tokens/{self_agent_token_id}/resume"),
            "managed-principal-admin",
        ),
        (
            format!("/v1/admin/tokens/{self_agent_token_id}/pause"),
            format!("/v1/admin/tokens/{self_agent_token_id}/resume"),
            "managed-global-admin",
        ),
    ] {
        let pause = authed_json_request(
            app.clone(),
            Method::POST,
            pause_uri,
            &format!("{prefix}-pause-agent-token"),
            "Authorization",
            admin_authorization.clone(),
            None,
        )
        .await;
        assert_eq!(pause.status(), StatusCode::OK, "{prefix}");
        assert!(response_json(pause).await["result"]["pausedAt"].is_string());

        let resume = authed_json_request(
            app.clone(),
            Method::POST,
            resume_uri,
            &format!("{prefix}-resume-agent-token"),
            "Authorization",
            admin_authorization.clone(),
            None,
        )
        .await;
        assert_eq!(resume.status(), StatusCode::OK, "{prefix}");
        assert!(response_json(resume).await["result"]["pausedAt"].is_null());
    }

    let self_agent_policy_denied = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/invoke/fake/echo",
        "managed-self-agent-policy-denied",
        "Authorization",
        format!("Bearer {self_agent_token}"),
        Some(r#"{"inputs":{"project":"OTHER","message":"denied"}}"#),
    )
    .await;
    assert_eq!(self_agent_policy_denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(self_agent_policy_denied).await["reasonCode"],
        "service_action_denied"
    );

    let self_issue_gitlab_only = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/tokens",
        "managed-self-issue-gitlab-only",
        "Authorization",
        format!("Bearer {raw_token}"),
        Some(r#"{"name":"gitlab only","allowedServices":["gitlab"],"allowedExecutionContexts":["default"]}"#),
    )
    .await;
    assert_eq!(self_issue_gitlab_only.status(), StatusCode::OK);
    let gitlab_only_token = response_json(self_issue_gitlab_only).await["result"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let gitlab_only_on_fake = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/invoke/fake/echo",
        "managed-gitlab-only-on-fake",
        "Authorization",
        format!("Bearer {gitlab_only_token}"),
        Some(r#"{"inputs":{"project":"TEST","message":"blocked"}}"#),
    )
    .await;
    assert_eq!(gitlab_only_on_fake.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(gitlab_only_on_fake).await["reasonCode"],
        "service_action_denied"
    );

    let self_issue_unrestricted = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/tokens",
        "managed-self-issue-unrestricted",
        "Authorization",
        format!("Bearer {raw_token}"),
        Some(r#"{"name":"unrestricted","allowedExecutionContexts":["default"]}"#),
    )
    .await;
    assert_eq!(self_issue_unrestricted.status(), StatusCode::OK);
    assert_eq!(
        self_issue_unrestricted.headers()[axum::http::header::CACHE_CONTROL],
        "no-store"
    );
    let unrestricted_issued = response_json(self_issue_unrestricted).await;
    assert!(unrestricted_issued["result"]["record"]["expiresAt"].is_string());
    assert_eq!(
        unrestricted_issued["result"]["record"]["scopes"],
        json!({"allowedExecutionContexts": ["default"]})
    );
    let unrestricted_token = unrestricted_issued["result"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let unrestricted_on_fake = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/invoke/fake/echo",
        "managed-unrestricted-on-fake",
        "Authorization",
        format!("Bearer {unrestricted_token}"),
        Some(r#"{"inputs":{"project":"TEST","message":"unrestricted"}}"#),
    )
    .await;
    assert_eq!(unrestricted_on_fake.status(), StatusCode::OK);

    let self_revoke_agent = authed_json_request(
        app.clone(),
        Method::DELETE,
        format!("/v1/tokens/{self_agent_token_id}"),
        "managed-self-revoke-agent-token",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(self_revoke_agent.status(), StatusCode::OK);
    assert!(response_json(self_revoke_agent).await["result"]["revokedAt"].is_string());
    let revoked_self_agent_use = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/invoke/fake/echo",
        "managed-revoked-self-agent-use",
        "Authorization",
        format!("Bearer {self_agent_token}"),
        Some(r#"{"inputs":{"project":"TEST","message":"revoked"}}"#),
    )
    .await;
    assert_eq!(revoked_self_agent_use.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(revoked_self_agent_use).await["reasonCode"],
        "broker_token_revoked"
    );

    let resume_revoked_self_agent = authed_json_request(
        app.clone(),
        Method::POST,
        format!("/v1/tokens/{self_agent_token_id}/resume"),
        "managed-self-resume-revoked-agent-token",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(resume_revoked_self_agent.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(resume_revoked_self_agent).await["reasonCode"],
        "broker_token_state_conflict"
    );

    let pause_revoked_principal_agent = authed_json_request(
        app.clone(),
        Method::POST,
        format!("/v1/admin/principals/alice/agent-tokens/{self_agent_token_id}/pause"),
        "managed-principal-admin-pause-revoked-agent-token",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(pause_revoked_principal_agent.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(pause_revoked_principal_agent).await["reasonCode"],
        "broker_token_state_conflict"
    );

    let self_tokens_list_revoked = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/tokens?includeRevoked=true",
        "managed-self-tokens-list-revoked",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(self_tokens_list_revoked.status(), StatusCode::OK);
    assert!(
        response_json(self_tokens_list_revoked).await["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|token| token["tokenId"] == self_agent_token_id)
    );

    let inspect_token = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/admin/tokens/{token_id}"))
                .extension(ConnectInfo(
                    "127.0.0.1:40113".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-inspect-token-id")
                .header("Authorization", admin_authorization.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inspect_token.status(), StatusCode::OK);
    let inspect_token_body = response_json(inspect_token).await;
    assert!(inspect_token_body["result"].get("tokenHash").is_none());
    assert!(!inspect_token_body.to_string().contains(&raw_token));

    let user_put_without_write_right = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/credentials/gitlab/default",
        "managed-user-put-no-write-right",
        "Authorization",
        format!("Bearer {raw_token}"),
        Some(r#"{"profile":"gitlab-access-token","secret":{"token":"gitlab-token-user-rotated"},"metadata":{"displayName":"User rotated"}}"#),
    )
    .await;
    assert_eq!(user_put_without_write_right.status(), StatusCode::OK);
    let user_put_without_write_body = response_json(user_put_without_write_right).await;
    assert_no_secret_storage_fields(&user_put_without_write_body);
    assert!(
        !user_put_without_write_body
            .to_string()
            .contains("gitlab-token-user-rotated")
    );

    {
        let conn = rusqlite::Connection::open(&store_path).unwrap();
        conn.execute(
            "UPDATE credential_secret_material
             SET key_id = 'leaked-secret-key-id'
             WHERE credential_id = ?1",
            rusqlite::params![credential_id.as_str()],
        )
        .unwrap();
    }
    let missing_key_verify = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/credentials/gitlab/default/verify",
        "managed-user-verify-missing-key",
        "Authorization",
        format!("Bearer {raw_token}"),
        Some("{}"),
    )
    .await;
    assert_eq!(missing_key_verify.status(), StatusCode::SERVICE_UNAVAILABLE);
    let missing_key_body = response_json(missing_key_verify).await;
    assert_eq!(missing_key_body["reasonCode"], "encryption_key_missing");
    assert!(
        missing_key_body
            .to_string()
            .contains("credential encryption key is unavailable")
    );
    assert!(
        !missing_key_body
            .to_string()
            .contains("leaked-secret-key-id")
    );
    assert_no_secret_storage_fields(&missing_key_body);
    {
        let conn = rusqlite::Connection::open(&store_path).unwrap();
        conn.execute(
            "UPDATE credential_secret_material SET key_id = 'k1' WHERE credential_id = ?1",
            rusqlite::params![credential_id.as_str()],
        )
        .unwrap();
    }

    let verify = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/credentials/gitlab/default/verify")
                .extension(ConnectInfo(
                    "127.0.0.1:40115".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-user-verify")
                .header("Authorization", format!("Bearer {raw_token}"))
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify.status(), StatusCode::OK);
    let verify_body = response_json(verify).await;
    assert_eq!(
        verify_body["result"]["verificationStatus"],
        "upstream_verified"
    );
    assert!(verify_body["result"]["lastVerifiedAt"].is_string());
    assert_no_secret_storage_fields(&verify_body);

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/credentials")
                .extension(ConnectInfo(
                    "127.0.0.1:40104".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-user-list")
                .header("Authorization", format!("Bearer {raw_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let list_body = response_json(list).await;
    assert_eq!(list_body["principal"], "alice");
    assert_eq!(list_body["result"][0]["service"], "gitlab");
    assert_eq!(list_body["result"][0]["name"], "default");
    assert_eq!(
        list_body["result"][0]["verificationStatus"],
        "upstream_verified"
    );
    assert_no_secret_storage_fields(&list_body);
    assert!(!list_body.to_string().contains("gitlab-token"));

    let non_admin = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/tokens",
        "managed-non-admin-denied",
        "Authorization",
        mallory_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(non_admin.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(non_admin).await["reasonCode"],
        "broker_token_class_denied"
    );

    let invalid_secret = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/admin/principals/alice/credentials/gitlab/default",
        "managed-invalid-secret",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"profile":"gitlab-access-token","secret":{},"metadata":{}}"#),
    )
    .await;
    assert_eq!(invalid_secret.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(invalid_secret).await["reasonCode"],
        "input_invalid"
    );

    let agent_token_issue = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/tokens",
        "managed-issue-agent-token",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"name":"alice invoke","tokenClass":"agent_invoke","scopes":{"allowedExecutionContexts":["default"]},"never":true}"#),
    )
    .await;
    assert_eq!(agent_token_issue.status(), StatusCode::OK);
    let agent_token_issue_body = response_json(agent_token_issue).await;
    assert!(agent_token_issue_body["result"]["record"]["expiresAt"].is_null());
    let agent_token = agent_token_issue_body["result"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let malformed_scope_token_issue = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/tokens",
        "managed-issue-malformed-scope-token",
        "Authorization",
        admin_authorization.clone(),
        Some(
            r#"{"name":"bad scope","tokenClass":"agent_invoke","scopes":{"allowedServices":[],"allowedExecutionContexts":["default"]},"ttl":"8h"}"#,
        ),
    )
    .await;
    assert_eq!(
        malformed_scope_token_issue.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        response_json(malformed_scope_token_issue).await["reasonCode"],
        "input_invalid"
    );
    let agent_on_user_route = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/credentials",
        "managed-agent-token-user-route",
        "Authorization",
        format!("Bearer {agent_token}"),
        None,
    )
    .await;
    assert_eq!(agent_on_user_route.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(agent_on_user_route).await["reasonCode"],
        "broker_token_class_denied"
    );

    let user_on_admin_route = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/tokens",
        "managed-user-token-admin-route",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(user_on_admin_route.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(user_on_admin_route).await["reasonCode"],
        "broker_token_class_denied"
    );

    let admin_token_missing_role = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/tokens",
        "managed-issue-admin-token-non-admin-target",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"name":"alice admin","tokenClass":"admin"}"#),
    )
    .await;
    assert_eq!(admin_token_missing_role.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(admin_token_missing_role).await["reasonCode"],
        "input_invalid"
    );

    let grant_alice_admin = authed_json_request(
        app.clone(),
        Method::PATCH,
        "/v1/admin/principals/alice/access",
        "managed-grant-alice-admin-before-token",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"role":"admin"}"#),
    )
    .await;
    assert_eq!(grant_alice_admin.status(), StatusCode::OK);

    let admin_token_missing_expiry = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/tokens",
        "managed-issue-admin-token-missing-expiry",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"name":"alice admin","tokenClass":"admin"}"#),
    )
    .await;
    assert_eq!(admin_token_missing_expiry.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(admin_token_missing_expiry).await["reasonCode"],
        "input_invalid"
    );

    let admin_token_never = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/tokens",
        "managed-issue-admin-token-never",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"name":"alice admin","tokenClass":"admin","never":true}"#),
    )
    .await;
    assert_eq!(admin_token_never.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(admin_token_never).await["reasonCode"],
        "input_invalid"
    );

    let admin_token_issue = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/tokens",
        "managed-issue-admin-token",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"name":"alice admin","tokenClass":"admin","ttl":"2h"}"#),
    )
    .await;
    assert_eq!(admin_token_issue.status(), StatusCode::OK);
    assert_eq!(
        admin_token_issue.headers()[axum::http::header::CACHE_CONTROL],
        "no-store"
    );
    let admin_issued = response_json(admin_token_issue).await;
    assert_eq!(admin_issued["result"]["record"]["browserSession"], false);
    assert!(admin_issued["result"]["record"]["expiresAt"].is_string());
    let raw_admin_token = admin_issued["result"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let admin_token_id = admin_issued["result"]["record"]["tokenId"]
        .as_str()
        .unwrap()
        .to_string();
    let admin_on_user_route = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/credentials",
        "managed-admin-token-user-route",
        "Authorization",
        format!("Bearer {raw_admin_token}"),
        None,
    )
    .await;
    assert_eq!(admin_on_user_route.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(admin_on_user_route).await["reasonCode"],
        "broker_token_class_denied"
    );
    let admin_on_tokens_route = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/tokens",
        "managed-admin-token-self-tokens-denied",
        "Authorization",
        format!("Bearer {raw_admin_token}"),
        None,
    )
    .await;
    assert_eq!(admin_on_tokens_route.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(admin_on_tokens_route).await["reasonCode"],
        "broker_token_class_denied"
    );
    let admin_token_admin_route = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/config/status",
        "managed-alice-admin-token-admin-route",
        "Authorization",
        format!("Bearer {raw_admin_token}"),
        None,
    )
    .await;
    assert_eq!(admin_token_admin_route.status(), StatusCode::OK);
    let revoke_alice_admin = authed_json_request(
        app.clone(),
        Method::PATCH,
        "/v1/admin/principals/alice/access",
        "managed-revoke-alice-admin-after-token",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"role":"user"}"#),
    )
    .await;
    assert_eq!(revoke_alice_admin.status(), StatusCode::OK);
    let admin_token_without_role = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/admin/config/status",
        "managed-alice-admin-token-role-revoked",
        "Authorization",
        format!("Bearer {raw_admin_token}"),
        None,
    )
    .await;
    assert_eq!(admin_token_without_role.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(admin_token_without_role).await["reasonCode"],
        "broker_token_revoked"
    );
    let user_inspect_admin_token = authed_json_request(
        app.clone(),
        Method::GET,
        format!("/v1/tokens/{admin_token_id}"),
        "managed-user-inspect-admin-token",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(user_inspect_admin_token.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(user_inspect_admin_token).await["reasonCode"],
        "credential_not_found"
    );
    let user_revoke_admin_token = authed_json_request(
        app.clone(),
        Method::DELETE,
        format!("/v1/tokens/{admin_token_id}"),
        "managed-user-revoke-admin-token",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(user_revoke_admin_token.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(user_revoke_admin_token).await["reasonCode"],
        "credential_not_found"
    );
    let global_admin_pause_management_token = authed_json_request(
        app.clone(),
        Method::POST,
        format!("/v1/admin/tokens/{admin_token_id}/pause"),
        "managed-global-admin-pause-management-token",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(
        global_admin_pause_management_token.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        response_json(global_admin_pause_management_token).await["reasonCode"],
        "broker_token_not_found"
    );

    let create_bob = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals",
        "managed-create-bob",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"principalId":"bob","kind":"user"}"#),
    )
    .await;
    assert_eq!(create_bob.status(), StatusCode::OK);
    let bob_token_issue = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals/bob/tokens",
        "managed-issue-bob-token",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"name":"bob setup","tokenClass":"user_manage"}"#),
    )
    .await;
    assert_eq!(bob_token_issue.status(), StatusCode::OK);
    let bob_issued = response_json(bob_token_issue).await;
    let bob_token = bob_issued["result"]["token"].as_str().unwrap().to_string();
    let bob_token_id = bob_issued["result"]["record"]["tokenId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(bob_issued["result"]["record"]["scopes"], json!({}));
    assert!(bob_issued["result"]["record"]["expiresAt"].is_string());
    for (request_id, body) in [
        (
            "managed-admin-issue-invalid-ttl",
            r#"{"name":"bad ttl","tokenClass":"user_manage","ttl":"0d"}"#,
        ),
        (
            "managed-admin-issue-conflicting-expiry",
            r#"{"name":"bad expiry","tokenClass":"user_manage","ttl":"1d","expiresAt":"2999-01-01T00:00:00Z"}"#,
        ),
        (
            "managed-admin-issue-past-expiry",
            r#"{"name":"bad expiry","tokenClass":"user_manage","expiresAt":"2000-01-01T00:00:00Z"}"#,
        ),
        (
            "managed-admin-issue-invalid-ttl-seconds",
            r#"{"name":"bad ttl seconds","tokenClass":"user_manage","ttlSeconds":0}"#,
        ),
        (
            "managed-admin-issue-user-manage-never",
            r#"{"name":"bad never","tokenClass":"user_manage","never":true}"#,
        ),
    ] {
        let invalid_issue = authed_json_request(
            app.clone(),
            Method::POST,
            "/v1/admin/principals/bob/tokens",
            request_id,
            "Authorization",
            admin_authorization.clone(),
            Some(body),
        )
        .await;
        assert_eq!(invalid_issue.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(invalid_issue).await["reasonCode"],
            "input_invalid"
        );
    }
    let bob_inspect_alice_token = authed_json_request(
        app.clone(),
        Method::GET,
        format!("/v1/tokens/{self_agent_token_id}"),
        "managed-bob-inspect-alice-token",
        "Authorization",
        format!("Bearer {bob_token}"),
        None,
    )
    .await;
    assert_eq!(bob_inspect_alice_token.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(bob_inspect_alice_token).await["reasonCode"],
        "credential_not_found"
    );
    let bob_revoke_alice_token = authed_json_request(
        app.clone(),
        Method::DELETE,
        format!("/v1/tokens/{self_agent_token_id}"),
        "managed-bob-revoke-alice-token",
        "Authorization",
        format!("Bearer {bob_token}"),
        None,
    )
    .await;
    assert_eq!(bob_revoke_alice_token.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(bob_revoke_alice_token).await["reasonCode"],
        "credential_not_found"
    );
    let bob_pause_revoked_alice_token = authed_json_request(
        app.clone(),
        Method::POST,
        format!("/v1/tokens/{self_agent_token_id}/pause"),
        "managed-bob-pause-revoked-alice-token",
        "Authorization",
        format!("Bearer {bob_token}"),
        None,
    )
    .await;
    assert_eq!(
        bob_pause_revoked_alice_token.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        response_json(bob_pause_revoked_alice_token).await["reasonCode"],
        "credential_not_found"
    );
    let admin_pause_revoked_alice_as_bob = authed_json_request(
        app.clone(),
        Method::POST,
        format!("/v1/admin/principals/bob/agent-tokens/{self_agent_token_id}/pause"),
        "managed-admin-pause-revoked-alice-token-as-bob",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(
        admin_pause_revoked_alice_as_bob.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        response_json(admin_pause_revoked_alice_as_bob).await["reasonCode"],
        "broker_token_not_found"
    );
    let bob_inspect_own_user_manage = authed_json_request(
        app.clone(),
        Method::GET,
        format!("/v1/tokens/{bob_token_id}"),
        "managed-bob-inspect-own-user-manage",
        "Authorization",
        format!("Bearer {bob_token}"),
        None,
    )
    .await;
    assert_eq!(bob_inspect_own_user_manage.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(bob_inspect_own_user_manage).await["reasonCode"],
        "credential_not_found"
    );
    let bob_revoke_own_user_manage = authed_json_request(
        app.clone(),
        Method::DELETE,
        format!("/v1/tokens/{bob_token_id}"),
        "managed-bob-revoke-own-user-manage",
        "Authorization",
        format!("Bearer {bob_token}"),
        None,
    )
    .await;
    assert_eq!(bob_revoke_own_user_manage.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(bob_revoke_own_user_manage).await["reasonCode"],
        "credential_not_found"
    );
    let bob_pause_own_user_manage = authed_json_request(
        app.clone(),
        Method::POST,
        format!("/v1/tokens/{bob_token_id}/pause"),
        "managed-bob-pause-own-user-manage",
        "Authorization",
        format!("Bearer {bob_token}"),
        None,
    )
    .await;
    assert_eq!(bob_pause_own_user_manage.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(bob_pause_own_user_manage).await["reasonCode"],
        "credential_not_found"
    );
    let bob_write_missing_right = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/credentials/gitlab/default",
        "managed-bob-write-no-right",
        "Authorization",
        format!("Bearer {bob_token}"),
        Some(r#"{"profile":"gitlab-access-token","secret":{"token":"bob-token"},"metadata":{}}"#),
    )
    .await;
    assert_eq!(bob_write_missing_right.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(bob_write_missing_right).await["reasonCode"],
        "service_action_denied"
    );

    let add_bob_group = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/admin/principals/bob/groups/users",
        "managed-add-bob-group",
        "Authorization",
        admin_authorization.clone(),
        Some("{}"),
    )
    .await;
    assert_eq!(add_bob_group.status(), StatusCode::OK);

    let expired_right = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/rights",
        "managed-grant-expired-right",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"principalId":"bob","right":"credentials:self:write","service":"gitlab","credentialName":"default","expiresAt":"2000-01-01T00:00:00Z"}"#),
    )
    .await;
    assert_eq!(expired_right.status(), StatusCode::OK);
    let bob_write_expired_right = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/credentials/gitlab/default",
        "managed-bob-write-expired-right",
        "Authorization",
        format!("Bearer {bob_token}"),
        Some(r#"{"profile":"gitlab-access-token","secret":{"token":"bob-token"},"metadata":{}}"#),
    )
    .await;
    assert_eq!(bob_write_expired_right.status(), StatusCode::OK);

    let active_right = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/rights",
        "managed-grant-active-right",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"principalId":"bob","right":"credentials:self:write","service":"gitlab","credentialName":"default"}"#),
    )
    .await;
    assert_eq!(active_right.status(), StatusCode::OK);
    let right_id = response_json(active_right).await["result"]["rightId"]
        .as_str()
        .unwrap()
        .to_string();
    let bob_input_schema = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/credentials/gitlab/default/input-schema?profile=gitlab-access-token",
        "managed-bob-schema-with-right",
        "Authorization",
        format!("Bearer {bob_token}"),
        None,
    )
    .await;
    assert_eq!(bob_input_schema.status(), StatusCode::OK);
    let bob_schema_body = response_json(bob_input_schema).await;
    assert_eq!(bob_schema_body["result"]["profile"], "gitlab-access-token");
    assert_eq!(bob_schema_body["result"]["fields"][0]["name"], "token");
    let revoke_right = authed_json_request(
        app.clone(),
        Method::DELETE,
        format!("/v1/admin/rights/{right_id}"),
        "managed-revoke-active-right",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(revoke_right.status(), StatusCode::OK);
    let bob_write_revoked_right = authed_json_request(
        app.clone(),
        Method::PUT,
        "/v1/credentials/gitlab/default",
        "managed-bob-write-revoked-right",
        "Authorization",
        format!("Bearer {bob_token}"),
        Some(r#"{"profile":"gitlab-access-token","secret":{"token":"bob-token"},"metadata":{}}"#),
    )
    .await;
    assert_eq!(bob_write_revoked_right.status(), StatusCode::OK);

    let revoke_bob_token = authed_json_request(
        app.clone(),
        Method::DELETE,
        format!("/v1/admin/tokens/{bob_token_id}"),
        "managed-revoke-bob-token",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(revoke_bob_token.status(), StatusCode::OK);
    let revoked_token_use = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/credentials",
        "managed-revoked-token-use",
        "Authorization",
        format!("Bearer {bob_token}"),
        None,
    )
    .await;
    assert_eq!(revoked_token_use.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(revoked_token_use).await["reasonCode"],
        "broker_token_revoked"
    );

    let duplicate_alice = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals",
        "managed-duplicate-alice",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"principalId":"alice","kind":"user"}"#),
    )
    .await;
    assert_eq!(duplicate_alice.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(duplicate_alice).await["reasonCode"],
        "version_conflict"
    );
    let disable_alice = authed_json_request(
        app.clone(),
        Method::PATCH,
        "/v1/admin/principals/alice",
        "managed-disable-alice",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"status":"disabled"}"#),
    )
    .await;
    assert_eq!(disable_alice.status(), StatusCode::OK);
    let disabled_alice_token_issue = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals/alice/tokens",
        "managed-issue-disabled-alice-token",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"name":"disabled alice setup","tokenClass":"user_manage","ttl":"2h"}"#),
    )
    .await;
    assert_eq!(disabled_alice_token_issue.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(disabled_alice_token_issue).await["reasonCode"],
        "principal_disabled"
    );
    let recreate_disabled_alice = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/principals",
        "managed-recreate-disabled-alice",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"principalId":"alice","kind":"user"}"#),
    )
    .await;
    assert_eq!(recreate_disabled_alice.status(), StatusCode::CONFLICT);
    let disabled_principal_use = authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/credentials",
        "managed-disabled-principal-use",
        "Authorization",
        format!("Bearer {raw_token}"),
        None,
    )
    .await;
    assert_eq!(disabled_principal_use.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(disabled_principal_use).await["reasonCode"],
        "principal_disabled"
    );

    let audit = std::fs::read_to_string(audit_path).unwrap();
    assert!(audit.contains("\"service\":\"broker\""));
    assert!(audit.contains("\"action\":\"admin.credentials.put\""));
    assert!(audit.contains("\"action\":\"admin.tokens.issue\""));
    assert!(audit.contains("\"action\":\"tokens.issue\""));
    assert!(audit.contains("\"action\":\"tokens.pause\""));
    assert!(audit.contains("\"action\":\"tokens.resume\""));
    assert!(audit.contains("\"action\":\"admin.tokens.pause_principal_agent\""));
    assert!(audit.contains("\"action\":\"admin.tokens.resume_principal_agent\""));
    assert!(audit.contains("\"action\":\"admin.tokens.pause\""));
    assert!(audit.contains("\"action\":\"admin.tokens.resume\""));
    assert!(audit.contains("\"action\":\"credentials.list\""));
    assert!(audit.contains("\"phase\":\"preflight\""));
    assert!(audit.contains("\"phase\":\"success\""));
    assert!(audit.contains(&self_agent_token_id));
    assert!(audit.contains("\"tokenClass\":\"user_manage\""));
    assert!(!audit.contains("gitlab-token"));
    assert!(!audit.contains(&raw_token));
    assert!(!audit.contains(&raw_admin_token));
    assert!(!audit.contains(&bob_token));
    assert!(!audit.contains(&self_agent_token));
    assert!(!audit.contains("secretBackend"));
    assert!(!audit.contains("secretRef"));
    assert!(!audit.contains("materialVersion"));
    assert!(!audit.contains("secretCiphertext"));
    assert!(!audit.contains("secretNonce"));
}

#[tokio::test]
async fn retained_service_policy_assignment_is_inert_under_toml_policy_authority() {
    let fixture = service_policy_management_fixture_with_policy_authority("toml").await;

    let assignments = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/service-managers?service=fake",
        "toml-policy-retained-assignment-list",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        None,
    )
    .await;
    assert_eq!(assignments.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(assignments).await["reasonCode"],
        "input_invalid"
    );

    let policy_status = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/status",
        "toml-policy-retained-assignment-denied",
        "Authorization",
        format!("Bearer {}", fixture.bob_user_token),
        None,
    )
    .await;
    assert_eq!(policy_status.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(policy_status).await["reasonCode"],
        "management_denied"
    );

    let catalog = spec_get(
        fixture.app.clone(),
        "/v1/spec/catalog",
        "toml-policy-retained-assignment-catalog",
        Some(&fixture.bob_user_token),
    )
    .await;
    assert_eq!(catalog.status(), StatusCode::OK);
    let catalog = response_json(catalog).await;
    assert!(catalog["routes"].as_array().unwrap().iter().all(|route| {
        !route["route"]
            .as_str()
            .unwrap()
            .starts_with("/v1/admin/policy/")
    }));

    let openapi = spec_get(
        fixture.app.clone(),
        "/v1/spec/openapi.json",
        "toml-policy-retained-assignment-openapi",
        Some(&fixture.bob_user_token),
    )
    .await;
    assert_eq!(openapi.status(), StatusCode::OK);
    let openapi = response_json(openapi).await;
    assert!(
        openapi["paths"]
            .as_object()
            .unwrap()
            .keys()
            .all(|route| !route.starts_with("/v1/admin/policy/"))
    );

    let send_schema = spec_get(
        fixture.app,
        "/v1/spec/send-schema.json",
        "toml-policy-retained-assignment-send-schema",
        Some(&fixture.bob_user_token),
    )
    .await;
    assert_eq!(send_schema.status(), StatusCode::OK);
    let send_schema = response_json(send_schema).await;
    assert!(
        send_schema["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .all(|variant| !variant["properties"]["route"]["const"]
                .as_str()
                .unwrap()
                .starts_with("/v1/admin/policy/"))
    );
}

#[tokio::test]
async fn service_policy_manager_assignments_support_direct_accounts_and_idempotence() {
    let fixture = service_policy_management_fixture().await;
    let admin_authorization = format!("Bearer {}", fixture.admin_token);

    let dormant_list = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/service-managers?service=retired",
        "service-manager-list-dormant",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(dormant_list.status(), StatusCode::OK);
    let dormant_list = response_json(dormant_list).await;
    assert_eq!(dormant_list["result"].as_array().unwrap().len(), 1);
    assert_eq!(dormant_list["result"][0]["service"], "retired");
    assert_eq!(dormant_list["result"][0]["serviceConfigured"], false);

    let dormant_manager = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/status",
        "service-manager-dormant-denied",
        "Authorization",
        format!("Bearer {}", fixture.bob_user_token),
        None,
    )
    .await;
    assert_eq!(dormant_manager.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(dormant_manager).await["reasonCode"],
        "management_denied"
    );

    let grant_bob = authed_json_request(
        fixture.app.clone(),
        Method::PUT,
        "/v1/admin/policy/services/fake/managers/bob",
        "service-manager-grant-bob",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(grant_bob.status(), StatusCode::OK);
    let grant_bob = response_json(grant_bob).await;
    assert_eq!(grant_bob["result"]["service"], "fake");
    assert_eq!(grant_bob["result"]["serviceConfigured"], true);
    assert_eq!(grant_bob["result"]["principalId"], "bob");
    assert_eq!(grant_bob["result"]["principalStatus"], "active");
    let bob_assignment_id = grant_bob["result"]["assignmentId"]
        .as_str()
        .unwrap()
        .to_string();

    let grant_bob_again = authed_json_request(
        fixture.app.clone(),
        Method::PUT,
        "/v1/admin/policy/services/fake/managers/bob",
        "service-manager-grant-bob-again",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(grant_bob_again.status(), StatusCode::OK);
    assert_eq!(
        response_json(grant_bob_again).await["result"]["assignmentId"],
        bob_assignment_id
    );

    let obsolete_group = authed_json_request(
        fixture.app.clone(),
        Method::PUT,
        "/v1/admin/policy/services/gitlab_git/managers/group/service-managers",
        "obsolete-group-manager",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(obsolete_group.status(), StatusCode::NOT_FOUND);
    let ordinary_group_member = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/status",
        "ordinary-group-is-not-manager",
        "Authorization",
        format!("Bearer {}", fixture.alice_user_token),
        None,
    )
    .await;
    assert_eq!(ordinary_group_member.status(), StatusCode::FORBIDDEN);
    let designate = authed_json_request(
        fixture.app.clone(),
        Method::PATCH,
        "/v1/admin/principals/alice/access",
        "designate-alice-manager",
        "Authorization",
        admin_authorization.clone(),
        Some(r#"{"role":"service_policy_manager"}"#),
    )
    .await;
    assert_eq!(designate.status(), StatusCode::OK);
    let grant_alice = authed_json_request(
        fixture.app.clone(),
        Method::PUT,
        "/v1/admin/policy/services/gitlab_git/managers/alice",
        "direct-alice-manager",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(grant_alice.status(), StatusCode::OK);
    assert_eq!(
        response_json(grant_alice).await["result"]["principalId"],
        "alice"
    );

    let list = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/service-managers",
        "service-manager-list",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);
    let list = response_json(list).await;
    assert_eq!(list["result"].as_array().unwrap().len(), 3);

    let filtered_list = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/service-managers?service=fake",
        "service-manager-list-filtered",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(filtered_list.status(), StatusCode::OK);
    let filtered_list = response_json(filtered_list).await;
    assert_eq!(filtered_list["result"].as_array().unwrap().len(), 1);
    assert_eq!(filtered_list["result"][0]["service"], "fake");

    let bob_status = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/status",
        "service-manager-bob-status",
        "Authorization",
        format!("Bearer {}", fixture.bob_user_token),
        None,
    )
    .await;
    assert_eq!(bob_status.status(), StatusCode::OK);
    assert_eq!(
        response_json(bob_status).await["result"]["managementScope"],
        json!({"kind":"services","services":["fake"]})
    );

    let alice_catalog = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/catalog",
        "service-manager-alice-catalog",
        "Authorization",
        format!("Bearer {}", fixture.alice_user_token),
        None,
    )
    .await;
    assert_eq!(alice_catalog.status(), StatusCode::OK);
    let alice_catalog = response_json(alice_catalog).await;
    assert_eq!(
        alice_catalog["result"]["services"]
            .as_array()
            .unwrap()
            .iter()
            .map(|service| service["service"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["gitlab_git"]
    );

    let revoke_alice = authed_json_request(
        fixture.app.clone(),
        Method::DELETE,
        "/v1/admin/policy/services/gitlab_git/managers/alice",
        "service-manager-revoke-alice",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(revoke_alice.status(), StatusCode::OK);
    assert_eq!(response_json(revoke_alice).await["result"]["removed"], true);

    let revoke_alice_again = authed_json_request(
        fixture.app.clone(),
        Method::DELETE,
        "/v1/admin/policy/services/gitlab_git/managers/alice",
        "service-manager-revoke-alice-again",
        "Authorization",
        admin_authorization,
        None,
    )
    .await;
    assert_eq!(revoke_alice_again.status(), StatusCode::OK);
    assert_eq!(
        response_json(revoke_alice_again).await["result"]["removed"],
        false
    );

    let alice_after_revoke = authed_json_request(
        fixture.app,
        Method::GET,
        "/v1/admin/policy/status",
        "service-manager-alice-after-revoke",
        "Authorization",
        format!("Bearer {}", fixture.alice_user_token),
        None,
    )
    .await;
    assert_eq!(alice_after_revoke.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(alice_after_revoke).await["reasonCode"],
        "management_denied"
    );
}

#[tokio::test]
async fn scoped_service_policy_manager_is_confined_and_revocation_is_immediate() {
    let fixture = service_policy_management_fixture().await;
    let admin_authorization = format!("Bearer {}", fixture.admin_token);
    let bob_authorization = format!("Bearer {}", fixture.bob_user_token);

    let assignment = authed_json_request(
        fixture.app.clone(),
        Method::PUT,
        "/v1/admin/policy/services/fake/managers/bob",
        "scoped-policy-assign-bob",
        "Authorization",
        admin_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(assignment.status(), StatusCode::OK);

    let expected_policy_routes = [
        ("GET", "/v1/admin/policy/resources"),
        ("GET", "/v1/admin/policy/resources/{id}"),
        ("GET", "/v1/admin/policy/resource-groups"),
        ("GET", "/v1/admin/policy/resource-groups/{id}"),
        ("POST", "/v1/admin/policy/effective-access"),
        ("GET", "/v1/admin/policy/status"),
        ("GET", "/v1/admin/policy/catalog"),
        ("GET", "/v1/admin/policy/grants"),
        ("POST", "/v1/admin/policy/grants"),
        ("POST", "/v1/admin/policy/grants/validate"),
        ("GET", "/v1/admin/policy/grants/{grant_ref}"),
        ("PATCH", "/v1/admin/policy/grants/{grant_ref}"),
        ("DELETE", "/v1/admin/policy/grants/{grant_ref}"),
        ("POST", "/v1/admin/policy/grants/{grant_ref}/enable"),
        ("POST", "/v1/admin/policy/grants/{grant_ref}/disable"),
        ("POST", "/v1/admin/policy/grants/{grant_ref}/subjects"),
        (
            "POST",
            "/v1/admin/policy/grants/{grant_ref}/subjects/remove",
        ),
    ]
    .into_iter()
    .map(|(method, route)| format!("{method} {route}"))
    .collect::<std::collections::BTreeSet<_>>();

    let catalog = spec_get(
        fixture.app.clone(),
        "/v1/spec/catalog",
        "scoped-policy-spec-catalog",
        Some(&fixture.bob_user_token),
    )
    .await;
    assert_eq!(catalog.status(), StatusCode::OK);
    let catalog = response_json(catalog).await;
    let catalog_admin_routes = catalog["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|route| {
            let path = route["route"].as_str()?;
            path.starts_with("/v1/admin/")
                .then(|| format!("{} {path}", route["method"].as_str().unwrap()))
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(catalog_admin_routes, expected_policy_routes);
    assert!(!catalog_has_route(
        &catalog,
        "GET",
        "/v1/admin/policy/grants/export"
    ));
    assert!(!catalog_has_route(
        &catalog,
        "GET",
        "/v1/admin/policy/service-managers"
    ));
    assert!(!catalog_has_route(&catalog, "GET", "/v1/admin/principals"));

    let openapi = spec_get(
        fixture.app.clone(),
        "/v1/spec/openapi.json",
        "scoped-policy-spec-openapi",
        Some(&fixture.bob_user_token),
    )
    .await;
    assert_eq!(openapi.status(), StatusCode::OK);
    let openapi = response_json(openapi).await;
    let openapi_admin_routes = openapi["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(path, operations)| {
            operations
                .as_object()
                .unwrap()
                .keys()
                .filter(move |_| path.starts_with("/v1/admin/"))
                .map(move |method| format!("{} {path}", method.to_ascii_uppercase()))
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(openapi_admin_routes, expected_policy_routes);

    let send_schema = spec_get(
        fixture.app.clone(),
        "/v1/spec/send-schema.json",
        "scoped-policy-spec-send-schema",
        Some(&fixture.bob_user_token),
    )
    .await;
    assert_eq!(send_schema.status(), StatusCode::OK);
    let send_schema = response_json(send_schema).await;
    let send_admin_routes = send_schema["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|variant| {
            let path = variant["properties"]["route"]["const"].as_str()?;
            path.starts_with("/v1/admin/").then(|| {
                format!(
                    "{} {path}",
                    variant["properties"]["method"]["const"].as_str().unwrap()
                )
            })
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(send_admin_routes, expected_policy_routes);

    let visibility_all = spec_get(
        fixture.app.clone(),
        "/v1/spec/catalog?visibility=all",
        "scoped-policy-spec-visibility-all-denied",
        Some(&fixture.bob_user_token),
    )
    .await;
    assert_eq!(visibility_all.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(visibility_all).await["reasonCode"],
        "management_denied"
    );

    let other_service_grant = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants",
        "scoped-policy-admin-create-other",
        "Authorization",
        admin_authorization.clone(),
        Some(
            r#"{
                "subjects":["user:alice"],
                "executionContexts":["default"],
                "service":"gitlab_git",
                "actions":["repo.fetch"],
                "resources":{"resourceIds":["repository-sip-service"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(other_service_grant.status(), StatusCode::OK);
    let other_service_grant = response_json(other_service_grant).await;
    let other_grant_id = other_service_grant["result"]["grant"]["grantId"]
        .as_str()
        .unwrap()
        .to_string();

    let own_service_grant = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants",
        "scoped-policy-bob-create-own",
        "Authorization",
        bob_authorization.clone(),
        Some(
            r#"{
                "subjects":["user:bob"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(own_service_grant.status(), StatusCode::OK);
    let own_service_grant = response_json(own_service_grant).await;
    let own_grant_id = own_service_grant["result"]["grant"]["grantId"]
        .as_str()
        .unwrap()
        .to_string();

    let move_patch = authed_json_request(
        fixture.app.clone(),
        Method::PATCH,
        format!("/v1/admin/policy/grants/{own_grant_id}"),
        "scoped-policy-bob-move-patch",
        "Authorization",
        bob_authorization.clone(),
        Some(r#"{"expectedVersion":1,"service":"gitlab_git"}"#),
    )
    .await;
    assert_eq!(move_patch.status(), StatusCode::FORBIDDEN);
    let move_patch = response_json(move_patch).await;
    assert_eq!(move_patch["decision"], "deny");
    assert_eq!(move_patch["reasonCode"], "management_denied");
    assert!(move_patch["result"].is_null());

    let move_validate = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants/validate",
        "scoped-policy-bob-move-validate",
        "Authorization",
        bob_authorization.clone(),
        Some(&format!(
            r#"{{"grantId":"{own_grant_id}","expectedVersion":1,"service":"gitlab_git"}}"#
        )),
    )
    .await;
    assert_eq!(move_validate.status(), StatusCode::FORBIDDEN);
    let move_validate = response_json(move_validate).await;
    assert_eq!(move_validate["decision"], "deny");
    assert_eq!(move_validate["reasonCode"], "management_denied");
    assert!(move_validate["result"].is_null());

    let list = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/grants",
        "scoped-policy-bob-list",
        "Authorization",
        bob_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);
    let list = response_json(list).await;
    assert_eq!(list["result"].as_array().unwrap().len(), 1);
    assert_eq!(list["result"][0]["grantRef"], own_grant_id);
    assert_eq!(list["result"][0]["service"], "fake");

    let inspect_own = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        format!("/v1/admin/policy/grants/{own_grant_id}"),
        "scoped-policy-bob-inspect-own",
        "Authorization",
        bob_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(inspect_own.status(), StatusCode::OK);

    let inspect_other = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        format!("/v1/admin/policy/grants/{other_grant_id}"),
        "scoped-policy-bob-inspect-other",
        "Authorization",
        bob_authorization.clone(),
        None,
    )
    .await;
    assert_eq!(inspect_other.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(inspect_other).await["reasonCode"],
        "policy_grant_not_found"
    );

    let validate_other = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants/validate",
        "scoped-policy-bob-validate-other",
        "Authorization",
        bob_authorization.clone(),
        Some(&format!(
            r#"{{"grantId":"{other_grant_id}","expectedVersion":999,"description":"probe"}}"#
        )),
    )
    .await;
    assert_eq!(validate_other.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(validate_other).await["reasonCode"],
        "policy_grant_not_found"
    );

    let create_other = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants",
        "scoped-policy-bob-create-other",
        "Authorization",
        bob_authorization.clone(),
        Some(
            r#"{
                "subjects":["user:bob"],
                "executionContexts":["default"],
                "service":"gitlab_git",
                "actions":["repo.fetch"],
                "resources":{"resourceIds":["repository-sip-service"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(create_other.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(create_other).await["reasonCode"],
        "management_denied"
    );

    for (uri, request_id) in [
        (
            "/v1/admin/policy/grants/export",
            "scoped-policy-bob-export-denied",
        ),
        (
            "/v1/admin/policy/service-managers",
            "scoped-policy-bob-assignments-denied",
        ),
    ] {
        let denied = authed_json_request(
            fixture.app.clone(),
            Method::GET,
            uri,
            request_id,
            "Authorization",
            bob_authorization.clone(),
            None,
        )
        .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "{request_id}");
        assert_eq!(
            response_json(denied).await["reasonCode"],
            "broker_token_class_denied",
            "{request_id}"
        );
    }

    let revoke = authed_json_request(
        fixture.app.clone(),
        Method::DELETE,
        "/v1/admin/policy/services/fake/managers/bob",
        "scoped-policy-revoke-bob",
        "Authorization",
        admin_authorization,
        None,
    )
    .await;
    assert_eq!(revoke.status(), StatusCode::OK);
    assert_eq!(response_json(revoke).await["result"]["removed"], true);

    let next_request = authed_json_request(
        fixture.app,
        Method::GET,
        "/v1/admin/policy/status",
        "scoped-policy-bob-after-revoke",
        "Authorization",
        bob_authorization,
        None,
    )
    .await;
    assert_eq!(next_request.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(next_request).await["reasonCode"],
        "management_denied"
    );
}

#[tokio::test]
async fn admin_policy_managed_grants_crud_validate_and_export() {
    let fixture = managed_policy_admin_fixture().await;
    let authorization = format!("Bearer {}", fixture.admin_token);

    let status = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/status",
        "managed-policy-status",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(status.status(), StatusCode::OK);
    let status_body = response_json(status).await;
    assert_eq!(status_body["result"]["policyAuthority"], "managed");
    assert_eq!(status_body["result"]["writable"], true);
    assert_eq!(status_body["result"]["counts"]["active"], 0);

    let catalog = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/catalog",
        "managed-policy-catalog",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(catalog.status(), StatusCode::OK);
    let catalog_body = response_json(catalog).await;
    assert!(
        catalog_body["result"]["services"]
            .as_array()
            .unwrap()
            .iter()
            .any(|service| service["service"] == "fake"
                && service["configuredCredentialModes"] == json!(["service"]))
    );
    let fake_service = catalog_body["result"]["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "fake")
        .unwrap();
    assert_eq!(fake_service["actions"][0]["lookupRequired"], false);
    assert_eq!(fake_service["actions"][0]["readOnly"], true);
    assert_eq!(
        fake_service["resourceScopes"]["project"],
        json!({"resourceType": "fake_project", "selectors": ["exact", "all"]})
    );
    assert!(
        catalog_body["result"]["subjects"]["groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|group| group["groupId"] == "agents")
    );
    assert_eq!(
        catalog_body["result"]["executionContexts"],
        json!({
            "allowedValues": ["default"],
            "defaultContext": "default",
            "contextRequired": false
        })
    );

    let missing_contexts_validate = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants/validate",
        "managed-policy-validate-missing-contexts",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{
                "subjects":["group:agents"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(missing_contexts_validate.status(), StatusCode::OK);
    let missing_contexts_body = response_json(missing_contexts_validate).await;
    assert_eq!(missing_contexts_body["result"]["valid"], false);
    assert_eq!(
        missing_contexts_body["result"]["errors"][0]["field"],
        "executionContexts"
    );
    assert_eq!(
        missing_contexts_body["result"]["errors"][0]["code"],
        "required"
    );

    let create = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants",
        "managed-policy-create",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{
                "subjects":["group:agents","user:admin"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                "credentialMode":"service",
                "priority":10,
                "description":"Test access"
            }"#,
        ),
    )
    .await;
    assert_eq!(create.status(), StatusCode::OK);
    let create_body = response_json(create).await;
    let grant_id = create_body["result"]["grant"]["grantId"]
        .as_str()
        .unwrap()
        .to_string();
    uuid::Uuid::parse_str(&grant_id).unwrap();
    assert_eq!(
        create_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 1
    );
    assert_eq!(create_body["result"]["grant"]["status"], "active");
    assert_eq!(
        create_body["result"]["grant"]["subjects"],
        json!(["group:agents", "user:admin"])
    );
    assert_eq!(
        create_body["result"]["grant"]["executionContexts"],
        json!(["default"])
    );

    let duplicate_validate = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants/validate",
        "managed-policy-validate-duplicate-id",
        "Authorization",
        authorization.clone(),
        Some(&format!(
            r#"{{
                "grantId":"{grant_id}",
                "subjects":["group:agents"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{{"resourceIds":["project-test"],"resourceGroupIds":[]}},
                "credentialMode":"service"
            }}"#
        )),
    )
    .await;
    assert_eq!(duplicate_validate.status(), StatusCode::OK);
    let duplicate_validate_body = response_json(duplicate_validate).await;
    assert_eq!(duplicate_validate_body["result"]["valid"], false);
    assert_eq!(
        duplicate_validate_body["result"]["errors"][0]["field"],
        "grantId"
    );
    assert_eq!(
        duplicate_validate_body["result"]["errors"][0]["code"],
        "grant_id_duplicate"
    );

    for (grant_id, request_id) in [
        ("export", "managed-policy-validate-reserved-export-id"),
        (".", "managed-policy-validate-dot-id"),
    ] {
        let invalid_grant_id_validate = authed_json_request(
            fixture.app.clone(),
            Method::POST,
            "/v1/admin/policy/grants/validate",
            request_id,
            "Authorization",
            authorization.clone(),
            Some(&format!(
                r#"{{
                    "grantId":"{grant_id}",
                    "subjects":["group:agents"],
                    "executionContexts":["default"],
                    "service":"fake",
                    "actions":["echo"],
                    "resources":{{"resourceIds":["project-test"],"resourceGroupIds":[]}},
                    "credentialMode":"service"
                }}"#
            )),
        )
        .await;
        assert_eq!(invalid_grant_id_validate.status(), StatusCode::OK);
        let invalid_grant_id_validate_body = response_json(invalid_grant_id_validate).await;
        assert_eq!(invalid_grant_id_validate_body["result"]["valid"], false);
        assert_eq!(
            invalid_grant_id_validate_body["result"]["errors"][0]["field"],
            "grantId"
        );
        assert_eq!(
            invalid_grant_id_validate_body["result"]["errors"][0]["code"],
            "grant_id_invalid"
        );
    }

    let duplicate_grant_validate = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants/validate",
        "managed-policy-validate-duplicate-grant",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{
                "subjects":["group:agents"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                "credentialMode":"service",
                "priority":10
            }"#,
        ),
    )
    .await;
    assert_eq!(duplicate_grant_validate.status(), StatusCode::OK);
    let duplicate_grant_validate_body = response_json(duplicate_grant_validate).await;
    assert_eq!(duplicate_grant_validate_body["result"]["valid"], false);
    assert!(
        duplicate_grant_validate_body["result"]["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error["field"] == "subjects[0]" && error["code"] == "grant_duplicate")
    );

    let list = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/grants?subject=group%3Aagents&service=fake&status=active",
        "managed-policy-list",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);
    let list_body = response_json(list).await;
    assert_eq!(list_body["result"].as_array().unwrap().len(), 1);
    assert_eq!(list_body["result"][0]["grantRef"], grant_id);
    assert_eq!(list_body["result"][0]["writable"], true);
    assert_eq!(
        list_body["result"][0]["subjects"],
        json!(["group:agents", "user:admin"])
    );
    assert_eq!(
        list_body["result"][0]["executionContexts"],
        json!(["default"])
    );

    let blind_patch = authed_json_request(
        fixture.app.clone(),
        Method::PATCH,
        format!("/v1/admin/policy/grants/{grant_id}"),
        "managed-policy-blind-patch",
        "Authorization",
        authorization.clone(),
        Some(r#"{"description":"Blind update"}"#),
    )
    .await;
    assert_eq!(blind_patch.status(), StatusCode::BAD_REQUEST);
    let blind_patch_body = response_json(blind_patch).await;
    assert_eq!(blind_patch_body["reasonCode"], "input_invalid");

    let singular_subject_create = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants",
        "managed-policy-create-singular-subject",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{
                "subject":"group:agents",
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(singular_subject_create.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(singular_subject_create).await["reasonCode"],
        "input_invalid"
    );

    let singular_subject_patch = authed_json_request(
        fixture.app.clone(),
        Method::PATCH,
        format!("/v1/admin/policy/grants/{grant_id}"),
        "managed-policy-patch-singular-subject",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":1,"subject":"group:agents"}"#),
    )
    .await;
    assert_eq!(singular_subject_patch.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(singular_subject_patch).await["reasonCode"],
        "input_invalid"
    );

    let singular_subject_validate = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants/validate",
        "managed-policy-validate-singular-subject",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{
                "subject":"group:agents",
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(singular_subject_validate.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(singular_subject_validate).await["reasonCode"],
        "input_invalid"
    );

    let patch = authed_json_request(
        fixture.app.clone(),
        Method::PATCH,
        format!("/v1/admin/policy/grants/{grant_id}"),
        "managed-policy-patch",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":1,"priority":null,"description":"Updated"}"#),
    )
    .await;
    assert_eq!(patch.status(), StatusCode::OK);
    let patch_body = response_json(patch).await;
    assert_eq!(
        patch_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 2
    );
    assert!(patch_body["result"]["grant"]["priority"].is_null());
    assert_eq!(patch_body["result"]["grant"]["version"], 2);
    assert_eq!(
        patch_body["result"]["grant"]["subjects"],
        json!(["group:agents", "user:admin"])
    );

    let subjects_patch = authed_json_request(
        fixture.app.clone(),
        Method::PATCH,
        format!("/v1/admin/policy/grants/{grant_id}"),
        "managed-policy-patch-subjects",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":2,"subjects":["user:admin","group:agents"]}"#),
    )
    .await;
    assert_eq!(subjects_patch.status(), StatusCode::OK);
    let subjects_patch_body = response_json(subjects_patch).await;
    assert_eq!(
        subjects_patch_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 3
    );
    assert_eq!(subjects_patch_body["result"]["grant"]["version"], 3);
    assert_eq!(
        subjects_patch_body["result"]["grant"]["subjects"],
        json!(["user:admin", "group:agents"])
    );
    assert_eq!(
        subjects_patch_body["result"]["grant"]["description"],
        "Updated"
    );
    assert!(subjects_patch_body["result"]["grant"]["priority"].is_null());

    let empty_subjects_patch = authed_json_request(
        fixture.app.clone(),
        Method::PATCH,
        format!("/v1/admin/policy/grants/{grant_id}"),
        "managed-policy-patch-empty-subjects",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":3,"subjects":[]}"#),
    )
    .await;
    assert_eq!(empty_subjects_patch.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(empty_subjects_patch).await["reasonCode"],
        "policy_validation_failed"
    );

    let inspect_after_empty_subjects_patch = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        format!("/v1/admin/policy/grants/{grant_id}"),
        "managed-policy-inspect-after-empty-subjects-patch",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(inspect_after_empty_subjects_patch.status(), StatusCode::OK);
    let inspect_after_empty_subjects_patch_body =
        response_json(inspect_after_empty_subjects_patch).await;
    assert_eq!(
        inspect_after_empty_subjects_patch_body["result"]["version"],
        3
    );
    assert_eq!(
        inspect_after_empty_subjects_patch_body["result"]["subjects"],
        json!(["user:admin", "group:agents"])
    );

    let status_after_empty_subjects_patch = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/status",
        "managed-policy-status-after-empty-subjects-patch",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(status_after_empty_subjects_patch.status(), StatusCode::OK);
    let status_after_empty_subjects_patch_body =
        response_json(status_after_empty_subjects_patch).await;
    assert_eq!(
        status_after_empty_subjects_patch_body["result"]["policyGeneration"],
        seeded_resource_generation() + 3
    );
    assert_eq!(
        status_after_empty_subjects_patch_body["result"]["counts"]["active"],
        1
    );

    let invalid_validate = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants/validate",
        "managed-policy-validate-invalid",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{
                "subjects":["group:missing"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(invalid_validate.status(), StatusCode::OK);
    let invalid_validate_body = response_json(invalid_validate).await;
    assert_eq!(invalid_validate_body["result"]["valid"], false);
    assert_eq!(
        invalid_validate_body["result"]["errors"][0]["field"],
        "subjects[0]"
    );
    assert_eq!(
        invalid_validate_body["result"]["errors"][0]["code"],
        "subject_not_found"
    );

    let duplicate_subject_validate = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants/validate",
        "managed-policy-validate-duplicate-subject",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{
                "subjects":["group:agents","group:agents"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(duplicate_subject_validate.status(), StatusCode::OK);
    let duplicate_subject_validate_body = response_json(duplicate_subject_validate).await;
    assert_eq!(duplicate_subject_validate_body["result"]["valid"], false);
    assert!(
        duplicate_subject_validate_body["result"]["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error["field"] == "subjects[1]" && error["code"] == "subject_duplicate")
    );

    let invalid_action_validate = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants/validate",
        "managed-policy-validate-invalid-action",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{
                "subjects":["group:agents"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["missing"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(invalid_action_validate.status(), StatusCode::OK);
    let invalid_action_validate_body = response_json(invalid_action_validate).await;
    assert_eq!(invalid_action_validate_body["result"]["valid"], false);
    assert!(
        invalid_action_validate_body["result"]["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error["field"] == "actions" && error["code"] == "action_unknown")
    );

    let empty_selection_validate = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants/validate",
        "managed-policy-validate-empty-selection",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{
                "subjects":["group:agents"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":[],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(empty_selection_validate.status(), StatusCode::OK);
    let empty_selection_validate_body = response_json(empty_selection_validate).await;
    assert_eq!(empty_selection_validate_body["result"]["valid"], true);

    let unconfigured_credential_validate = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants/validate",
        "managed-policy-validate-unconfigured-credential",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{
                "subjects":["group:agents"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                "credentialMode":"per_user"
            }"#,
        ),
    )
    .await;
    assert_eq!(unconfigured_credential_validate.status(), StatusCode::OK);
    let unconfigured_credential_validate_body =
        response_json(unconfigured_credential_validate).await;
    assert_eq!(
        unconfigured_credential_validate_body["result"]["valid"],
        false
    );
    assert!(
        unconfigured_credential_validate_body["result"]["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error["field"] == "credentialMode"
                && error["code"] == "credential_mode_unconfigured")
    );

    let disabled_invalid = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants",
        "managed-policy-create-disabled-invalid",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{
                "subjects":["group:agents"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["missing"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                "credentialMode":"service",
                "status":"disabled"
            }"#,
        ),
    )
    .await;
    assert_eq!(disabled_invalid.status(), StatusCode::BAD_REQUEST);
    let disabled_invalid_body = response_json(disabled_invalid).await;
    assert_eq!(
        disabled_invalid_body["reasonCode"],
        "policy_validation_failed"
    );

    let blind_disable = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{grant_id}/disable"),
        "managed-policy-blind-disable",
        "Authorization",
        authorization.clone(),
        Some(r#"{}"#),
    )
    .await;
    assert_eq!(blind_disable.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(blind_disable).await["reasonCode"],
        "input_invalid"
    );

    let disable = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{grant_id}/disable"),
        "managed-policy-disable",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":3}"#),
    )
    .await;
    assert_eq!(disable.status(), StatusCode::OK);
    let disable_body = response_json(disable).await;
    assert_eq!(disable_body["result"]["grant"]["status"], "disabled");
    assert_eq!(
        disable_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 4
    );

    let enable = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{grant_id}/enable"),
        "managed-policy-enable",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":4}"#),
    )
    .await;
    assert_eq!(enable.status(), StatusCode::OK);
    let enable_body = response_json(enable).await;
    assert_eq!(enable_body["result"]["grant"]["status"], "active");
    assert_eq!(
        enable_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 5
    );

    let group_detail = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/groups/agents",
        "managed-policy-group-detail",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(group_detail.status(), StatusCode::OK);
    let group_detail_body = response_json(group_detail).await;
    let policy_reference_sections = group_detail_body["result"]["policyReferenceSections"]
        .as_array()
        .unwrap();
    assert_eq!(policy_reference_sections.len(), 1);
    assert_eq!(policy_reference_sections[0]["kind"], "direct_group");
    assert_eq!(policy_reference_sections[0]["subject"], "group:agents");
    assert_eq!(policy_reference_sections[0]["subjectRuntimeEligible"], true);
    let policy_references = policy_reference_sections[0]["references"]
        .as_array()
        .unwrap();
    assert_eq!(policy_references.len(), 1);
    assert_eq!(policy_references[0]["grantRef"], grant_id);
    assert_eq!(policy_references[0]["status"], "active");
    assert_eq!(policy_references[0]["writable"], true);
    assert_eq!(
        policy_references[0]["subjects"],
        json!(["user:admin", "group:agents"])
    );
    assert_eq!(
        policy_references[0]["executionContexts"],
        json!(["default"])
    );
    assert_eq!(policy_references[0]["description"], "Updated");

    let blind_delete = authed_json_request(
        fixture.app.clone(),
        Method::DELETE,
        format!("/v1/admin/policy/grants/{grant_id}"),
        "managed-policy-blind-delete",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(blind_delete.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(blind_delete).await["reasonCode"],
        "input_invalid"
    );

    let delete = authed_json_request(
        fixture.app.clone(),
        Method::DELETE,
        format!("/v1/admin/policy/grants/{grant_id}?expectedVersion=5"),
        "managed-policy-delete",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(delete.status(), StatusCode::OK);
    let delete_body = response_json(delete).await;
    assert_eq!(delete_body["result"]["grant"]["status"], "deleted");
    assert_eq!(
        delete_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 6
    );

    let default_list_after_delete = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/grants",
        "managed-policy-list-after-delete",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(default_list_after_delete.status(), StatusCode::OK);
    assert!(
        response_json(default_list_after_delete).await["result"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let deleted_list = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/grants?status=deleted",
        "managed-policy-list-deleted",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(deleted_list.status(), StatusCode::OK);
    let deleted_list_body = response_json(deleted_list).await;
    assert_eq!(deleted_list_body["result"].as_array().unwrap().len(), 1);
    assert_eq!(deleted_list_body["result"][0]["grantRef"], grant_id);
    assert_eq!(deleted_list_body["result"][0]["writable"], false);

    let deleted_group_detail = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/groups/agents",
        "managed-policy-group-detail-deleted",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(deleted_group_detail.status(), StatusCode::OK);
    assert_eq!(
        response_json(deleted_group_detail).await["result"]["policyReferenceSections"][0]
            ["references"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    let slug_grant_id = "fake-agents-slug";
    let slug_create = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants",
        "managed-policy-create-slug",
        "Authorization",
        authorization.clone(),
        Some(&format!(
            r#"{{
                "grantId":"{slug_grant_id}",
                "subjects":["group:agents"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{{"resourceIds":["project-slug"],"resourceGroupIds":[]}},
                "credentialMode":"service",
                "status":"disabled",
                "description":"Slug access"
            }}"#
        )),
    )
    .await;
    assert_eq!(slug_create.status(), StatusCode::OK);
    let slug_create_body = response_json(slug_create).await;
    assert_eq!(
        slug_create_body["result"]["grant"]["grantId"],
        slug_grant_id
    );
    assert_eq!(slug_create_body["result"]["grant"]["status"], "disabled");
    assert_eq!(
        slug_create_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 7
    );

    let slug_inspect = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        format!("/v1/admin/policy/grants/{slug_grant_id}"),
        "managed-policy-inspect-slug",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(slug_inspect.status(), StatusCode::OK);
    let slug_inspect_body = response_json(slug_inspect).await;
    assert_eq!(slug_inspect_body["result"]["grantRef"], slug_grant_id);

    let slug_patch = authed_json_request(
        fixture.app.clone(),
        Method::PATCH,
        format!("/v1/admin/policy/grants/{slug_grant_id}"),
        "managed-policy-patch-slug",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":1,"priority":30,"description":"Slug updated"}"#),
    )
    .await;
    assert_eq!(slug_patch.status(), StatusCode::OK);
    let slug_patch_body = response_json(slug_patch).await;
    assert_eq!(slug_patch_body["result"]["grant"]["version"], 2);
    assert_eq!(slug_patch_body["result"]["grant"]["priority"], 30);
    assert_eq!(
        slug_patch_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 8
    );

    let slug_enable = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{slug_grant_id}/enable"),
        "managed-policy-enable-slug",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":2}"#),
    )
    .await;
    assert_eq!(slug_enable.status(), StatusCode::OK);
    let slug_enable_body = response_json(slug_enable).await;
    assert_eq!(slug_enable_body["result"]["grant"]["status"], "active");
    assert_eq!(
        slug_enable_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 9
    );

    let slug_disable = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{slug_grant_id}/disable"),
        "managed-policy-disable-slug",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":3}"#),
    )
    .await;
    assert_eq!(slug_disable.status(), StatusCode::OK);
    let slug_disable_body = response_json(slug_disable).await;
    assert_eq!(slug_disable_body["result"]["grant"]["status"], "disabled");
    assert_eq!(
        slug_disable_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 10
    );

    let slug_delete = authed_json_request(
        fixture.app.clone(),
        Method::DELETE,
        format!("/v1/admin/policy/grants/{slug_grant_id}?expectedVersion=4"),
        "managed-policy-delete-slug",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(slug_delete.status(), StatusCode::OK);
    let slug_delete_body = response_json(slug_delete).await;
    assert_eq!(slug_delete_body["result"]["grant"]["status"], "deleted");
    assert_eq!(
        slug_delete_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 11
    );

    let export = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/policy/grants/export",
        "managed-policy-export",
        "Authorization",
        authorization,
        None,
    )
    .await;
    assert_eq!(export.status(), StatusCode::OK);
    let export_body = response_json(export).await;
    assert_eq!(
        export_body["result"]["policyGeneration"],
        seeded_resource_generation() + 11
    );
    let exported_grants = export_body["result"]["grants"].as_array().unwrap();
    assert_eq!(exported_grants.len(), 2);
    let exported_primary_grant = exported_grants
        .iter()
        .find(|grant| grant["grantId"] == grant_id)
        .unwrap();
    assert_eq!(
        exported_primary_grant["subjects"],
        json!(["user:admin", "group:agents"])
    );
    assert_eq!(
        exported_primary_grant["executionContexts"],
        json!(["default"])
    );
}

#[tokio::test]
async fn admin_policy_subjectless_disabled_grants_keep_active_invariant() {
    let fixture = managed_policy_admin_fixture().await;
    let authorization = format!("Bearer {}", fixture.admin_token);
    let grant_id = "fake-disabled-subjectless";

    let validate_active_subjectless = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants/validate",
        "managed-policy-validate-active-subjectless",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{
                "subjects":[],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-empty"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(validate_active_subjectless.status(), StatusCode::OK);
    let validate_body = response_json(validate_active_subjectless).await;
    assert_eq!(validate_body["result"]["valid"], false);
    assert_eq!(validate_body["result"]["errors"][0]["field"], "subjects");
    assert_eq!(validate_body["result"]["errors"][0]["code"], "empty");

    let create_active_subjectless = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants",
        "managed-policy-create-active-subjectless",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{
                "grantId":"fake-active-subjectless",
                "subjects":[],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-empty"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(create_active_subjectless.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(create_active_subjectless).await["reasonCode"],
        "policy_validation_failed"
    );

    let create_disabled_subjectless = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants",
        "managed-policy-create-disabled-subjectless",
        "Authorization",
        authorization.clone(),
        Some(&format!(
            r#"{{
                "grantId":"{grant_id}",
                "subjects":[],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{{"resourceIds":["project-empty"],"resourceGroupIds":[]}},
                "credentialMode":"service",
                "status":"disabled"
            }}"#
        )),
    )
    .await;
    assert_eq!(create_disabled_subjectless.status(), StatusCode::OK);
    let create_disabled_body = response_json(create_disabled_subjectless).await;
    assert_eq!(
        create_disabled_body["result"]["grant"]["status"],
        "disabled"
    );
    assert_eq!(
        create_disabled_body["result"]["grant"]["subjects"],
        json!([])
    );
    assert_eq!(
        create_disabled_body["result"]["grant"]["executionContexts"],
        json!(["default"])
    );
    assert_eq!(create_disabled_body["result"]["grant"]["version"], 1);

    let enable_subjectless = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{grant_id}/enable"),
        "managed-policy-enable-subjectless",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":1}"#),
    )
    .await;
    assert_eq!(enable_subjectless.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(enable_subjectless).await["reasonCode"],
        "policy_validation_failed"
    );

    let inspect = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        format!("/v1/admin/policy/grants/{grant_id}"),
        "managed-policy-inspect-subjectless-after-enable-reject",
        "Authorization",
        authorization,
        None,
    )
    .await;
    assert_eq!(inspect.status(), StatusCode::OK);
    let inspect_body = response_json(inspect).await;
    assert_eq!(inspect_body["result"]["status"], "disabled");
    assert_eq!(inspect_body["result"]["subjects"], json!([]));
    assert_eq!(inspect_body["result"]["version"], 1);
}

#[tokio::test]
async fn admin_policy_grant_subject_entrypoints_and_reference_sections() {
    let fixture = managed_policy_admin_fixture().await;
    let authorization = format!("Bearer {}", fixture.admin_token);
    let grant_id = "fake-admin-entrypoints";

    let create = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/policy/grants",
        "managed-policy-subject-create",
        "Authorization",
        authorization.clone(),
        Some(&format!(
            r#"{{
                "grantId":"{grant_id}",
                "subjects":["user:admin"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{{"resourceIds":["project-subjects"],"resourceGroupIds":[]}},
                "credentialMode":"service"
            }}"#
        )),
    )
    .await;
    assert_eq!(create.status(), StatusCode::OK);
    let create_body = response_json(create).await;
    assert_eq!(
        create_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 1
    );
    assert_eq!(create_body["result"]["grant"]["version"], 1);

    let add_group = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{grant_id}/subjects"),
        "managed-policy-subject-add-group",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":1,"subject":"group:agents"}"#),
    )
    .await;
    assert_eq!(add_group.status(), StatusCode::OK);
    let add_group_body = response_json(add_group).await;
    assert_eq!(
        add_group_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 2
    );
    assert_eq!(add_group_body["result"]["grant"]["version"], 2);
    assert_eq!(
        add_group_body["result"]["grant"]["subjects"],
        json!(["user:admin", "group:agents"])
    );

    let duplicate_group = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{grant_id}/subjects"),
        "managed-policy-subject-add-duplicate",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":2,"subject":"group:agents"}"#),
    )
    .await;
    assert_eq!(duplicate_group.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(duplicate_group).await["reasonCode"],
        "input_invalid"
    );

    let remove_group = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{grant_id}/subjects/remove"),
        "managed-policy-subject-remove-group",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":2,"subject":"group:agents"}"#),
    )
    .await;
    assert_eq!(remove_group.status(), StatusCode::OK);
    let remove_group_body = response_json(remove_group).await;
    assert_eq!(
        remove_group_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 3
    );
    assert_eq!(remove_group_body["result"]["grant"]["version"], 3);
    assert_eq!(
        remove_group_body["result"]["grant"]["subjects"],
        json!(["user:admin"])
    );

    let reject_final_subject = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{grant_id}/subjects/remove"),
        "managed-policy-subject-remove-final-reject",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":3,"subject":"user:admin"}"#),
    )
    .await;
    assert_eq!(reject_final_subject.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(reject_final_subject).await["reasonCode"],
        "policy_validation_failed"
    );

    let inspect_after_reject = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        format!("/v1/admin/policy/grants/{grant_id}"),
        "managed-policy-subject-inspect-after-reject",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(inspect_after_reject.status(), StatusCode::OK);
    let inspect_after_reject_body = response_json(inspect_after_reject).await;
    assert_eq!(inspect_after_reject_body["result"]["version"], 3);
    assert_eq!(
        inspect_after_reject_body["result"]["subjects"],
        json!(["user:admin"])
    );

    let remove_final_subject = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{grant_id}/subjects/remove"),
        "managed-policy-subject-remove-final-disable",
        "Authorization",
        authorization.clone(),
        Some(
            r#"{"expectedVersion":3,"subject":"user:admin","lastSubjectBehavior":"disable_grant"}"#,
        ),
    )
    .await;
    assert_eq!(remove_final_subject.status(), StatusCode::OK);
    let remove_final_subject_body = response_json(remove_final_subject).await;
    assert_eq!(
        remove_final_subject_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 4
    );
    assert_eq!(remove_final_subject_body["result"]["grant"]["version"], 4);
    assert_eq!(
        remove_final_subject_body["result"]["grant"]["status"],
        "disabled"
    );
    assert_eq!(
        remove_final_subject_body["result"]["grant"]["subjects"],
        json!([])
    );

    let add_group_to_disabled = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{grant_id}/subjects"),
        "managed-policy-subject-add-group-to-disabled",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":4,"subject":"group:agents"}"#),
    )
    .await;
    assert_eq!(add_group_to_disabled.status(), StatusCode::OK);
    let add_group_to_disabled_body = response_json(add_group_to_disabled).await;
    assert_eq!(
        add_group_to_disabled_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 5
    );
    assert_eq!(add_group_to_disabled_body["result"]["grant"]["version"], 5);
    assert_eq!(
        add_group_to_disabled_body["result"]["grant"]["status"],
        "disabled"
    );
    assert_eq!(
        add_group_to_disabled_body["result"]["grant"]["subjects"],
        json!(["group:agents"])
    );

    let enable = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        format!("/v1/admin/policy/grants/{grant_id}/enable"),
        "managed-policy-subject-enable",
        "Authorization",
        authorization.clone(),
        Some(r#"{"expectedVersion":5}"#),
    )
    .await;
    assert_eq!(enable.status(), StatusCode::OK);
    let enable_body = response_json(enable).await;
    assert_eq!(
        enable_body["result"]["revision"]["generation"],
        seeded_resource_generation() + 6
    );
    assert_eq!(enable_body["result"]["grant"]["version"], 6);
    assert_eq!(enable_body["result"]["grant"]["status"], "active");

    let principal_detail = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/principals/admin",
        "managed-policy-subject-principal-detail",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(principal_detail.status(), StatusCode::OK);
    let principal_detail_body = response_json(principal_detail).await;
    assert_eq!(
        principal_detail_body["result"]["activePolicyGroupSubjects"],
        json!(["group:agents"])
    );
    let principal_sections = principal_detail_body["result"]["policyReferenceSections"]
        .as_array()
        .unwrap();
    assert_eq!(principal_sections.len(), 2);
    assert_eq!(principal_sections[0]["kind"], "direct_user");
    assert_eq!(
        principal_sections[0]["references"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(principal_sections[1]["kind"], "group_derived");
    assert!(principal_sections[1].get("subject").is_none());
    assert_eq!(principal_sections[1]["subjectRuntimeEligible"], true);
    let derived_references = principal_sections[1]["references"].as_array().unwrap();
    assert_eq!(derived_references.len(), 1);
    assert_eq!(derived_references[0]["grantRef"], grant_id);
    assert_eq!(
        derived_references[0]["derivedViaSubjects"],
        json!(["group:agents"])
    );
    assert_eq!(derived_references[0]["derivedViaGroups"], json!(["agents"]));

    let no_groups_detail = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/principals/nogroups",
        "managed-policy-subject-principal-detail-no-groups",
        "Authorization",
        authorization.clone(),
        None,
    )
    .await;
    assert_eq!(no_groups_detail.status(), StatusCode::OK);
    let no_groups_detail_body = response_json(no_groups_detail).await;
    assert_eq!(
        no_groups_detail_body["result"]["activePolicyGroupSubjects"],
        json!([])
    );
    let no_groups_sections = no_groups_detail_body["result"]["policyReferenceSections"]
        .as_array()
        .unwrap();
    assert_eq!(no_groups_sections[1]["kind"], "group_derived");
    assert!(no_groups_sections[1].get("subject").is_none());
    assert_eq!(no_groups_sections[1]["subjectRuntimeEligible"], false);
    assert_eq!(
        no_groups_sections[1]["runtimeIneligibleReason"],
        "not_applicable"
    );
    assert_eq!(
        no_groups_sections[1]["references"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    let group_detail = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/groups/agents",
        "managed-policy-subject-group-detail",
        "Authorization",
        authorization,
        None,
    )
    .await;
    assert_eq!(group_detail.status(), StatusCode::OK);
    let group_detail_body = response_json(group_detail).await;
    let group_sections = group_detail_body["result"]["policyReferenceSections"]
        .as_array()
        .unwrap();
    assert_eq!(group_sections.len(), 1);
    assert_eq!(group_sections[0]["kind"], "direct_group");
    let group_references = group_sections[0]["references"].as_array().unwrap();
    assert_eq!(group_references.len(), 1);
    assert_eq!(group_references[0]["grantRef"], grant_id);
}

#[tokio::test]
async fn admin_policy_toml_grants_are_read_only() {
    let admin_token = temp_path("toml-policy-admin-token");
    let audit_path = temp_path("toml-policy-admin.audit.jsonl");
    std::fs::write(&admin_token, "admin-token").unwrap();
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "admin".to_string(),
            kind: "static_principals".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![StaticPrincipalConfig {
                principal: "admin".to_string(),
                token_refs: vec![format!("file:{}", admin_token.display())],
            }],
        }],
        groups: vec![],
    };
    config.management = agent_access_core::ManagementConfig {
        enabled: true,
        admin_principals: vec!["admin".to_string()],
        allow_classless_admin_identities: true,
        initial_admin: agent_access_core::InitialAdminConfig::default(),
        ..agent_access_core::ManagementConfig::default()
    };
    config
        .policy
        .resource_groups
        .push(agent_access_core::ResourceGroupDefinition {
            id: "toml-resources".to_string(),
            name: "TOML resources".to_string(),
            included_resource_ids: vec!["project-test".to_string()],
            excluded_resource_ids: vec![],
        });
    config.policy.grants[0]
        .resources
        .resource_group_ids
        .push("toml-resources".to_string());
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();

    let malformed_unauthenticated = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/admin/policy/grants")
                .extension(ConnectInfo(
                    "127.0.0.1:43120".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "toml-policy-malformed-unauth")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed_unauthenticated.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(malformed_unauthenticated).await["reasonCode"],
        "identity_required"
    );

    let list = admin_request(
        app.clone(),
        Method::GET,
        "/v1/admin/policy/grants",
        Some("toml-policy-list"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);
    let list_body = response_json(list).await;
    assert_eq!(list_body["result"][0]["grantRef"], "toml:0");
    assert_eq!(list_body["result"][0]["writable"], false);

    let inspect = admin_request(
        app.clone(),
        Method::GET,
        "/v1/admin/policy/grants/toml%3A0",
        Some("toml-policy-inspect"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(inspect.status(), StatusCode::OK);
    assert_eq!(response_json(inspect).await["result"]["index"], 0);

    let used_by = admin_request(
        app.clone(),
        Method::GET,
        "/v1/admin/policy/resources/project-test/used-by",
        Some("toml-resource-used-by"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(used_by.status(), StatusCode::OK);
    let used_by = response_json(used_by).await;
    let references = used_by["result"].as_array().unwrap();
    assert!(
        references
            .iter()
            .any(|reference| reference["kind"] == "resource_group"
                && reference["id"] == "toml-resources")
    );
    assert!(
        references
            .iter()
            .any(|reference| reference["kind"] == "grant"
                && reference["id"] == "toml:0"
                && reference["viaGroupId"].is_null())
    );
    assert!(
        references
            .iter()
            .any(|reference| reference["kind"] == "grant"
                && reference["id"] == "toml:0"
                && reference["viaGroupId"] == "toml-resources")
    );
    let group_used_by = admin_request(
        app.clone(),
        Method::GET,
        "/v1/admin/policy/resource-groups/toml-resources/used-by",
        Some("toml-resource-group-used-by"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(group_used_by.status(), StatusCode::OK);
    assert_eq!(
        response_json(group_used_by).await["result"][0]["id"],
        "toml:0"
    );

    let unknown_ref = admin_request(
        app.clone(),
        Method::GET,
        "/v1/admin/policy/grants/1d2cb2b0-9ac2-46ec-944a-6ce7e59c6406",
        Some("toml-policy-unknown-ref"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(unknown_ref.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(unknown_ref).await["reasonCode"],
        "policy_grant_not_found"
    );

    let validate = authed_json_request(
        app.clone(),
        Method::POST,
        "/v1/admin/policy/grants/validate",
        "toml-policy-validate-denied",
        "Authorization",
        "Bearer admin-token",
        Some(
            r#"{
                "subjects":["group:anonymous"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(validate.status(), StatusCode::OK);
    let validate_body = response_json(validate).await;
    assert_eq!(validate_body["result"]["valid"], false);
    assert_eq!(
        validate_body["result"]["errors"][0]["code"],
        "policy_authority_unavailable"
    );

    let create = authed_json_request(
        app,
        Method::POST,
        "/v1/admin/policy/grants",
        "toml-policy-create-denied",
        "Authorization",
        "Bearer admin-token",
        Some(
            r#"{
                "subjects":["group:anonymous"],
                "executionContexts":["default"],
                "service":"fake",
                "actions":["echo"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                "credentialMode":"service"
            }"#,
        ),
    )
    .await;
    assert_eq!(create.status(), StatusCode::BAD_REQUEST);
    let create_body = response_json(create).await;
    assert_eq!(create_body["reasonCode"], "policy_authority_unavailable");
}

#[tokio::test]
async fn auth_logout_is_disabled_when_browser_auth_is_disabled() {
    let broker = TestBroker::start_config(&fake_config("")).await;
    let app = broker.app();

    let logout = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/logout")
                .extension(ConnectInfo(
                    "127.0.0.1:40120".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "browser-logout-disabled")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(logout.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(logout).await["reasonCode"],
        "management_denied"
    );
}

#[tokio::test]
async fn browser_login_audit_failure_does_not_issue_cookie() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let hash_key_path = temp_path("audit-failure-hash-key");
    let csrf_key_path = temp_path("audit-failure-csrf-key");
    let password_pepper_path = temp_path("audit-failure-password-pepper");
    let store_path = temp_path("audit-failure-store.sqlite");
    let audit_dir = temp_path("audit-failure-directory");
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([14_u8; 32])).unwrap();
    std::fs::write(&csrf_key_path, URL_SAFE_NO_PAD.encode([15_u8; 32])).unwrap();
    std::fs::write(&password_pepper_path, URL_SAFE_NO_PAD.encode([16_u8; 32])).unwrap();

    let mut config = fake_config(audit_dir.to_str().unwrap());
    config.identity.mode = "required".to_string();
    config.identity.authority = "managed".to_string();
    config.identity.sources = vec![IdentitySourceConfig {
        name: "broker".to_string(),
        kind: "broker_tokens".to_string(),
        header: "Authorization".to_string(),
        scheme: "Bearer".to_string(),
        principals: vec![],
    }];
    config.managed_store = Some(agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.management = agent_access_core::ManagementConfig {
        enabled: true,
        ..agent_access_core::ManagementConfig::default()
    };
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        default_agent_invoke_ttl: None,
        default_user_manage_ttl: Some("8h".to_string()),
        default_admin_ttl: None,
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    config.browser_auth = agent_access_core::BrowserAuthConfig {
        enabled: true,
        public_origin: Some("http://localhost".to_string()),
        session_cookie_name: "aab_session".to_string(),
        csrf_header: "X-Agent-Access-CSRF".to_string(),
        csrf_key_ref: Some(format!("file:{}", csrf_key_path.display())),
        session_ttl: "8h".to_string(),
        allowed_return_paths: vec!["/ui".to_string()],
        local_password: agent_access_core::LocalPasswordConfig {
            enabled: true,
            pepper_ref: Some(format!("file:{}", password_pepper_path.display())),
            min_password_length: 8,
            max_failed_attempts: 3,
            lockout_ttl: "15m".to_string(),
        },
        oidc: Default::default(),
    };

    let broker = TestBroker::start_config(&config).await;
    let runtime = broker.runtime();
    let store = runtime.managed_store().unwrap().clone();
    let password_hasher = runtime.local_password_hasher().unwrap().clone();
    store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".to_string(),
        })
        .unwrap();
    store
        .enable_local_password(
            &password_hasher,
            agent_access_core::LocalPasswordWriteRequest {
                principal_id: "alice".to_string(),
                password: "alice-password".to_string(),
                min_password_length: 8,
                password_change_required: false,
                actor: "admin".to_string(),
            },
        )
        .unwrap();
    let app = broker.app();
    // Startup refuses an unwritable audit store, so the store becomes a
    // directory while the broker serves.
    std::fs::remove_file(&audit_dir).unwrap();
    std::fs::create_dir_all(&audit_dir).unwrap();

    let login = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(
                    "127.0.0.1:40121".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "browser-login-audit-failure")
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"principalId":"alice","password":"alice-password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(login.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(login.headers().get("set-cookie").is_none());
    assert_eq!(
        response_json(login).await["reasonCode"],
        "audit_unavailable"
    );
}

#[tokio::test]
async fn browser_login_enforces_origin_and_sets_session_cookie() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let hash_key_path = temp_path("browser-login-origin-hash-key");
    let csrf_key_path = temp_path("browser-login-origin-csrf-key");
    let password_pepper_path = temp_path("browser-login-origin-password-pepper");
    let store_path = temp_path("browser-login-origin-store.sqlite");
    let audit_path = temp_path("browser-login-origin.audit.jsonl");
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([17_u8; 32])).unwrap();
    std::fs::write(&csrf_key_path, URL_SAFE_NO_PAD.encode([18_u8; 32])).unwrap();
    std::fs::write(&password_pepper_path, URL_SAFE_NO_PAD.encode([19_u8; 32])).unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity.mode = "required".to_string();
    config.identity.authority = "managed".to_string();
    config.identity.sources = vec![IdentitySourceConfig {
        name: "broker".to_string(),
        kind: "broker_tokens".to_string(),
        header: "Authorization".to_string(),
        scheme: "Bearer".to_string(),
        principals: vec![],
    }];
    config.managed_store = Some(agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.management = agent_access_core::ManagementConfig {
        enabled: true,
        ..agent_access_core::ManagementConfig::default()
    };
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        default_agent_invoke_ttl: None,
        default_user_manage_ttl: Some("8h".to_string()),
        default_admin_ttl: None,
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    config.browser_auth = agent_access_core::BrowserAuthConfig {
        enabled: true,
        public_origin: Some("http://localhost".to_string()),
        session_cookie_name: "aab_session".to_string(),
        csrf_header: "X-Agent-Access-CSRF".to_string(),
        csrf_key_ref: Some(format!("file:{}", csrf_key_path.display())),
        session_ttl: "8h".to_string(),
        allowed_return_paths: vec!["/ui".to_string()],
        local_password: agent_access_core::LocalPasswordConfig {
            enabled: true,
            pepper_ref: Some(format!("file:{}", password_pepper_path.display())),
            min_password_length: 8,
            max_failed_attempts: 3,
            lockout_ttl: "15m".to_string(),
        },
        oidc: Default::default(),
    };

    let broker = TestBroker::start_config(&config).await;
    let runtime = broker.runtime();
    let store = runtime.managed_store().unwrap().clone();
    let password_hasher = runtime.local_password_hasher().unwrap().clone();
    store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".to_string(),
        })
        .unwrap();
    store
        .enable_local_password(
            &password_hasher,
            agent_access_core::LocalPasswordWriteRequest {
                principal_id: "alice".to_string(),
                password: "alice-password".to_string(),
                min_password_length: 8,
                password_change_required: false,
                actor: "admin".to_string(),
            },
        )
        .unwrap();
    let app = broker.app();

    let cross_site = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(
                    "127.0.0.1:40122".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "browser-login-cross-site")
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header("Sec-Fetch-Site", "cross-site")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"principalId":"alice","password":"alice-password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(cross_site).await["reasonCode"],
        "csrf_invalid"
    );

    let missing_origin = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(
                    "127.0.0.1:40123".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "browser-login-missing-origin")
                .header("Host", "localhost")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"principalId":"alice","password":"alice-password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(missing_origin).await["reasonCode"],
        "csrf_invalid"
    );

    let login = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(
                    "127.0.0.1:40124".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "browser-login-origin-ok")
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"principalId":"alice","password":"alice-password","returnTo":"/ui"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let set_cookie = login
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.starts_with("aab_session="));
    assert!(set_cookie.contains("Path=/v1"));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    assert!(set_cookie.contains("Max-Age=28800"));
    assert!(!set_cookie.contains("Secure"));
    let body = response_json(login).await;
    assert_eq!(body["result"]["authenticated"], true);
    assert_eq!(body["result"]["csrfHeader"], "X-Agent-Access-CSRF");
    assert!(body["result"]["csrfToken"].as_str().unwrap().len() > 32);
}

struct BrowserRateFixture {
    _broker: TestBroker,
    app: Router,
    state: Arc<ReloadableState>,
    audit_path: PathBuf,
    ingress: Arc<IngressGuards>,
    cookie: String,
    csrf: String,
    agent_tokens: [String; 2],
    management_token: String,
    admin_token: String,
    store_path: PathBuf,
}

async fn browser_rate_fixture(limits: LimitsConfig) -> BrowserRateFixture {
    browser_rate_fixture_with(limits, |_| {}).await
}

/// [`browser_rate_fixture`] with a final configuration hook applied before
/// the broker starts.
async fn browser_rate_fixture_with(
    limits: LimitsConfig,
    configure: impl FnOnce(&mut BrokerConfig),
) -> BrowserRateFixture {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let hash_key_path = temp_path("browser-rate-isolation-hash-key");
    let csrf_key_path = temp_path("browser-rate-isolation-csrf-key");
    let password_pepper_path = temp_path("browser-rate-isolation-password-pepper");
    let store_path = temp_path("browser-rate-isolation-store.sqlite");
    let audit_path = temp_path("browser-rate-isolation.audit.sqlite");
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([17_u8; 32])).unwrap();
    std::fs::write(&csrf_key_path, URL_SAFE_NO_PAD.encode([18_u8; 32])).unwrap();
    std::fs::write(&password_pepper_path, URL_SAFE_NO_PAD.encode([19_u8; 32])).unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity.mode = "required".to_string();
    config.identity.authority = "managed".to_string();
    config.identity.sources = vec![IdentitySourceConfig {
        name: "broker".to_string(),
        kind: "broker_tokens".to_string(),
        header: "X-Agent-Token".to_string(),
        scheme: "Bearer".to_string(),
        principals: vec![],
    }];
    config.managed_store = Some(agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.management = agent_access_core::ManagementConfig {
        enabled: true,
        ..agent_access_core::ManagementConfig::default()
    };
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        default_agent_invoke_ttl: None,
        default_user_manage_ttl: Some("8h".to_string()),
        default_admin_ttl: None,
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    config.browser_auth = agent_access_core::BrowserAuthConfig {
        enabled: true,
        public_origin: Some("http://localhost".to_string()),
        session_cookie_name: "aab_session".to_string(),
        csrf_header: "X-Agent-Access-CSRF".to_string(),
        csrf_key_ref: Some(format!("file:{}", csrf_key_path.display())),
        session_ttl: "8h".to_string(),
        allowed_return_paths: vec!["/ui".to_string()],
        local_password: agent_access_core::LocalPasswordConfig {
            enabled: true,
            pepper_ref: Some(format!("file:{}", password_pepper_path.display())),
            min_password_length: 8,
            max_failed_attempts: 3,
            lockout_ttl: "15m".to_string(),
        },
        oidc: Default::default(),
    };

    config.limits = LimitsConfig {
        upload_spool_dir: config.limits.upload_spool_dir.clone(),
        ..limits
    };
    config.policy.grants[0].subjects = vec!["user:alice".to_string()];
    configure(&mut config);
    let store = agent_access_core::ManagedStore::open(
        config.managed_store.as_ref().unwrap(),
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".to_string(),
        })
        .unwrap();
    store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "admin".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: ("admin").into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("test").into(),
        })
        .unwrap();
    let broker = TestBroker::start_config(&config).await;
    let runtime = broker.runtime();
    let password_hasher = runtime.local_password_hasher().unwrap().clone();
    store
        .enable_local_password(
            &password_hasher,
            agent_access_core::LocalPasswordWriteRequest {
                principal_id: "alice".to_string(),
                password: "alice-password".to_string(),
                min_password_length: 8,
                password_change_required: false,
                actor: "admin".to_string(),
            },
        )
        .unwrap();

    let hasher = runtime.broker_token_hasher().unwrap();
    let issue = |token_class: agent_access_core::BrokerTokenClass| {
        store
            .issue_broker_token(
                hasher,
                agent_access_core::BrokerTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "rate isolation fixture".to_string(),
                    token_class: token_class.clone(),
                    scopes: if token_class == agent_access_core::BrokerTokenClass::AgentInvoke {
                        json!({"allowedExecutionContexts": ["default"]})
                    } else {
                        json!({})
                    },
                    expires_at: None,
                    created_by: "test".to_string(),
                },
            )
            .unwrap()
            .token
    };
    let agent_tokens = [
        issue(agent_access_core::BrokerTokenClass::AgentInvoke),
        issue(agent_access_core::BrokerTokenClass::AgentInvoke),
    ];
    let management_token = issue(agent_access_core::BrokerTokenClass::UserManage);
    let admin_token = store
        .issue_broker_token(
            hasher,
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: "admin".to_string(),
                name: "rate isolation admin".to_string(),
                token_class: agent_access_core::BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "test".to_string(),
            },
        )
        .unwrap()
        .token;
    let state = broker.state();
    let ingress = state.shared_ingress.clone();
    let app = broker.app();
    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(
                    "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "rate-fixture-login")
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"principalId":"alice","password":"alice-password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let csrf = response_json(login).await["result"]["csrfToken"]
        .as_str()
        .unwrap()
        .to_string();
    BrowserRateFixture {
        _broker: broker,
        app,
        state,
        audit_path,
        ingress,
        cookie,
        csrf,
        agent_tokens,
        management_token,
        admin_token,
        store_path,
    }
}

impl BrowserRateFixture {
    async fn browser_request(
        &self,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> axum::response::Response {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .extension(ConnectInfo(
                        "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(REQUEST_ID_HEADER, "browser-rate-request")
                    .header("Cookie", &self.cookie)
                    .header("X-Agent-Access-CSRF", &self.csrf)
                    .header("Host", "localhost")
                    .header("Origin", "http://localhost")
                    .header(CONTENT_TYPE, "application/json")
                    .body(
                        body.map(|value| Body::from(value.to_string()))
                            .unwrap_or_else(Body::empty),
                    )
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// `fake.echo` for project TEST with an agent token.
    async fn token_invoke(&self, request_id: &str, token: &str) -> axum::response::Response {
        authed_json_request(
            self.app.clone(),
            Method::POST,
            "/v1/invoke/fake/echo",
            request_id,
            "X-Agent-Token",
            format!("Bearer {token}"),
            Some(r#"{"inputs":{"project":"TEST","message":"counted"}}"#),
        )
        .await
    }

    async fn token_request(&self, token: &str, uri: &str) -> axum::response::Response {
        authed_json_request(
            self.app.clone(),
            Method::GET,
            uri,
            "agent-rate-request",
            "X-Agent-Token",
            format!("Bearer {token}"),
            None,
        )
        .await
    }
}

fn one_invocation_per_minute() -> agent_access_core::InvocationLimitsConfig {
    agent_access_core::InvocationLimitsConfig {
        default: Some(agent_access_core::InvocationLimitConfig {
            requests: 1,
            window: "1m".to_string(),
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn browser_rate_isolation_covers_provisioning_discovery_specs_session_and_logout() {
    let fixture = browser_rate_fixture(LimitsConfig {
        invocations: one_invocation_per_minute(),
        auth_requests_per_source_per_minute: 1,
        auth_requests_per_principal_per_minute: 1,
        ..LimitsConfig::default()
    })
    .await;
    // Login has already exhausted the independent authentication budgets.
    // Browsing and authenticated discovery are never counted.
    for round in 0..2 {
        for uri in [
            "/v1/me",
            "/v1/broker/status",
            "/v1/services",
            "/v1/services/fake",
            "/v1/capabilities",
            "/v1/spec/catalog",
            "/v1/spec/openapi.json",
            "/v1/spec/send-schema.json",
            "/v1/tokens",
            "/v1/auth/session",
        ] {
            let response = fixture.browser_request(Method::GET, uri, None).await;
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "round {round}: {uri}: {}",
                response_json(response).await
            );
        }
        let issued = fixture.browser_request(Method::POST, "/v1/tokens", Some(json!({"name": format!("provisioned-{round}"), "allowedExecutionContexts": ["default"]}))).await;
        assert_eq!(
            issued.status(),
            StatusCode::OK,
            "{}",
            response_json(issued).await
        );
        let agent = fixture
            .token_request(&fixture.agent_tokens[0], "/v1/services")
            .await;
        assert_eq!(agent.status(), StatusCode::OK, "round {round}");
    }
    let logout = fixture
        .browser_request(Method::POST, "/v1/auth/logout", None)
        .await;
    assert_eq!(logout.status(), StatusCode::OK);
    assert_eq!(
        fixture
            .browser_request(Method::GET, "/v1/auth/session", None)
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn authenticated_discovery_and_management_do_not_spend_invocation_budgets() {
    let fixture = browser_rate_fixture(LimitsConfig {
        invocations: one_invocation_per_minute(),
        ..LimitsConfig::default()
    })
    .await;
    for round in 0..5 {
        for token in &fixture.agent_tokens {
            for uri in [
                "/v1/services",
                "/v1/services/fake",
                "/v1/capabilities",
                "/v1/me",
                "/v1/spec/catalog",
            ] {
                assert_eq!(
                    fixture.token_request(token, uri).await.status(),
                    StatusCode::OK,
                    "round {round}: {uri}"
                );
            }
        }
        assert_eq!(
            fixture
                .token_request(&fixture.management_token, "/v1/tokens")
                .await
                .status(),
            StatusCode::OK
        );
    }
    // Tokens of one principal share the (principal, service) window.
    let first = fixture
        .token_invoke("shared-principal-first", &fixture.agent_tokens[0])
        .await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = fixture
        .token_invoke("shared-principal-second", &fixture.agent_tokens[1])
        .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response_json(second).await["reasonCode"], "rate_limited");
    // Discovery and management remain available after the limit is reached.
    assert_eq!(
        fixture
            .token_request(&fixture.agent_tokens[1], "/v1/services")
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .token_request(&fixture.management_token, "/v1/tokens")
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn browser_rate_isolation_rejects_spoofed_and_expired_cookies_under_auth_limits() {
    let fixture = browser_rate_fixture(LimitsConfig {
        auth_requests_per_source_per_minute: 3,
        ..LimitsConfig::default()
    })
    .await;
    // A real management token in a cookie is not a verified browser session.
    let spoofed = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/tokens",
        "spoofed-session",
        "Cookie",
        format!("aab_session={}", fixture.management_token),
        None,
    )
    .await;
    assert_eq!(spoofed.status(), StatusCode::UNAUTHORIZED);
    let malformed = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/spec/catalog",
        "malformed-session",
        "Cookie",
        "aab_session=not-a-session",
        None,
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::UNAUTHORIZED);
    let conn = rusqlite::Connection::open(&fixture.store_path).unwrap();
    conn.execute("UPDATE broker_tokens SET expires_at = '2000-01-01T00:00:00Z' WHERE token_id IN (SELECT token_id FROM browser_sessions)", []).unwrap();
    drop(conn);
    for uri in [
        "/v1/tokens",
        "/v1/services",
        "/v1/spec/catalog",
        "/v1/auth/session",
    ] {
        let expired = fixture.browser_request(Method::GET, uri, None).await;
        assert_eq!(expired.status(), StatusCode::TOO_MANY_REQUESTS, "{uri}");
        assert_eq!(response_json(expired).await["reasonCode"], "rate_limited");
    }
    // Authentication abuse must not spend the independently configured agent budget.
    assert_eq!(
        fixture
            .token_request(&fixture.agent_tokens[0], "/v1/services")
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn browser_rate_isolation_keeps_global_and_principal_concurrency_protection() {
    let fixture = browser_rate_fixture(LimitsConfig {
        max_concurrent_requests: 1,
        max_concurrent_requests_per_principal: 1,
        ..LimitsConfig::default()
    })
    .await;
    let global = fixture.ingress.try_global_concurrency(1).unwrap();
    let response = fixture
        .browser_request(Method::GET, "/v1/tokens", None)
        .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "concurrency_limited"
    );
    drop(global);
    let principal = fixture
        .ingress
        .try_principal_concurrency("alice", 1)
        .unwrap();
    let response = fixture
        .browser_request(Method::GET, "/v1/tokens", None)
        .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "concurrency_limited"
    );
    drop(principal);
    assert_eq!(
        fixture
            .browser_request(Method::GET, "/v1/tokens", None)
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn browser_rate_isolation_password_change_uses_auth_principal_budget() {
    let fixture = browser_rate_fixture(LimitsConfig {
        auth_requests_per_principal_per_minute: 1,
        ..LimitsConfig::default()
    })
    .await;
    // Successful login spent the authentication principal allowance, not the agent allowance.
    let response = fixture
        .browser_request(
            Method::POST,
            "/v1/auth/local/password/change",
            Some(
                json!({"currentPassword":"alice-password", "newPassword":"alice-password-updated"}),
            ),
        )
        .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response_json(response).await["reasonCode"], "rate_limited");
    assert_eq!(
        fixture
            .token_request(&fixture.agent_tokens[0], "/v1/services")
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .browser_request(Method::GET, "/v1/auth/session", None)
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn browser_rate_isolation_configured_token_header_takes_precedence_over_cookie() {
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    for (token, expected) in [
        ("invalid-token", StatusCode::UNAUTHORIZED),
        (fixture.agent_tokens[0].as_str(), StatusCode::OK),
        (fixture.agent_tokens[1].as_str(), StatusCode::OK),
    ] {
        let response = fixture
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/services")
                    .extension(ConnectInfo(
                        "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(REQUEST_ID_HEADER, "mixed-browser-token-auth")
                    .header("Cookie", &fixture.cookie)
                    .header("X-Agent-Token", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert_eq!(
        fixture
            .browser_request(Method::GET, "/v1/services", None)
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn managed_jira_verify_marks_upstream_verified_after_provider_probe() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let admin_token_path = temp_path("managed-upstream-admin-token");
    let key_path = temp_path("managed-upstream-key");
    let store_path = temp_path("managed-upstream-store.sqlite");
    let audit_path = temp_path("managed-upstream.audit.jsonl");
    std::fs::write(&admin_token_path, "admin-token").unwrap();
    std::fs::write(&key_path, URL_SAFE_NO_PAD.encode([9_u8; 32])).unwrap();

    let config = managed_jira_verify_config(&admin_token_path, &key_path, &store_path, &audit_path);

    let runtime_broker = TestBroker::start_with_providers(
        &config,
        vec![Arc::new(TestCredentialVerificationProvider)],
    )
    .await;
    let runtime = runtime_broker.runtime();
    let store = runtime.managed_store().unwrap().clone();
    store
        .create_or_update_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".to_string(),
        })
        .unwrap();
    store
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            CredentialWriteRequest {
                owner_principal_id: "alice".to_string(),
                service: "jira".to_string(),
                name: "default".to_string(),
                profile: "jira-cloud-api-token".to_string(),
                credential_kind: "basic_api_token".to_string(),
                secret: json!({"username": "alice@example.com", "token": "jira-token"}),
                metadata: json!({}),
                actor: "admin".to_string(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    let app = runtime_broker.app();

    let verify = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/admin/principals/alice/credentials/jira/default/verify")
                .extension(ConnectInfo(
                    "127.0.0.1:43000".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "managed-upstream-verify")
                .header("Authorization", "Bearer admin-token")
                .header("Content-Type", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(verify.status(), StatusCode::OK);
    let body = response_json(verify).await;
    assert_eq!(body["result"]["verificationStatus"], "upstream_verified");
    assert!(body["result"]["lastVerifiedAt"].is_string());

    let audit = std::fs::read_to_string(audit_path).unwrap();
    let records = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let upstream_verify = records
        .iter()
        .find(|record| {
            record["action"] == "admin.credentials.verify"
                && record["providerAudit"]["management"]["phase"] == "upstream_verification"
        })
        .unwrap();
    assert_eq!(upstream_verify["upstreamStatus"], 200);
    assert_eq!(upstream_verify["upstreamDurationMs"], 1);
    assert_eq!(
        upstream_verify["providerAudit"]["verification"]["provider"],
        "jira"
    );
    assert_eq!(
        upstream_verify["providerAudit"]["verification"]["operation"],
        "credential.verify"
    );
}

#[tokio::test]
async fn managed_jira_verify_does_not_mark_credential_after_upstream_failure() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let admin_token_path = temp_path("managed-upstream-fail-admin-token");
    let key_path = temp_path("managed-upstream-fail-key");
    let store_path = temp_path("managed-upstream-fail-store.sqlite");
    let audit_path = temp_path("managed-upstream-fail.audit.jsonl");
    std::fs::write(&admin_token_path, "admin-token").unwrap();
    std::fs::write(&key_path, URL_SAFE_NO_PAD.encode([9_u8; 32])).unwrap();

    let config = managed_jira_verify_config(&admin_token_path, &key_path, &store_path, &audit_path);
    let runtime_broker = TestBroker::start_with_providers(
        &config,
        vec![Arc::new(TestFailingCredentialVerificationProvider)],
    )
    .await;
    let runtime = runtime_broker.runtime();
    let store = runtime.managed_store().unwrap().clone();
    store
        .create_or_update_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".to_string(),
        })
        .unwrap();
    store
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            CredentialWriteRequest {
                owner_principal_id: "alice".to_string(),
                service: "jira".to_string(),
                name: "default".to_string(),
                profile: "jira-cloud-api-token".to_string(),
                credential_kind: "basic_api_token".to_string(),
                secret: json!({"username": "alice@example.com", "token": "jira-token"}),
                metadata: json!({}),
                actor: "admin".to_string(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    let app = runtime_broker.app();

    let verify = admin_request(
        app,
        Method::POST,
        "/v1/admin/principals/alice/credentials/jira/default/verify",
        Some("managed-upstream-fail-verify"),
        Some("admin-token"),
    )
    .await;

    assert_eq!(verify.status(), StatusCode::FAILED_DEPENDENCY);
    let body = response_json(verify).await;
    assert_eq!(body["reasonCode"], "upstream_unauthorized");
    assert_eq!(body["decision"], "error");
    let metadata = store
        .credential_by_tuple("alice", "jira", "default")
        .unwrap();
    assert!(metadata.last_verified_at.is_none());
    assert_eq!(
        metadata.verification_status.as_deref(),
        Some("verification_failed")
    );
    assert!(metadata.last_verification_attempt_at.is_some());
    assert_eq!(
        metadata.last_verification_error_code.as_deref(),
        Some("upstream_unauthorized")
    );
}

#[tokio::test]
async fn managed_verify_does_not_mark_credential_after_local_failure() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let admin_token_path = temp_path("managed-local-fail-admin-token");
    let key_path = temp_path("managed-local-fail-key");
    let store_path = temp_path("managed-local-fail-store.sqlite");
    let audit_path = temp_path("managed-local-fail.audit.jsonl");
    std::fs::write(&admin_token_path, "admin-token").unwrap();
    std::fs::write(&key_path, URL_SAFE_NO_PAD.encode([9_u8; 32])).unwrap();

    let config = managed_jira_verify_config(&admin_token_path, &key_path, &store_path, &audit_path);
    let runtime_broker = TestBroker::start_with_providers(
        &config,
        vec![Arc::new(TestLocalCredentialVerificationFailureProvider)],
    )
    .await;
    let runtime = runtime_broker.runtime();
    let store = runtime.managed_store().unwrap().clone();
    store
        .create_or_update_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".to_string(),
        })
        .unwrap();
    store
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            CredentialWriteRequest {
                owner_principal_id: "alice".to_string(),
                service: "jira".to_string(),
                name: "default".to_string(),
                profile: "jira-cloud-api-token".to_string(),
                credential_kind: "basic_api_token".to_string(),
                secret: json!({"username": "alice@example.com", "token": "jira-token"}),
                metadata: json!({}),
                actor: "admin".to_string(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    let app = runtime_broker.app();

    let verify = authed_json_request(
        app,
        Method::POST,
        "/v1/admin/principals/alice/credentials/jira/default/verify",
        "managed-local-fail-verify",
        "Authorization",
        "Bearer admin-token",
        Some("{}"),
    )
    .await;

    assert_eq!(verify.status(), StatusCode::BAD_REQUEST);
    let body = response_json(verify).await;
    assert_eq!(body["reasonCode"], "input_invalid");
    assert_eq!(body["decision"], "deny");
    let metadata = store
        .credential_by_tuple("alice", "jira", "default")
        .unwrap();
    assert!(metadata.last_verified_at.is_none());
    assert_eq!(
        metadata.verification_status.as_deref(),
        Some("not_verified")
    );
    assert!(metadata.last_verification_attempt_at.is_none());
    assert!(metadata.last_verification_error_code.is_none());
}

#[tokio::test]
async fn admin_verify_rejects_disabled_managed_credential_owner() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let admin_token_path = temp_path("managed-disabled-owner-admin-token");
    let key_path = temp_path("managed-disabled-owner-key");
    let store_path = temp_path("managed-disabled-owner-store.sqlite");
    let audit_path = temp_path("managed-disabled-owner.audit.jsonl");
    std::fs::write(&admin_token_path, "admin-token").unwrap();
    std::fs::write(&key_path, URL_SAFE_NO_PAD.encode([9_u8; 32])).unwrap();

    let config = managed_jira_verify_config(&admin_token_path, &key_path, &store_path, &audit_path);
    let runtime_broker = TestBroker::start_with_providers(
        &config,
        vec![Arc::new(TestCredentialVerificationProvider)],
    )
    .await;
    let runtime = runtime_broker.runtime();
    let store = runtime.managed_store().unwrap().clone();
    store
        .create_or_update_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".to_string(),
        })
        .unwrap();
    store
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            CredentialWriteRequest {
                owner_principal_id: "alice".to_string(),
                service: "jira".to_string(),
                name: "default".to_string(),
                profile: "jira-cloud-api-token".to_string(),
                credential_kind: "basic_api_token".to_string(),
                secret: json!({"username": "alice@example.com", "token": "jira-token"}),
                metadata: json!({}),
                actor: "admin".to_string(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    store
        .patch_principal(PrincipalPatchRequest {
            principal_id: "alice".to_string(),
            display_name: None,
            email: None,
            status: Some("disabled".to_string()),
        })
        .unwrap();
    let app = runtime_broker.app();

    let verify = admin_request(
        app,
        Method::POST,
        "/v1/admin/principals/alice/credentials/jira/default/verify",
        Some("managed-disabled-owner-verify"),
        Some("admin-token"),
    )
    .await;

    assert_eq!(verify.status(), StatusCode::FORBIDDEN);
    let body = response_json(verify).await;
    assert_eq!(body["reasonCode"], "principal_disabled");
    let metadata = store
        .credential_by_tuple("alice", "jira", "default")
        .unwrap();
    assert_eq!(
        metadata.verification_status.as_deref(),
        Some("not_verified")
    );
    assert!(metadata.last_verification_attempt_at.is_none());
}

#[tokio::test]
async fn multipart_authorizes_metadata_before_reading_file_parts() {
    let broker = TestBroker::start_config(&fake_config("")).await;
    let app = broker.app();
    let boundary = "agent-access-boundary";
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"request\"\r\n\
         Content-Type: application/json\r\n\r\n\
         {{\"inputs\":{{\"project\":\"OTHER\",\"message\":\"hello\"}}}}\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; filename=\"missing-name.txt\"\r\n\
         Content-Type: text/plain\r\n\r\n\
         this part should not be inspected before policy denial\r\n\
         --{boundary}--\r\n"
    );

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/fake/echo")
                .extension(ConnectInfo(
                    "127.0.0.1:40004".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-multipart-denied")
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["reasonCode"], "service_action_denied");
}

#[tokio::test]
async fn multipart_is_rejected_for_actions_without_body_parts() {
    let broker = TestBroker::start_config(&fake_config("")).await;
    let app = broker.app();
    let boundary = "agent-access-boundary";
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"request\"\r\n\
         Content-Type: application/json\r\n\r\n\
         {{\"inputs\":{{\"project\":\"TEST\",\"message\":\"hello\"}}}}\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; filename=\"ignored.txt\"\r\n\
         Content-Type: text/plain\r\n\r\n\
         this part must not be accepted for fake.echo\r\n\
         --{boundary}--\r\n"
    );

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/fake/echo")
                .extension(ConnectInfo(
                    "127.0.0.1:40005".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-multipart-unsupported")
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["reasonCode"], "body_malformed");
    assert_eq!(
        value["reason"],
        "action does not accept multipart body parts"
    );
}

#[tokio::test]
async fn multipart_file_parts_are_temp_file_backed_not_memory_backed() {
    let mut config = download_config("");
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        execution_contexts: None,
        service: "jira".to_string(),
        actions: vec!["attachment.add".to_string()],
        resources: selected_resources(&[("jira-project", &["TEST"])]),
        credential_mode: "service".to_string(),
        priority: None,
    });
    let runtime_broker =
        TestBroker::start_with_providers(&config, vec![Arc::new(TestMultipartProvider)]).await;
    let app = runtime_broker.app();
    let boundary = "agent-access-boundary";
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"request\"\r\n\
         Content-Type: application/json\r\n\r\n\
         {{\"inputs\":{{\"project\":\"TEST\",\"attachments\":[{{\"field\":\"file\",\"filename\":\"evidence.txt\",\"contentType\":\"text/plain\",\"size\":21,\"sha256\":\"5fe643b936e7d326642540a9bee7db2db0fe7895ac5ab2e58278512a21930129\"}}]}}}}\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"evidence.txt\"\r\n\
         Content-Type: text/plain\r\n\r\n\
         streamed upload bytes\r\n\
         --{boundary}--\r\n"
    );

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/attachment.add")
                .extension(ConnectInfo(
                    "127.0.0.1:40006".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-multipart-temp-file")
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = response_json(response).await;
    assert_eq!(value["decision"], "allow");
    assert_eq!(value["result"]["bytesInMemory"], 0);
    assert_eq!(value["result"]["tempFileBacked"], true);
    assert_eq!(value["result"]["readBack"], "streamed upload bytes");
    #[cfg(unix)]
    assert_eq!(value["result"]["tempFileMode"], "600");
    assert!(
        !Path::new(value["result"]["tempPath"].as_str().unwrap()).exists(),
        "spooled multipart temp file should be deleted after invocation"
    );
}

#[tokio::test]
async fn multipart_rejects_header_mismatch_before_spooling() {
    let broker = test_multipart_broker().await;
    let app = broker.app();
    let boundary = "agent-access-boundary";
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"request\"\r\n\
         Content-Type: application/json\r\n\r\n\
         {{\"inputs\":{{\"project\":\"TEST\",\"attachments\":[{{\"field\":\"file\",\"filename\":\"evidence.txt\",\"contentType\":\"text/plain\",\"size\":21,\"sha256\":\"5fe643b936e7d326642540a9bee7db2db0fe7895ac5ab2e58278512a21930129\"}}]}}}}\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"wrong.txt\"\r\n\
         Content-Type: text/plain\r\n\r\n\
         streamed upload bytes\r\n\
         --{boundary}--\r\n"
    );

    let response = multipart_upload_request(
        app,
        "agent-req-multipart-header-mismatch",
        "127.0.0.1:40007",
        boundary,
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let value = response_json(response).await;
    assert_eq!(value["reasonCode"], "body_malformed");
    assert_eq!(
        value["reason"],
        "attachment filename did not match metadata"
    );
}

#[tokio::test]
async fn multipart_rejects_actual_size_over_metadata_as_413() {
    let broker = test_multipart_broker().await;
    let app = broker.app();
    let boundary = "agent-access-boundary";
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"request\"\r\n\
         Content-Type: application/json\r\n\r\n\
         {{\"inputs\":{{\"project\":\"TEST\",\"attachments\":[{{\"field\":\"file\",\"filename\":\"evidence.txt\",\"contentType\":\"text/plain\",\"size\":1,\"sha256\":\"5fe643b936e7d326642540a9bee7db2db0fe7895ac5ab2e58278512a21930129\"}}]}}}}\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"evidence.txt\"\r\n\
         Content-Type: text/plain\r\n\r\n\
         streamed upload bytes\r\n\
         --{boundary}--\r\n"
    );

    let response = multipart_upload_request(
        app,
        "agent-req-multipart-size-mismatch",
        "127.0.0.1:40008",
        boundary,
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let value = response_json(response).await;
    assert_eq!(value["reasonCode"], "attachment_integrity_mismatch");
}

#[tokio::test]
async fn multipart_reserves_aggregate_spool_capacity_before_file_read() {
    let mut config = test_multipart_config();
    config.limits.upload_spool_max_bytes = 20;
    let broker =
        TestBroker::start_with_providers(&config, vec![Arc::new(TestMultipartProvider)]).await;
    let app = broker.app();
    let boundary = "agent-access-boundary";
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"request\"\r\n\
         Content-Type: application/json\r\n\r\n\
         {{\"inputs\":{{\"project\":\"TEST\",\"attachments\":[{{\"field\":\"file\",\"filename\":\"evidence.txt\",\"contentType\":\"text/plain\",\"size\":21,\"sha256\":\"5fe643b936e7d326642540a9bee7db2db0fe7895ac5ab2e58278512a21930129\"}}]}}}}\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"evidence.txt\"\r\n\
         Content-Type: text/plain\r\n\r\n\
         streamed upload bytes\r\n\
         --{boundary}--\r\n"
    );

    let response = multipart_upload_request(
        app,
        "agent-req-multipart-spool-capacity",
        "127.0.0.1:40011",
        boundary,
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let value = response_json(response).await;
    assert_eq!(value["reasonCode"], "attachment_size_denied");
    assert_eq!(value["reason"], "upload spool capacity is exhausted");
}

#[tokio::test]
async fn multipart_idle_timeout_errors_before_metadata_read_completes() {
    let mut config = test_multipart_config();
    config.limits.streaming_idle_timeout_ms = 1;
    let broker =
        TestBroker::start_with_providers(&config, vec![Arc::new(TestMultipartProvider)]).await;
    let app = broker.app();
    let boundary = "agent-access-boundary";
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"request\"\r\n\
         Content-Type: application/json\r\n\r\n\
         {{\"inputs\":{{\"project\":\"TEST\",\"attachments\":[]}}}}\r\n\
         --{boundary}--\r\n"
    );
    let delayed_body = Body::from_stream(stream::once(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        Ok::<Bytes, std::io::Error>(Bytes::from(body))
    }));

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/attachment.add")
                .extension(ConnectInfo(
                    "127.0.0.1:40012".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-multipart-idle-timeout")
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(delayed_body)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let value = response_json(response).await;
    assert_eq!(value["reasonCode"], "body_malformed");
}

#[tokio::test]
async fn json_body_limit_errors_return_413() {
    let mut config = fake_config("");
    config.limits.max_http_body_bytes = 8;
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/fake/echo")
                .extension(ConnectInfo(
                    "127.0.0.1:40009".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-json-body-limit")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"inputs":{"project":"TEST","message":"hello"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let value = response_json(response).await;
    assert_eq!(value["reasonCode"], "attachment_size_denied");
}

#[tokio::test]
async fn multipart_body_limit_errors_return_413() {
    let mut config = fake_config("");
    config.limits.max_http_body_bytes = 64;
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();
    let boundary = "agent-access-boundary";
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"request\"\r\n\
         Content-Type: application/json\r\n\r\n\
         {{\"inputs\":{{\"project\":\"TEST\",\"message\":\"hello\"}}}}\r\n\
         --{boundary}--\r\n"
    );

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/fake/echo")
                .extension(ConnectInfo(
                    "127.0.0.1:40010".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-multipart-body-limit")
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let value = response_json(response).await;
    assert_eq!(value["reasonCode"], "attachment_size_denied");
}

#[tokio::test]
async fn trusted_proxy_source_derivation_audits_forwarded_chain() {
    let audit_path = temp_path("trusted-proxy.audit.jsonl");
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.network.trusted_proxies = vec!["127.0.0.1".to_string(), "127.0.0.2".to_string()];
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();

    let response = invoke_fake(
        app,
        "127.0.0.1:41000",
        "agent-req-trusted-proxy",
        &[("X-Forwarded-For", "203.0.113.10, 127.0.0.2")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let record = read_audit_record(&audit_path);
    assert_eq!(record["source"]["remote"], "203.0.113.10");
    assert_eq!(record["source"]["proxyChain"][0], "203.0.113.10");
    assert_eq!(record["source"]["proxyChain"][1], "127.0.0.2");
}

#[test]
fn trusted_proxy_parser_rejects_trust_all_shapes() {
    assert!(TrustedProxy::parse("*").is_none());
    assert!(TrustedProxy::parse("0.0.0.0/0").is_none());
    assert!(TrustedProxy::parse("::/0").is_none());
    assert!(TrustedProxy::parse("127.0.0.1/33").is_none());
    assert!(TrustedProxy::parse("::1/129").is_none());
    assert!(TrustedProxy::parse("127.0.0.1").is_some());
    assert!(TrustedProxy::parse("127.0.0.0/24").is_some());
}

#[tokio::test]
async fn untrusted_peer_forwarded_headers_are_ignored() {
    let audit_path = temp_path("untrusted-proxy.audit.jsonl");
    let broker = TestBroker::start_config(&fake_config(audit_path.to_str().unwrap())).await;
    let app = broker.app();

    let response = invoke_fake(
        app,
        "127.0.0.1:41001",
        "agent-req-untrusted-proxy",
        &[("X-Forwarded-For", "203.0.113.10")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let record = read_audit_record(&audit_path);
    assert_eq!(record["source"]["remote"], "127.0.0.1:41001");
    assert!(record["source"].get("proxyChain").is_none());
}

#[tokio::test]
async fn anonymous_source_rate_limit_applies_by_ip() {
    let mut config = fake_config("");
    config.limits.auth_requests_per_source_per_minute = 1;
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();

    let first = invoke_fake(app.clone(), "127.0.0.1:41002", "agent-req-rate-1", &[]).await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = invoke_fake(app, "127.0.0.1:41003", "agent-req-rate-2", &[]).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let value = response_json(second).await;
    assert_eq!(value["reasonCode"], "rate_limited");
}

#[tokio::test(flavor = "current_thread")]
async fn source_rate_limit_event_includes_request_correlation_fields() {
    let captured = install_trace_capture().start();

    let mut config = fake_config("");
    config.limits.auth_requests_per_source_per_minute = 1;
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();

    let first = invoke_fake(
        app.clone(),
        "127.0.0.1:41032",
        "agent-req-rate-event-1",
        &[],
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = captured
        .run(invoke_fake(
            app,
            "127.0.0.1:41033",
            "agent-req-rate-event-2",
            &[],
        ))
        .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let value = response_json(second).await;
    assert_eq!(value["reasonCode"], "rate_limited");

    let events = captured.take_events();
    let limited = event_by_name_and_agent(&events, "request_limited", "agent-req-rate-event-2");
    assert_eq!(string_field(limited, "level"), Some("WARN"));
    assert_eq!(
        string_field(limited, "agentRequestId"),
        Some("agent-req-rate-event-2")
    );
    assert!(string_field(limited, "brokerRequestId").is_some());
    assert_eq!(string_field(limited, "service"), Some("fake"));
    assert_eq!(string_field(limited, "action"), Some("echo"));
    assert_eq!(string_field(limited, "limitKind"), Some("auth_source_rate"));
    assert_eq!(number_field(limited, "limit"), Some(1));
    assert_eq!(string_field(limited, "source"), Some("127.0.0.1"));
    assert_eq!(string_field(limited, "decision"), Some("error"));
    assert_eq!(string_field(limited, "reasonCode"), Some("rate_limited"));
    assert_eq!(number_field(limited, "http.statusCode"), Some(429));
}

#[tokio::test]
async fn jira_read_response_options_are_closed_and_rejected_before_provider_access() {
    let fixture = jira_read_presentation_fixture("").await;

    for (request_id, action, body, status, reason) in [
        (
            "jira-read-unknown-top-level",
            "issue.view",
            json!({
                "inputs": { "issue": "PROJ-7" },
                "readContentFormats": "markdown"
            }),
            StatusCode::BAD_REQUEST,
            "input_invalid",
        ),
        (
            "jira-read-invalid-enum",
            "issue.view",
            json!({
                "inputs": { "issue": "PROJ-7" },
                "readContentFormat": "html"
            }),
            StatusCode::BAD_REQUEST,
            "input_invalid",
        ),
        (
            "jira-read-mutually-exclusive",
            "issue.view",
            json!({
                "inputs": { "issue": "PROJ-7" },
                "readContentFormat": "markdown",
                "responseFormat": "markdown"
            }),
            StatusCode::BAD_REQUEST,
            "input_invalid",
        ),
        (
            "jira-read-whole-unsupported-on-mutation",
            "issue.update",
            json!({
                "inputs": { "issue": "PROJ-7" },
                "responseFormat": "markdown"
            }),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "response_format_unsupported",
        ),
        (
            "jira-read-embedded-unsupported-on-body-free-read",
            "verify",
            json!({
                "inputs": { "issue": "PROJ-7" },
                "readContentFormat": "text"
            }),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "response_format_unsupported",
        ),
    ] {
        let response =
            jira_read_presentation_request(fixture.app.clone(), request_id, action, body).await;
        assert_eq!(response.status(), status, "{request_id}");
        let response = response_json(response).await;
        assert_eq!(response["reasonCode"], reason, "{request_id}");
    }

    assert_eq!(fixture.scope_resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn jira_read_formats_transform_success_and_allow_with_result_without_observability_leaks() {
    let captured = install_trace_capture().start();

    let audit_path = temp_path("jira-normalized-read.audit.jsonl");
    let fixture = jira_read_presentation_fixture(audit_path.to_str().unwrap()).await;

    let embedded = captured
        .run(jira_read_presentation_request(
            fixture.app.clone(),
            "jira-read-embedded-success",
            "issue.view",
            json!({
                "inputs": { "issue": "PROJ-7" },
                "readContentFormat": "markdown"
            }),
        ))
        .await;
    assert_eq!(embedded.status(), StatusCode::OK);
    let embedded = response_json(embedded).await;
    assert_eq!(embedded["decision"], "allow");
    assert_eq!(
        embedded["result"]["description"]["content"][0]["content"][0]["text"],
        JIRA_READ_NATIVE_SENTINEL
    );
    assert_eq!(embedded["result"]["renderedBody"]["format"], "markdown");
    assert_eq!(
        embedded["result"]["renderedBody"]["value"],
        JIRA_READ_NATIVE_SENTINEL
    );

    let whole = captured
        .run(jira_read_presentation_request(
            fixture.app.clone(),
            "jira-read-whole-success",
            "issue.view",
            json!({
                "inputs": { "issue": "PROJ-7" },
                "responseFormat": "markdown"
            }),
        ))
        .await;
    assert_eq!(whole.status(), StatusCode::OK);
    let whole = response_json(whole).await;
    assert_eq!(whole["decision"], "allow");
    assert_eq!(whole["result"]["format"], "markdown");
    let markdown = whole["result"]["value"].as_str().unwrap();
    assert!(markdown.starts_with("# `PROJ-7` — Normalized read fixture\n"));
    assert!(markdown.contains("## Description\n\n"));
    assert!(markdown.contains(JIRA_READ_NATIVE_SENTINEL));
    assert!(!markdown.contains("\"type\":\"doc\""));
    assert!(markdown.ends_with('\n'));

    let mismatch = captured
        .run(jira_read_presentation_request(
            fixture.app.clone(),
            "jira-read-whole-mismatch",
            "verify",
            json!({
                "inputs": { "issue": "PROJ-7" },
                "responseFormat": "markdown"
            }),
        ))
        .await;
    assert_eq!(mismatch.status(), StatusCode::CONFLICT);
    let mismatch = response_json(mismatch).await;
    assert_eq!(mismatch["decision"], "allow");
    assert_eq!(mismatch["reasonCode"], "verification_mismatch");
    assert_eq!(mismatch["result"]["format"], "markdown");
    let markdown = mismatch["result"]["value"].as_str().unwrap();
    assert!(markdown.starts_with("# Jira verification for `PROJ-7`\n"));
    assert!(markdown.contains("- Status: mismatch\n"));
    assert!(markdown.contains("comment: `43`"));

    assert_eq!(fixture.scope_resolutions.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 3);

    let events = captured.take_events();
    // The capture observed each request, so the sentinel check covers them.
    for request_id in [
        "jira-read-embedded-success",
        "jira-read-whole-success",
        "jira-read-whole-mismatch",
    ] {
        event_by_name_and_agent(&events, "invoke_completed", request_id);
    }
    let events = serde_json::to_string(&events).unwrap();
    assert!(!events.contains(JIRA_READ_NATIVE_SENTINEL));
    let audit = std::fs::read_to_string(&audit_path).unwrap();
    assert!(!audit.contains(JIRA_READ_NATIVE_SENTINEL));
    for record in read_audit_records(&audit_path) {
        assert!(
            !record["providerAudit"]
                .to_string()
                .contains(JIRA_READ_NATIVE_SENTINEL)
        );
        assert!(
            !record["objectIds"]
                .to_string()
                .contains(JIRA_READ_NATIVE_SENTINEL)
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn jira_normalized_write_content_is_absent_from_tracing_and_audit() {
    let captured = install_trace_capture().start();

    let audit_path = temp_path("jira-normalized-write-tracing.audit.jsonl");
    let service_username_path = temp_path("jira-normalized-write-tracing-service-username");
    let service_token_path = temp_path("jira-normalized-write-tracing-service-token");
    std::fs::write(&service_username_path, "service@example.com").unwrap();
    std::fs::write(&service_token_path, "service-token").unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.credentials.service.insert(
        "jira".to_string(),
        CredentialConfig {
            kind: "basic_api_token".to_string(),
            username_ref: Some(format!("file:{}", service_username_path.display())),
            token_ref: Some(format!("file:{}", service_token_path.display())),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config
        .providers
        .insert(agent_access_jira::JiraProviderConfig {
            tenant_host: "example.atlassian.net".to_string(),
            cloud_id: None,
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".to_string()],
            attachments: agent_access_provider::AttachmentLimitsConfig::default(),
            content: agent_access_jira::JiraContentConfig {
                comment_formats: vec!["adf".to_string()],
                ..agent_access_jira::JiraContentConfig::default()
            },
            search: agent_access_provider::SearchLimitsConfig::default(),
            comments: agent_access_jira::JiraCommentsConfig::default(),
            issue_links: agent_access_jira::JiraIssueLinksConfig::default(),
        });
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        execution_contexts: None,
        service: "jira".to_string(),
        actions: vec!["issue.create".to_string()],
        resources: selected_resources(&[("jira-project", &["PROJ"])]),
        credential_mode: "service".to_string(),
        priority: None,
    }];
    let broker =
        TestBroker::start_with_providers(&config, vec![Arc::new(TestJiraNormalizedWriteProvider)])
            .await;
    let app = broker.app();

    let successful = captured
        .run(app.clone().oneshot(jira_normalized_write_request(
            "agent-req-jira-normalized-write-success",
            "127.0.0.1:43110",
            JIRA_WRITE_SOURCE_SENTINEL,
        )))
        .await
        .unwrap();
    assert_eq!(successful.status(), StatusCode::OK);
    let successful_body = response_json(successful).await;
    assert_eq!(successful_body["decision"], "allow");
    assert_eq!(successful_body["result"]["issue"]["key"], "PROJ-17");
    let successful_body = successful_body.to_string();
    assert!(!successful_body.contains(JIRA_WRITE_SOURCE_SENTINEL));
    assert!(!successful_body.contains(JIRA_WRITE_NATIVE_SENTINEL));

    let failed = captured
        .run(app.oneshot(jira_normalized_write_request(
            "agent-req-jira-normalized-write-failed",
            "127.0.0.1:43111",
            JIRA_WRITE_INVALID_SOURCE_SENTINEL,
        )))
        .await
        .unwrap();
    assert_eq!(failed.status(), StatusCode::BAD_REQUEST);
    let failed_body = response_json(failed).await;
    assert_eq!(failed_body["decision"], "deny");
    assert_eq!(failed_body["reasonCode"], "body_malformed");
    assert!(failed_body.get("objectIds").is_none());
    let failed_body = failed_body.to_string();
    assert!(!failed_body.contains(JIRA_WRITE_INVALID_SOURCE_SENTINEL));
    assert!(!failed_body.contains(JIRA_WRITE_NATIVE_SENTINEL));

    let events = captured.take_events();
    // The capture observed both requests, so the sentinel check covers them.
    for request_id in [
        "agent-req-jira-normalized-write-success",
        "agent-req-jira-normalized-write-failed",
    ] {
        event_by_name_and_agent(&events, "invoke_completed", request_id);
    }
    let serialized_events = serde_json::to_string(&events).unwrap();
    for sentinel in [
        JIRA_WRITE_SOURCE_SENTINEL,
        JIRA_WRITE_INVALID_SOURCE_SENTINEL,
        JIRA_WRITE_NATIVE_SENTINEL,
    ] {
        assert!(!serialized_events.contains(sentinel));
    }

    let audit = std::fs::read_to_string(&audit_path).unwrap();
    for sentinel in [
        JIRA_WRITE_SOURCE_SENTINEL,
        JIRA_WRITE_INVALID_SOURCE_SENTINEL,
        JIRA_WRITE_NATIVE_SENTINEL,
    ] {
        assert!(!audit.contains(sentinel));
    }
    for record in read_audit_records(&audit_path) {
        let object_ids = record.get("objectIds").cloned().unwrap_or(Value::Null);
        let object_ids = object_ids.to_string();
        assert!(!object_ids.contains(JIRA_WRITE_SOURCE_SENTINEL));
        assert!(!object_ids.contains(JIRA_WRITE_INVALID_SOURCE_SENTINEL));
        assert!(!object_ids.contains(JIRA_WRITE_NATIVE_SENTINEL));
    }
}

fn jira_normalized_write_request(request_id: &str, remote: &str, content: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/invoke/jira/issue.create")
        .extension(ConnectInfo(remote.parse::<SocketAddr>().unwrap()))
        .header(REQUEST_ID_HEADER, request_id)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "inputs": {
                    "project": "PROJ",
                    "issueTypeId": "10001",
                    "summary": "Tracing redaction regression",
                    "contentFormat": "markdown",
                    "content": content
                }
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn confluence_normalized_write_content_is_absent_from_tracing_and_audit() {
    let captured = install_trace_capture().start();

    let audit_path = temp_path("confluence-normalized-write-tracing.audit.jsonl");
    let service_username_path = temp_path("confluence-normalized-write-tracing-service-username");
    let service_token_path = temp_path("confluence-normalized-write-tracing-service-token");
    let lookup_username_path = temp_path("confluence-normalized-write-tracing-lookup-username");
    let lookup_token_path = temp_path("confluence-normalized-write-tracing-lookup-token");
    std::fs::write(&service_username_path, "service@example.com").unwrap();
    std::fs::write(&service_token_path, "service-token").unwrap();
    std::fs::write(&lookup_username_path, "lookup@example.com").unwrap();
    std::fs::write(&lookup_token_path, "lookup-token").unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.credentials.service.insert(
        "confluence".to_string(),
        CredentialConfig {
            kind: "basic_api_token".to_string(),
            username_ref: Some(format!("file:{}", service_username_path.display())),
            token_ref: Some(format!("file:{}", service_token_path.display())),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config.credentials.lookup.insert(
        "confluence".to_string(),
        CredentialConfig {
            kind: "basic_api_token".to_string(),
            username_ref: Some(format!("file:{}", lookup_username_path.display())),
            token_ref: Some(format!("file:{}", lookup_token_path.display())),
            provider: None,
            path: None,
            read_only: Some(true),
            credential_name: None,
            profile: None,
        },
    );
    config
        .providers
        .insert(agent_access_confluence::ConfluenceProviderConfig {
            tenant_host: "example.atlassian.net".to_string(),
            cloud_id: None,
            egress_proxy: None,
            allowed_upstream_hosts: vec![
                "https://example.atlassian.net/wiki/api/v2/**".to_string(),
                "https://example.atlassian.net/wiki/rest/api/**".to_string(),
            ],
            attachments: agent_access_provider::AttachmentLimitsConfig::default(),
            content: agent_access_confluence::ConfluenceContentConfig {
                page_formats: vec!["storage".to_string()],
                max_body_bytes: 128,
                ..agent_access_confluence::ConfluenceContentConfig::default()
            },
            search: agent_access_provider::SearchLimitsConfig::default(),
        });
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        execution_contexts: None,
        service: "confluence".to_string(),
        actions: vec!["page.create".to_string()],
        resources: selected_resources(&[("space", &["ENG"])]),
        credential_mode: "service".to_string(),
        priority: None,
    }];
    let broker = TestBroker::start_with_providers(
        &config,
        vec![Arc::new(TestConfluenceNormalizedWriteProvider)],
    )
    .await;
    let app = broker.app();

    let successful = captured
        .run(app.clone().oneshot(confluence_normalized_write_request(
            "agent-req-confluence-normalized-write-success",
            "127.0.0.1:43120",
            CONFLUENCE_WRITE_SOURCE_SENTINEL,
        )))
        .await
        .unwrap();
    assert_eq!(successful.status(), StatusCode::OK);
    let successful_body = response_json(successful).await;
    assert_eq!(successful_body["decision"], "allow");
    assert_eq!(successful_body["result"]["page"]["id"], "9017");
    let successful_body = successful_body.to_string();
    assert!(!successful_body.contains(CONFLUENCE_WRITE_SOURCE_SENTINEL));
    assert!(!successful_body.contains(CONFLUENCE_WRITE_NATIVE_SENTINEL));

    let oversized_content = format!(
        "{}{}",
        CONFLUENCE_WRITE_OVERSIZED_SOURCE_SENTINEL,
        "x".repeat(256)
    );
    let failed = captured
        .run(app.oneshot(confluence_normalized_write_request(
            "agent-req-confluence-normalized-write-failed",
            "127.0.0.1:43121",
            &oversized_content,
        )))
        .await
        .unwrap();
    assert_eq!(failed.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let failed_body = response_json(failed).await;
    assert_eq!(failed_body["decision"], "deny");
    assert_eq!(failed_body["reasonCode"], "body_size_denied");
    assert!(failed_body.get("objectIds").is_none());
    let failed_body = failed_body.to_string();
    assert!(!failed_body.contains(CONFLUENCE_WRITE_OVERSIZED_SOURCE_SENTINEL));
    assert!(!failed_body.contains(CONFLUENCE_WRITE_NATIVE_SENTINEL));

    let events = captured.take_events();
    // The capture observed both requests, so the sentinel check covers them.
    for request_id in [
        "agent-req-confluence-normalized-write-success",
        "agent-req-confluence-normalized-write-failed",
    ] {
        event_by_name_and_agent(&events, "invoke_completed", request_id);
    }
    let serialized_events = serde_json::to_string(&events).unwrap();
    for sentinel in [
        CONFLUENCE_WRITE_SOURCE_SENTINEL,
        CONFLUENCE_WRITE_OVERSIZED_SOURCE_SENTINEL,
        CONFLUENCE_WRITE_NATIVE_SENTINEL,
    ] {
        assert!(!serialized_events.contains(sentinel));
    }

    let audit = std::fs::read_to_string(&audit_path).unwrap();
    for sentinel in [
        CONFLUENCE_WRITE_SOURCE_SENTINEL,
        CONFLUENCE_WRITE_OVERSIZED_SOURCE_SENTINEL,
        CONFLUENCE_WRITE_NATIVE_SENTINEL,
    ] {
        assert!(!audit.contains(sentinel));
    }
    for record in read_audit_records(&audit_path) {
        let object_ids = record.get("objectIds").cloned().unwrap_or(Value::Null);
        let object_ids = object_ids.to_string();
        assert!(!object_ids.contains(CONFLUENCE_WRITE_SOURCE_SENTINEL));
        assert!(!object_ids.contains(CONFLUENCE_WRITE_OVERSIZED_SOURCE_SENTINEL));
        assert!(!object_ids.contains(CONFLUENCE_WRITE_NATIVE_SENTINEL));
    }
}

fn confluence_normalized_write_request(
    request_id: &str,
    remote: &str,
    content: &str,
) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/invoke/confluence/page.create")
        .extension(ConnectInfo(remote.parse::<SocketAddr>().unwrap()))
        .header(REQUEST_ID_HEADER, request_id)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "inputs": {
                    "space": "ENG",
                    "title": "Tracing redaction regression",
                    "contentFormat": "markdown",
                    "content": content
                }
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn gitlab_normalized_write_content_is_absent_from_tracing_and_audit() {
    let captured = install_trace_capture().start();

    let audit_path = temp_path("gitlab-normalized-write-tracing.audit.jsonl");
    let service_token_path = temp_path("gitlab-normalized-write-tracing-service-token");
    let lookup_token_path = temp_path("gitlab-normalized-write-tracing-lookup-token");
    std::fs::write(&service_token_path, "service-token").unwrap();
    std::fs::write(&lookup_token_path, "lookup-token").unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.credentials.service.insert(
        "gitlab".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some(format!("file:{}", service_token_path.display())),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config.credentials.lookup.insert(
        "gitlab".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some(format!("file:{}", lookup_token_path.display())),
            provider: None,
            path: None,
            read_only: Some(true),
            credential_name: None,
            profile: None,
        },
    );
    config
        .providers
        .insert(agent_access_gitlab::GitlabProviderConfig {
            provisioning: agent_access_gitlab::GitlabProvisioningConfig::default(),
            attachments: Default::default(),
            api_base_url: "https://gitlab.example.com/api/v4".to_string(),
            web_base_url: "https://gitlab.example.com".to_string(),
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://gitlab.example.com/api/v4/**".to_string()],
            webhooks: agent_access_gitlab::GitlabWebhooksConfig::default(),
            content: agent_access_gitlab::GitlabContentConfig {
                max_body_bytes: 128,
                ..agent_access_gitlab::GitlabContentConfig::default()
            },
            search: agent_access_provider::SearchLimitsConfig::default(),
        });
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        execution_contexts: None,
        service: "gitlab".to_string(),
        actions: vec!["issue.create".to_string()],
        resources: selected_resources(&[("repository", &["sip/service"])]),
        credential_mode: "service".to_string(),
        priority: None,
    }];
    let broker = TestBroker::start_with_providers(
        &config,
        vec![Arc::new(TestGitlabNormalizedWriteProvider)],
    )
    .await;
    let app = broker.app();

    let successful = captured
        .run(app.clone().oneshot(gitlab_normalized_write_request(
            "agent-req-gitlab-normalized-write-success",
            "127.0.0.1:43130",
            GITLAB_WRITE_SOURCE_SENTINEL,
        )))
        .await
        .unwrap();
    assert_eq!(successful.status(), StatusCode::OK);
    let successful_body = response_json(successful).await;
    assert_eq!(successful_body["decision"], "allow");
    assert_eq!(successful_body["result"]["issue"]["iid"], 17);
    let successful_body = successful_body.to_string();
    assert!(!successful_body.contains(GITLAB_WRITE_SOURCE_SENTINEL));
    assert!(!successful_body.contains(GITLAB_WRITE_NATIVE_SENTINEL));

    let oversized_content = format!(
        "{}{}",
        GITLAB_WRITE_OVERSIZED_SOURCE_SENTINEL,
        "x".repeat(256)
    );
    let failed = captured
        .run(app.oneshot(gitlab_normalized_write_request(
            "agent-req-gitlab-normalized-write-failed",
            "127.0.0.1:43131",
            &oversized_content,
        )))
        .await
        .unwrap();
    assert_eq!(failed.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let failed_body = response_json(failed).await;
    assert_eq!(failed_body["decision"], "deny");
    assert_eq!(failed_body["reasonCode"], "body_size_denied");
    assert!(failed_body.get("objectIds").is_none());
    let failed_body = failed_body.to_string();
    assert!(!failed_body.contains(GITLAB_WRITE_OVERSIZED_SOURCE_SENTINEL));
    assert!(!failed_body.contains(GITLAB_WRITE_NATIVE_SENTINEL));

    let events = captured.take_events();
    // The capture observed both requests, so the sentinel check covers them.
    for request_id in [
        "agent-req-gitlab-normalized-write-success",
        "agent-req-gitlab-normalized-write-failed",
    ] {
        event_by_name_and_agent(&events, "invoke_completed", request_id);
    }
    let serialized_events = serde_json::to_string(&events).unwrap();
    for sentinel in [
        GITLAB_WRITE_SOURCE_SENTINEL,
        GITLAB_WRITE_OVERSIZED_SOURCE_SENTINEL,
        GITLAB_WRITE_NATIVE_SENTINEL,
    ] {
        assert!(!serialized_events.contains(sentinel));
    }

    let audit = std::fs::read_to_string(&audit_path).unwrap();
    for sentinel in [
        GITLAB_WRITE_SOURCE_SENTINEL,
        GITLAB_WRITE_OVERSIZED_SOURCE_SENTINEL,
        GITLAB_WRITE_NATIVE_SENTINEL,
    ] {
        assert!(!audit.contains(sentinel));
    }
    for record in read_audit_records(&audit_path) {
        let object_ids = record.get("objectIds").cloned().unwrap_or(Value::Null);
        let object_ids = object_ids.to_string();
        assert!(!object_ids.contains(GITLAB_WRITE_SOURCE_SENTINEL));
        assert!(!object_ids.contains(GITLAB_WRITE_OVERSIZED_SOURCE_SENTINEL));
        assert!(!object_ids.contains(GITLAB_WRITE_NATIVE_SENTINEL));
    }
}

#[tokio::test]
async fn gitlab_review_failures_preserve_exact_http_contract_without_echoing_content() {
    let audit_path = temp_path("gitlab-review-failure-contract.audit.jsonl");
    let broker = gitlab_review_failure_contract_broker(&audit_path).await;
    let app = broker.app();

    let mutation = app
        .clone()
        .oneshot(gitlab_review_failure_contract_request(
            "agent-req-gitlab-review-mutation-unverified",
            GITLAB_REVIEW_MUTATION_SECRET_SENTINEL,
        ))
        .await
        .unwrap();
    assert_eq!(mutation.status(), StatusCode::CONFLICT);
    let mutation = response_json(mutation).await;
    assert_eq!(mutation["decision"], "error");
    assert_eq!(mutation["reasonCode"], "mutation_verification_failed");
    assert_eq!(
        mutation["result"],
        json!({
            "mutationStatus": "applied_unverified",
            "retrySafe": false,
            "verificationStage": "mutation_readback",
            "safeLocators": {
                "discussionId": "discussion-17",
                "noteId": 29
            }
        })
    );
    assert_eq!(
        mutation["error"]["message"],
        "upstream mutation could not be fully verified"
    );
    assert!(
        !mutation
            .to_string()
            .contains(GITLAB_REVIEW_MUTATION_SECRET_SENTINEL)
    );

    for (request_id, content, expected_category) in [
        (
            "agent-req-gitlab-review-coordinates-unresolved",
            GITLAB_REVIEW_COORDINATES_SECRET_SENTINEL,
            "coordinates_unresolved",
        ),
        (
            "agent-req-gitlab-review-patch-unavailable",
            GITLAB_REVIEW_PATCH_SECRET_SENTINEL,
            "patch_unavailable",
        ),
    ] {
        let position = app
            .clone()
            .oneshot(gitlab_review_failure_contract_request(request_id, content))
            .await
            .unwrap();
        assert_eq!(position.status(), StatusCode::BAD_REQUEST);
        let position = response_json(position).await;
        assert_eq!(position["decision"], "deny");
        assert_eq!(position["reasonCode"], "input_invalid");
        assert_eq!(
            position["result"],
            json!({ "inputCategory": expected_category })
        );
        assert_eq!(position["error"]["message"], "position is invalid");
        assert!(!position.to_string().contains(content));
    }

    let audit = std::fs::read_to_string(audit_path).unwrap();
    for secret in [
        GITLAB_REVIEW_MUTATION_SECRET_SENTINEL,
        GITLAB_REVIEW_COORDINATES_SECRET_SENTINEL,
        GITLAB_REVIEW_PATCH_SECRET_SENTINEL,
    ] {
        assert!(!audit.contains(secret));
    }
}

#[tokio::test]
async fn gitlab_suggestion_apply_direct_http_result_and_audit_are_safe() {
    let audit_path = temp_path("gitlab-suggestion-apply.audit.jsonl");
    let service_token_path = temp_path("gitlab-suggestion-apply-service-token");
    let lookup_token_path = temp_path("gitlab-suggestion-apply-lookup-token");
    std::fs::write(&service_token_path, "service-token").unwrap();
    std::fs::write(&lookup_token_path, "lookup-token").unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.credentials.service.insert(
        "gitlab".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some(format!("file:{}", service_token_path.display())),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config.credentials.lookup.insert(
        "gitlab".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some(format!("file:{}", lookup_token_path.display())),
            provider: None,
            path: None,
            read_only: Some(true),
            credential_name: None,
            profile: None,
        },
    );
    config
        .providers
        .insert(agent_access_gitlab::GitlabProviderConfig {
            provisioning: agent_access_gitlab::GitlabProvisioningConfig::default(),
            attachments: Default::default(),
            api_base_url: "https://gitlab.example.com/api/v4".to_string(),
            web_base_url: "https://gitlab.example.com".to_string(),
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://gitlab.example.com/api/v4/**".to_string()],
            webhooks: agent_access_gitlab::GitlabWebhooksConfig::default(),
            content: agent_access_gitlab::GitlabContentConfig::default(),
            search: agent_access_provider::SearchLimitsConfig::default(),
        });
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        execution_contexts: None,
        service: "gitlab".to_string(),
        actions: vec!["merge_request.suggestion.apply".to_string()],
        resources: selected_resources(&[("repository", &["sip/service"])]),
        credential_mode: "service".to_string(),
        priority: None,
    }];
    let broker = TestBroker::start_with_providers(
        &config,
        vec![Arc::new(TestGitlabSuggestionApplyProvider)],
    )
    .await;
    let app = broker.app();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/gitlab/merge_request.suggestion.apply")
                .extension(ConnectInfo(
                    "127.0.0.1:43134".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-gitlab-suggestion-apply")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"inputs":{
                        "project":"sip/service","iid":5,
                        "expectedHeadSha":"0123456789abcdef0123456789abcdef01234567",
                        "discussionId":"discussion-17","noteId":29,"suggestionId":456,
                        "commitMessage":GITLAB_SUGGESTION_COMMIT_SECRET_SENTINEL
                    }})
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["decision"], "allow");
    assert_eq!(
        body["result"],
        json!({
            "mutationStatus":"applied",
            "retrySafe":false,
            "suggestionIds":[456]
        })
    );
    assert!(
        !body
            .to_string()
            .contains(GITLAB_SUGGESTION_COMMIT_SECRET_SENTINEL)
    );
    assert!(body["result"].get("commitId").is_none());
    assert!(body["result"].get("commitSha").is_none());

    let records = read_audit_records(&audit_path);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["action"], "merge_request.suggestion.apply");
    assert_eq!(records[0]["objectIds"]["suggestionIds"], json!([456]));
    assert!(
        !serde_json::to_string(&records)
            .unwrap()
            .contains(GITLAB_SUGGESTION_COMMIT_SECRET_SENTINEL)
    );
}

async fn gitlab_review_failure_contract_broker(audit_path: &Path) -> TestBroker {
    let service_token_path = temp_path("gitlab-review-failure-contract-service-token");
    let lookup_token_path = temp_path("gitlab-review-failure-contract-lookup-token");
    std::fs::write(&service_token_path, "service-token").unwrap();
    std::fs::write(&lookup_token_path, "lookup-token").unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.credentials.service.insert(
        "gitlab".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some(format!("file:{}", service_token_path.display())),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config.credentials.lookup.insert(
        "gitlab".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some(format!("file:{}", lookup_token_path.display())),
            provider: None,
            path: None,
            read_only: Some(true),
            credential_name: None,
            profile: None,
        },
    );
    config
        .providers
        .insert(agent_access_gitlab::GitlabProviderConfig {
            provisioning: agent_access_gitlab::GitlabProvisioningConfig::default(),
            attachments: Default::default(),
            api_base_url: "https://gitlab.example.com/api/v4".to_string(),
            web_base_url: "https://gitlab.example.com".to_string(),
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://gitlab.example.com/api/v4/**".to_string()],
            webhooks: agent_access_gitlab::GitlabWebhooksConfig::default(),
            content: agent_access_gitlab::GitlabContentConfig::default(),
            search: agent_access_provider::SearchLimitsConfig::default(),
        });
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        execution_contexts: None,
        service: "gitlab".to_string(),
        actions: vec!["merge_request.discussion.inline.add".to_string()],
        resources: selected_resources(&[("repository", &["sip/service"])]),
        credential_mode: "service".to_string(),
        priority: None,
    }];
    TestBroker::start_with_providers(&config, vec![Arc::new(TestGitlabReviewFailureProvider)]).await
}

fn gitlab_review_failure_contract_request(request_id: &str, content: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/invoke/gitlab/merge_request.discussion.inline.add")
        .extension(ConnectInfo(
            "127.0.0.1:43132".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, request_id)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "inputs": {
                    "project": "sip/service",
                    "iid": 5,
                    "expectedHeadSha": "0123456789abcdef0123456789abcdef01234567",
                    "content": content,
                    "contentFormat": "markdown",
                    "position": {
                        "positionType": "text",
                        "oldPath": "src/lib.rs",
                        "newPath": "src/lib.rs",
                        "newLine": 17
                    }
                }
            })
            .to_string(),
        ))
        .unwrap()
}

fn gitlab_normalized_write_request(request_id: &str, remote: &str, content: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/invoke/gitlab/issue.create")
        .extension(ConnectInfo(remote.parse::<SocketAddr>().unwrap()))
        .header(REQUEST_ID_HEADER, request_id)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "inputs": {
                    "project": "sip/service",
                    "title": "Tracing redaction regression",
                    "contentFormat": "plain_text",
                    "content": content
                }
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn discovery_routes_share_source_rate_limits() {
    let mut config = fake_config("");
    config.limits.auth_requests_per_source_per_minute = 1;
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();

    let first = services_request(app.clone(), "127.0.0.1:41010", "agent-req-services-1").await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = services_request(app, "127.0.0.1:41011", "agent-req-services-2").await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let value = response_json(second).await;
    assert_eq!(value["reasonCode"], "rate_limited");
}

#[tokio::test]
async fn unknown_service_discovery_uses_principal_rate_limits() {
    let mut config = fake_config("");
    config.limits.auth_requests_per_principal_per_minute = 1;
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/services/missing")
                .extension(ConnectInfo(
                    "127.0.0.1:41013".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-unknown-service-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::FORBIDDEN);

    let second = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/services/missing")
                .extension(ConnectInfo(
                    "127.0.0.1:41014".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-unknown-service-2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let value = response_json(second).await;
    assert_eq!(value["reasonCode"], "rate_limited");
}

#[tokio::test]
async fn duplicate_forwarded_headers_are_not_trusted() {
    let audit_path = temp_path("duplicate-forwarded.audit.jsonl");
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.network.trusted_proxies = vec!["127.0.0.1".to_string()];
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/fake/echo")
                .extension(ConnectInfo(
                    "127.0.0.1:41012".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "agent-req-duplicate-forwarded")
                .header("X-Forwarded-For", "203.0.113.10")
                .header("X-Forwarded-For", "198.51.100.20")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"inputs":{"project":"TEST","message":"hello"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let record = read_audit_record(&audit_path);
    assert_eq!(record["source"]["remote"], "127.0.0.1:41012");
    assert!(record["source"].get("proxyChain").is_none());
}

#[tokio::test]
async fn readiness_fails_when_credential_material_is_unavailable() {
    let audit_path = temp_path("credential-readiness.audit.jsonl");
    let missing_token = temp_path("missing-service-token");
    let mut config = fake_config(audit_path.to_str().unwrap());
    config
        .credentials
        .service
        .get_mut("fake")
        .unwrap()
        .token_ref = Some(format!("file:{}", missing_token.display()));
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();

    let ready = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    let value = response_json(ready).await;
    assert_eq!(value["status"], "not_ready");
    assert_eq!(value["reason"], "active runtime is not ready");
}

#[test]
fn concurrency_guards_fail_closed_at_configured_limits() {
    let limits = LimitsConfig {
        max_concurrent_requests: 1,
        max_concurrent_requests_per_principal: 1,
        ..LimitsConfig::default()
    };
    let guards = Arc::new(IngressGuards::new());

    let _global = guards
        .try_global_concurrency(limits.max_concurrent_requests)
        .unwrap();
    let error = match guards.try_global_concurrency(limits.max_concurrent_requests) {
        Ok(_) => panic!("expected global concurrency rejection"),
        Err(error) => error,
    };
    assert_eq!(
        error.provider_error().reason_code(),
        ReasonCode::ConcurrencyLimited
    );

    let _principal = guards
        .try_principal_concurrency("anonymous", limits.max_concurrent_requests_per_principal)
        .unwrap();
    let error = match guards
        .try_principal_concurrency("anonymous", limits.max_concurrent_requests_per_principal)
    {
        Ok(_) => panic!("expected principal concurrency rejection"),
        Err(error) => error,
    };
    assert_eq!(
        error.provider_error().reason_code(),
        ReasonCode::ConcurrencyLimited
    );

    let capacity_guards = Arc::new(IngressGuards::new());
    let mut permits = Vec::new();
    for index in 0..8192 {
        permits.push(
            capacity_guards
                .try_principal_concurrency(&format!("principal-{index}"), 1)
                .unwrap(),
        );
    }
    let error = match capacity_guards.try_principal_concurrency("principal-over-capacity", 1) {
        Ok(_) => panic!("expected principal limiter capacity rejection"),
        Err(error) => error,
    };
    assert_eq!(error.kind().as_str(), "limiter_capacity");
    assert_eq!(
        error.provider_error().reason_code(),
        ReasonCode::RateLimited
    );
}

#[tokio::test]
async fn health_and_readiness_report_liveness_and_audit_failures() {
    let not_dir = temp_path("audit-parent-file");
    create_private_dir(&not_dir);
    let audit_path = not_dir.join("audit.jsonl");
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.audit = Some(agent_access_core::AuditConfig::new(
        agent_access_core::AuditStoreType::Jsonl,
        audit_path.display().to_string(),
    ));
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();
    // Startup refuses an unwritable audit store, so the store's directory
    // becomes a file while the broker serves.
    std::fs::remove_dir_all(&not_dir).unwrap();
    std::fs::write(&not_dir, "not a directory").unwrap();

    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let ready = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    let value = response_json(ready).await;
    assert_eq!(value["status"], "not_ready");
}

#[tokio::test]
async fn metrics_endpoint_is_not_exposed() {
    let broker = TestBroker::start_config(&fake_config("")).await;
    let app = broker.app();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/metrics")
                .extension(ConnectInfo(
                    "127.0.0.1:41016".parse::<SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn audit_sink_rotates_and_prunes_retained_files() {
    let dir = temp_path("audit-retention-dir");
    create_private_dir(&dir);
    let audit_path = dir.join("audit.jsonl");
    let old_rotated = dir.join(format!(
        "audit.jsonl.20000101T000000Z.{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&old_rotated, "{}\n").unwrap();
    let old_mtime = FileTime::from_system_time(SystemTime::now() - Duration::from_secs(172800));
    filetime::set_file_mtime(&old_rotated, old_mtime).unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    let audit = config.audit.as_mut().unwrap();
    audit.rotate_bytes = Some(1);
    audit.retention_days = 1;
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();

    let first = invoke_fake(app.clone(), "127.0.0.1:41004", "agent-req-audit-1", &[]).await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = invoke_fake(app, "127.0.0.1:41005", "agent-req-audit-2", &[]).await;
    assert_eq!(second.status(), StatusCode::OK);

    wait_for_path_absent(&old_rotated).await;
    let rotated_count = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            // The broker's audit state lock lives beside the store.
            entry.file_name().to_str().is_some_and(|name| {
                name.starts_with("audit.jsonl.") && name != "audit.jsonl.agent-access.lock"
            })
        })
        .count();
    assert!(rotated_count >= 1);
}

#[tokio::test]
async fn audit_sink_prunes_retained_files_without_rotation() {
    let dir = temp_path("audit-retention-without-rotation-dir");
    create_private_dir(&dir);
    let audit_path = dir.join("audit.jsonl");
    let old_rotated = dir.join(format!(
        "audit.jsonl.20000101T000000Z.{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&old_rotated, "{}\n").unwrap();
    let old_mtime = FileTime::from_system_time(SystemTime::now() - Duration::from_secs(172800));
    filetime::set_file_mtime(&old_rotated, old_mtime).unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.audit.as_mut().unwrap().retention_days = 1;
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();

    let response = invoke_fake(app, "127.0.0.1:41015", "agent-req-audit-prune", &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    wait_for_path_absent(&old_rotated).await;
    let rotated_count = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            // The broker's audit state lock lives beside the store.
            entry.file_name().to_str().is_some_and(|name| {
                name.starts_with("audit.jsonl.") && name != "audit.jsonl.agent-access.lock"
            })
        })
        .count();
    assert_eq!(rotated_count, 0);
}

#[derive(Debug)]
struct TestDownloadProvider {
    invocations: Arc<AtomicUsize>,
    with_stream: bool,
    live_stream: bool,
}

struct TestCredentialVerificationProvider;

struct TestFailingCredentialVerificationProvider;

struct TestLocalCredentialVerificationFailureProvider;

struct TestMultipartProvider;

struct TestJiraParentInvokeProvider;

struct TestJiraReadPresentationProvider {
    scope_resolutions: Arc<AtomicUsize>,
    invocations: Arc<AtomicUsize>,
}

struct TestJiraNormalizedWriteProvider;

struct TestConfluenceNormalizedWriteProvider;

struct TestManagedGitlabCredentialProvider {
    descriptor: ServiceDescriptor,
}

impl agent_access_provider::test_support::DescribedProvider
    for TestManagedGitlabCredentialProvider
{
    fn descriptor(&self) -> ServiceDescriptor {
        self.descriptor.clone()
    }
}

impl TestManagedGitlabCredentialProvider {
    fn local_scopes(
        &self,
        _action: &str,
        _inputs: &Value,
    ) -> Result<ResourceScopes, ProviderError> {
        panic!("management credential fixture must not invoke GitLab actions")
    }
}

#[async_trait::async_trait]
impl Provider for TestManagedGitlabCredentialProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }
    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        panic!("management credential fixture must not invoke GitLab actions")
    }
    async fn verify_execution_credential(
        &self,
        credential: &agent_access_provider::ExecutionCredential,
        correlation: &agent_access_provider::CorrelationContext,
    ) -> Result<Option<agent_access_provider::ProviderCredentialVerification>, ProviderError> {
        assert_eq!(credential.kind().as_str(), "bearer_token");
        let expected_token = match correlation.agent_request_id.as_str() {
            "managed-token-verify-with-policy" => "mallory-token-rotated",
            "managed-user-verify" => "gitlab-token-user-rotated",
            request_id => panic!("unexpected credential verification request: {request_id}"),
        };
        assert_eq!(credential_token(credential), expected_token);
        Ok(Some(
            agent_access_provider::ProviderCredentialVerification::new(
                200,
                1,
                json!({"provider":"gitlab","operation":"credential.verify"}),
            ),
        ))
    }
}

struct TestGitlabNormalizedWriteProvider;

struct TestGitlabReviewFailureProvider;

struct TestGitlabSuggestionApplyProvider;

const JIRA_READ_NATIVE_SENTINEL: &str = "JIRAREADNATIVESENTINEL7F4D21";
const JIRA_WRITE_SOURCE_SENTINEL: &str = "jira-write-source-sentinel-a7f31c";
const JIRA_WRITE_INVALID_SOURCE_SENTINEL: &str = "jira-write-invalid-source-sentinel-b8e42d";
const JIRA_WRITE_NATIVE_SENTINEL: &str = "jira-write-native-adf-sentinel-c9d53e";
const CONFLUENCE_WRITE_SOURCE_SENTINEL: &str = "confluence-write-source-sentinel-d6a41f";
const CONFLUENCE_WRITE_OVERSIZED_SOURCE_SENTINEL: &str =
    "confluence-write-oversized-source-sentinel-e7b52a";
const CONFLUENCE_WRITE_NATIVE_SENTINEL: &str = "confluence-write-native-storage-sentinel-f8c63b";
const GITLAB_WRITE_SOURCE_SENTINEL: &str = "gitlab-write-source-sentinel-a1d74e";
const GITLAB_WRITE_OVERSIZED_SOURCE_SENTINEL: &str =
    "gitlab-write-oversized-source-sentinel-b2e85f";
const GITLAB_WRITE_NATIVE_SENTINEL: &str = "gitlab-write-native-markdown-sentinel-c3f960";
const GITLAB_REVIEW_MUTATION_SECRET_SENTINEL: &str =
    "gitlab-review-mutation-secret-sentinel-d4a071";
const GITLAB_REVIEW_COORDINATES_SECRET_SENTINEL: &str =
    "gitlab-review-coordinates-secret-sentinel-e5b182";
const GITLAB_REVIEW_PATCH_SECRET_SENTINEL: &str = "gitlab-review-patch-secret-sentinel-f6c293";
const GITLAB_SUGGESTION_COMMIT_SECRET_SENTINEL: &str = "gitlab-suggestion-commit-secret-81d2f7";

fn managed_jira_verify_config(
    admin_token_path: &std::path::Path,
    key_path: &std::path::Path,
    store_path: &std::path::Path,
    audit_path: &std::path::Path,
) -> BrokerConfig {
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "local".to_string(),
            kind: "static_principals".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![StaticPrincipalConfig {
                principal: "admin".to_string(),
                token_refs: vec![format!("file:{}", admin_token_path.display())],
            }],
        }],
        groups: vec![IdentityGroupConfig {
            id: "broker-admins".to_string(),
            status: "active".to_string(),
            members: vec!["admin".to_string()],
        }],
    };
    config.management = agent_access_core::ManagementConfig {
        enabled: true,
        admin_principals: vec!["admin".to_string()],
        admin_groups: vec!["broker-admins".to_string()],
        allow_classless_admin_identities: true,
        allow_classless_user_management: false,
        initial_admin: agent_access_core::InitialAdminConfig::default(),
    };
    config.managed_store = Some(agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.credential_encryption = Some(agent_access_core::CredentialEncryptionConfig {
        active_key: "k1".to_string(),
        keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
            id: "k1".to_string(),
            provider: "file".to_string(),
            env: None,
            path: Some(key_path.display().to_string()),
        }],
    });
    config
        .providers
        .insert(agent_access_jira::JiraProviderConfig {
            tenant_host: "example.atlassian.net".to_string(),
            cloud_id: None,
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".to_string()],
            attachments: agent_access_provider::AttachmentLimitsConfig::default(),
            content: agent_access_jira::JiraContentConfig {
                comment_formats: vec!["adf".to_string()],
                ..agent_access_jira::JiraContentConfig::default()
            },
            search: agent_access_provider::SearchLimitsConfig::default(),
            comments: agent_access_jira::JiraCommentsConfig::default(),
            issue_links: agent_access_jira::JiraIssueLinksConfig::default(),
        });
    config.credentials.per_user.insert(
        "jira".to_string(),
        CredentialConfig {
            kind: "managed_store".to_string(),
            username_ref: None,
            token_ref: None,
            provider: None,
            path: None,
            read_only: None,
            credential_name: Some("default".to_string()),
            profile: Some("jira-cloud-api-token".to_string()),
        },
    );
    config
}

fn test_multipart_config() -> BrokerConfig {
    let mut config = download_config("");
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        execution_contexts: None,
        service: "jira".to_string(),
        actions: vec!["attachment.add".to_string()],
        resources: selected_resources(&[("jira-project", &["TEST"])]),
        credential_mode: "service".to_string(),
        priority: None,
    });
    config
}

async fn test_multipart_broker() -> TestBroker {
    TestBroker::start_with_providers(
        &test_multipart_config(),
        vec![Arc::new(TestMultipartProvider)],
    )
    .await
}

impl agent_access_provider::test_support::DescribedProvider for TestJiraParentInvokeProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("jira", "Jira Parent Invoke Provider")
            .with_resource_scopes(fixture_scope_capabilities("project"))
            .with_actions(vec![
                ActionDescriptor::new(
                    "issue.parent.set",
                    "Set Jira issue parent in route tests",
                    json!({
                        "type": "object",
                        "required": ["issue", "parentIssue"],
                        "properties": {
                            "issue": { "type": "string" },
                            "parentIssue": { "type": "string" }
                        },
                        "additionalProperties": false
                    }),
                )
                .scope("project")
                .credential_modes(["service"])
                .lookup(LookupRequirement::ScopeResolution),
                ActionDescriptor::new(
                    "issue.child.create",
                    "Create Jira child issue in route tests",
                    json!({
                        "type": "object",
                        "required": ["project", "issueTypeId", "summary", "parentIssue"],
                        "properties": {
                            "project": { "type": "string" },
                            "issueTypeId": { "type": "string" },
                            "summary": { "type": "string" },
                            "parentIssue": { "type": "string" }
                        },
                        "additionalProperties": false
                    }),
                )
                .scope("project")
                .credential_modes(["service"])
                .lookup(LookupRequirement::ScopeResolution),
            ])
    }
}

impl TestJiraParentInvokeProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if !matches!(action, "issue.parent.set" | "issue.child.create") {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "Jira route test action is not supported",
            ));
        }
        let parent = inputs
            .get("parentIssue")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProviderError::deny(ReasonCode::InputInvalid, "parentIssue is required")
            })?;
        let issues = if action == "issue.parent.set" {
            let issue = inputs.get("issue").and_then(Value::as_str).ok_or_else(|| {
                ProviderError::deny(ReasonCode::InputInvalid, "issue is required")
            })?;
            vec![issue.to_string(), parent.to_string()]
        } else {
            vec![parent.to_string()]
        };
        Ok(ResourceScopes::from([
            ("project".to_string(), vec!["PROJ".to_string()]),
            ("issue".to_string(), issues),
        ]))
    }
}

#[async_trait::async_trait]
impl Provider for TestJiraParentInvokeProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        assert_eq!(
            request.lookup_credential().map(credential_token),
            Some("lookup-token")
        );
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        assert_eq!(
            request
                .execution()
                .static_credential()
                .map(credential_token),
            Some("service-token")
        );
        assert_eq!(
            request.resource_scopes().unwrap()["project"],
            vec!["PROJ".to_string()]
        );
        if request.action() == "issue.child.create" {
            assert_eq!(
                request.resource_scopes().unwrap()["issue"],
                vec!["PROJ-100".to_string()]
            );
            return Ok(ProviderResult::new(json!({
                "operation": "issue.child.create",
                "issue": {
                    "id": "10002",
                    "key": "PROJ-2",
                    "project": "PROJ",
                    "webUrl": "https://example.atlassian.net/browse/PROJ-2"
                },
                "parentIssue": {
                    "id": "10100",
                    "key": "PROJ-100",
                    "project": "PROJ",
                    "webUrl": "https://example.atlassian.net/browse/PROJ-100"
                },
                "verification": { "status": "matched" }
            }))
            .with_audit(json!({
                "provider": "jira",
                "operation": "issue.child.create",
                "issueKey": "PROJ-2",
                "project": "PROJ",
                "parentIssueKey": "PROJ-100",
                "parentProject": "PROJ",
                "verificationStatus": "matched",
            }))
            .with_upstream(Some(201), Some(19))
            .with_object_ids(json!({
                "issueId": "10002",
                "issueKey": "PROJ-2",
                "parentIssueId": "10100",
                "parentIssueKey": "PROJ-100",
            })));
        }
        assert_eq!(
            request.resource_scopes().unwrap()["issue"],
            vec!["PROJ-2".to_string(), "PROJ-100".to_string()]
        );
        Ok(ProviderResult::new(json!({
            "operation": "issue.parent.set",
            "issue": {
                "id": "10002",
                "key": "PROJ-2",
                "project": "PROJ",
                "webUrl": "https://example.atlassian.net/browse/PROJ-2"
            },
            "parentIssue": {
                "id": "10100",
                "key": "PROJ-100",
                "project": "PROJ",
                "webUrl": "https://example.atlassian.net/browse/PROJ-100"
            },
            "verification": { "status": "matched" }
        }))
        .with_audit(json!({
            "provider": "jira",
            "operation": "issue.parent.set",
            "issueKey": "PROJ-2",
            "project": "PROJ",
            "parentIssueKey": "PROJ-100",
            "parentProject": "PROJ",
            "verificationStatus": "matched",
        }))
        .with_upstream(Some(204), Some(17))
        .with_object_ids(json!({
            "issueId": "10002",
            "issueKey": "PROJ-2",
            "parentIssueId": "10100",
            "parentIssueKey": "PROJ-100",
        })))
    }
}

impl agent_access_provider::test_support::DescribedProvider for TestJiraReadPresentationProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let action = |action: &str| {
            ActionDescriptor::new(
                action,
                format!("Jira normalized read test action {action}"),
                json!({
                    "type": "object",
                    "properties": {
                        "issue": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
            )
            .scope("project")
            .credential_modes(["service"])
            .presentation(backend_presentation("jira", action))
        };
        ServiceDescriptor::new("jira", "Jira Normalized Read Test Provider")
            .with_resource_scopes(fixture_scope_capabilities("project"))
            .with_actions(vec![
                action("issue.view"),
                action("issue.update"),
                action("verify"),
            ])
            .with_credentials(CredentialDescriptor::without_execution_credential())
            .with_presentation_body_limit(
                agent_access_jira::JiraContentConfig::default().max_body_bytes,
            )
    }
}

impl TestJiraReadPresentationProvider {
    fn local_scopes(&self, action: &str, _inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        assert!(matches!(action, "issue.view" | "issue.update" | "verify"));
        self.scope_resolutions.fetch_add(1, Ordering::SeqCst);
        Ok(ResourceScopes::from([(
            "project".to_string(),
            vec!["PROJ".to_string()],
        )]))
    }
}

#[async_trait::async_trait]
impl Provider for TestJiraReadPresentationProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        let safe_audit = json!({
            "provider": "jira",
            "operation": request.action(),
            "project": "PROJ"
        });
        if request.action() == "verify" {
            return Err(ProviderError::allow_with_result(
                ReasonCode::VerificationMismatch,
                "Jira verification mismatch",
                json!({
                    "verification": {
                        "status": "mismatch",
                        "checked": [{ "type": "comment", "id": "42" }],
                        "mismatch": { "type": "comment", "id": "43" }
                    },
                    "issueKey": "PROJ-7",
                    "project": "PROJ"
                }),
            )
            .with_audit(safe_audit)
            .with_object_ids(json!({ "issueKey": "PROJ-7" })));
        }
        assert_eq!(request.action(), "issue.view");
        Ok(ProviderResult::new(json!({
            "id": "10007",
            "key": "PROJ-7",
            "project": "PROJ",
            "summary": "Normalized read fixture",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{
                        "type": "text",
                        "text": JIRA_READ_NATIVE_SENTINEL
                    }]
                }]
            },
            "webUrl": "https://example.atlassian.net/browse/PROJ-7"
        }))
        .with_audit(safe_audit)
        .with_upstream(Some(200), Some(5))
        .with_object_ids(json!({ "issueId": "10007", "issueKey": "PROJ-7" })))
    }
}

impl agent_access_provider::test_support::DescribedProvider for TestJiraNormalizedWriteProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("jira", "Jira Normalized Write Test Provider").with_resource_scopes(fixture_scope_capabilities("project")).with_actions(vec![
                ActionDescriptor::new(
                    "issue.create",
                    "Create a Jira issue in normalized write tracing tests",
                    json!({
                        "type": "object",
                        "required": ["project", "issueTypeId", "summary", "contentFormat", "content"],
                        "properties": {
                            "project": { "type": "string" },
                            "issueTypeId": { "type": "string" },
                            "summary": { "type": "string" },
                            "contentFormat": { "type": "string", "enum": ["adf", "markdown", "plain_text"] },
                            "content": { "type": "string" }
                        },
                        "additionalProperties": false
                    }),
                )
                .scope("project")
                .credential_modes(["service"]),
            ])
    }
}

impl TestJiraNormalizedWriteProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if action != "issue.create" {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "Jira normalized write tracing test action is not supported",
            ));
        }
        let project = inputs
            .get("project")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
        Ok(ResourceScopes::from([(
            "project".to_string(),
            vec![project.to_string()],
        )]))
    }
}

#[async_trait::async_trait]
impl Provider for TestJiraNormalizedWriteProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        assert_eq!(request.action(), "issue.create");
        assert_eq!(request.inputs()["contentFormat"], "markdown");
        assert_eq!(
            request
                .execution()
                .static_credential()
                .map(credential_token),
            Some("service-token")
        );
        let source = request.inputs()["content"].as_str().unwrap();
        if source == JIRA_WRITE_INVALID_SOURCE_SENTINEL {
            return Err(ProviderError::deny(
                ReasonCode::BodyMalformed,
                "jira.issue.create markdown content could not be converted",
            )
            .with_audit(json!({
                "provider": "jira",
                "operation": "issue.create",
                "contentFormat": "markdown",
                "nativeFormat": "adf"
            })));
        }
        assert_eq!(source, JIRA_WRITE_SOURCE_SENTINEL);
        let converted_native_body = json!({
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [{ "type": "text", "text": JIRA_WRITE_NATIVE_SENTINEL }]
            }]
        });
        assert_eq!(
            converted_native_body["content"][0]["content"][0]["text"],
            JIRA_WRITE_NATIVE_SENTINEL
        );
        Ok(ProviderResult::new(json!({
            "operation": "issue.create",
            "issue": {
                "id": "10117",
                "key": "PROJ-17",
                "project": "PROJ"
            }
        }))
        .with_audit(json!({
            "provider": "jira",
            "operation": "issue.create",
            "project": "PROJ",
            "issueKey": "PROJ-17",
            "contentFormat": "markdown",
            "nativeFormat": "adf"
        }))
        .with_upstream(Some(201), Some(9))
        .with_object_ids(json!({ "issueId": "10117", "issueKey": "PROJ-17" })))
    }
}

impl agent_access_provider::test_support::DescribedProvider
    for TestConfluenceNormalizedWriteProvider
{
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("confluence", "Confluence Normalized Write Test Provider").with_resource_scopes(fixture_scope_capabilities("space")).with_actions(vec![
                ActionDescriptor::new(
                    "page.create",
                    "Create a Confluence page in normalized write tracing tests",
                    json!({
                        "type": "object",
                        "required": ["space", "title", "contentFormat", "content"],
                        "properties": {
                            "space": { "type": "string" },
                            "title": { "type": "string" },
                            "contentFormat": { "type": "string", "enum": ["storage", "markdown", "plain_text"] },
                            "content": { "type": "string" }
                        },
                        "additionalProperties": false
                    }),
                )
                .scope("space")
                .credential_modes(["service"]),
            ])
    }
}

impl TestConfluenceNormalizedWriteProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if action != "page.create" {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "Confluence normalized write tracing test action is not supported",
            ));
        }
        let space = inputs
            .get("space")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "space is required"))?;
        Ok(ResourceScopes::from([(
            "space".to_string(),
            vec![space.to_string()],
        )]))
    }
}

#[async_trait::async_trait]
impl Provider for TestConfluenceNormalizedWriteProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        assert_eq!(request.action(), "page.create");
        assert_eq!(request.inputs()["contentFormat"], "markdown");
        assert_eq!(
            request
                .execution()
                .static_credential()
                .map(credential_token),
            Some("service-token")
        );
        let source = request.inputs()["content"].as_str().unwrap();
        if source.len() > 128 {
            assert!(source.contains(CONFLUENCE_WRITE_OVERSIZED_SOURCE_SENTINEL));
            return Err(ProviderError::deny(
                ReasonCode::BodySizeDenied,
                "converted Confluence content exceeded the configured byte cap",
            )
            .with_audit(json!({
                "provider": "confluence",
                "operation": "page.create",
                "contentFormat": "markdown",
                "nativeFormat": "storage",
                "sourceBytes": source.len()
            })));
        }
        assert_eq!(source, CONFLUENCE_WRITE_SOURCE_SENTINEL);
        let converted_native_body = format!("<p>{CONFLUENCE_WRITE_NATIVE_SENTINEL}</p>");
        assert!(converted_native_body.contains(CONFLUENCE_WRITE_NATIVE_SENTINEL));
        Ok(ProviderResult::new(json!({
            "operation": "page.create",
            "page": {
                "id": "9017",
                "space": "ENG",
                "title": "Tracing redaction regression"
            }
        }))
        .with_audit(json!({
            "provider": "confluence",
            "operation": "page.create",
            "space": "ENG",
            "pageId": "9017",
            "contentFormat": "markdown",
            "nativeFormat": "storage",
            "sourceBytes": source.len(),
            "nativeBytes": converted_native_body.len()
        }))
        .with_upstream(Some(200), Some(11))
        .with_object_ids(json!({ "pageId": "9017" })))
    }
}

impl agent_access_provider::test_support::DescribedProvider for TestGitlabNormalizedWriteProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("gitlab", "GitLab Normalized Write Test Provider")
            .with_resource_scopes(fixture_scope_capabilities("repository"))
            .with_actions(vec![
            ActionDescriptor::new(
                "issue.create",
                "Create a GitLab issue in normalized write tracing tests",
                json!({
                    "type": "object",
                    "required": ["project", "title", "contentFormat", "content"],
                    "properties": {
                        "project": { "type": "string" },
                        "title": { "type": "string" },
                        "contentFormat": { "type": "string", "enum": ["markdown", "plain_text"] },
                        "content": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
            )
            .scope("repository")
            .credential_modes(["service"]),
        ])
    }
}

impl TestGitlabNormalizedWriteProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if action != "issue.create" {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "GitLab normalized write tracing test action is not supported",
            ));
        }
        let project = inputs
            .get("project")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
        Ok(ResourceScopes::from([(
            "repository".to_string(),
            vec![project.to_string()],
        )]))
    }
}

#[async_trait::async_trait]
impl Provider for TestGitlabNormalizedWriteProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        assert_eq!(request.action(), "issue.create");
        assert_eq!(request.inputs()["contentFormat"], "plain_text");
        assert_eq!(
            request
                .execution()
                .static_credential()
                .map(credential_token),
            Some("service-token")
        );
        let source = request.inputs()["content"].as_str().unwrap();
        if source.len() > 128 {
            assert!(source.contains(GITLAB_WRITE_OVERSIZED_SOURCE_SENTINEL));
            return Err(ProviderError::deny(
                ReasonCode::BodySizeDenied,
                "converted GitLab content exceeded the configured byte cap",
            )
            .with_audit(json!({
                "provider": "gitlab",
                "operation": "issue.create",
                "contentFormat": "plain_text",
                "nativeFormat": "markdown",
                "sourceBytes": source.len()
            })));
        }
        assert_eq!(source, GITLAB_WRITE_SOURCE_SENTINEL);
        let converted_native_body = format!("\\{GITLAB_WRITE_NATIVE_SENTINEL}");
        assert!(converted_native_body.contains(GITLAB_WRITE_NATIVE_SENTINEL));
        Ok(ProviderResult::new(json!({
            "operation": "issue.create",
            "issue": {
                "iid": 17,
                "project": "sip/service",
                "title": "Tracing redaction regression"
            }
        }))
        .with_audit(json!({
            "provider": "gitlab",
            "operation": "issue.create",
            "repository": "sip/service",
            "issueIid": 17,
            "contentFormat": "plain_text",
            "nativeFormat": "markdown",
            "sourceBytes": source.len(),
            "nativeBytes": converted_native_body.len()
        }))
        .with_upstream(Some(201), Some(10))
        .with_object_ids(json!({ "issueIid": 17 })))
    }
}

impl agent_access_provider::test_support::DescribedProvider for TestGitlabReviewFailureProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("gitlab", "GitLab Review Failure Contract Test Provider")
            .with_resource_scopes(fixture_scope_capabilities("repository"))
            .with_actions(vec![
                ActionDescriptor::new(
                    "merge_request.discussion.inline.add",
                    "Return fixed GitLab review failures in HTTP contract tests",
                    json!({
                        "type": "object",
                        "required": [
                            "project", "iid", "expectedHeadSha", "content", "contentFormat",
                            "position"
                        ],
                        "properties": {
                            "project": { "type": "string" },
                            "iid": { "type": "integer", "minimum": 1 },
                            "expectedHeadSha": { "type": "string" },
                            "content": { "type": "string" },
                            "contentFormat": { "type": "string", "enum": ["markdown"] },
                            "position": {
                                "type": "object",
                                "required": ["positionType", "oldPath", "newPath", "newLine"],
                                "properties": {
                                    "positionType": { "const": "text" },
                                    "oldPath": { "type": "string" },
                                    "newPath": { "type": "string" },
                                    "newLine": { "type": "integer", "minimum": 1 }
                                },
                                "additionalProperties": false
                            }
                        },
                        "additionalProperties": false
                    }),
                )
                .scope("repository")
                .credential_modes(["service"]),
            ])
    }
}

impl TestGitlabReviewFailureProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if action != "merge_request.discussion.inline.add" {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "GitLab review failure contract test action is not supported",
            ));
        }
        let project = inputs
            .get("project")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
        Ok(ResourceScopes::from([(
            "repository".to_string(),
            vec![project.to_string()],
        )]))
    }
}

#[async_trait::async_trait]
impl Provider for TestGitlabReviewFailureProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        assert_eq!(request.action(), "merge_request.discussion.inline.add");
        assert_eq!(
            request
                .execution()
                .static_credential()
                .map(credential_token),
            Some("service-token")
        );
        match request.inputs()["content"].as_str().unwrap() {
            GITLAB_REVIEW_MUTATION_SECRET_SENTINEL => Err(ProviderError::error(
                ReasonCode::MutationVerificationFailed,
                "upstream mutation could not be fully verified",
            )
            .with_result(json!({
                "mutationStatus": "applied_unverified",
                "retrySafe": false,
                "verificationStage": "mutation_readback",
                "safeLocators": {
                    "discussionId": "discussion-17",
                    "noteId": 29
                }
            }))),
            GITLAB_REVIEW_COORDINATES_SECRET_SENTINEL => {
                Err(agent_access_gitlab::position_input_invalid(
                    PositionInputCategory::CoordinatesUnresolved,
                ))
            }
            GITLAB_REVIEW_PATCH_SECRET_SENTINEL => {
                Err(agent_access_gitlab::position_input_invalid(
                    PositionInputCategory::PatchUnavailable,
                ))
            }
            content => panic!("unexpected GitLab review failure test content: {content}"),
        }
    }
}

impl agent_access_provider::test_support::DescribedProvider for TestGitlabSuggestionApplyProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("gitlab", "GitLab Suggestion Apply Test Provider").with_resource_scopes(fixture_scope_capabilities("repository")).with_actions(vec![
                ActionDescriptor::new(
                    "merge_request.suggestion.apply",
                    "Apply a scoped GitLab suggestion",
                    json!({
                        "type":"object","additionalProperties":false,
                        "required":["project","iid","expectedHeadSha","discussionId","noteId","suggestionId"],
                        "properties":{
                            "project":{"type":"string"},
                            "iid":{"type":"integer","minimum":1},
                            "expectedHeadSha":{"type":"string"},
                            "discussionId":{"type":"string"},
                            "noteId":{"type":"integer","minimum":1},
                            "suggestionId":{"type":"integer","minimum":1},
                            "commitMessage":{"type":"string"}
                        }
                    }),
                )
                .scope("repository")
                .credential_modes(["service"]),
            ])
    }
}

impl TestGitlabSuggestionApplyProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if action != "merge_request.suggestion.apply" {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "GitLab suggestion test action is not supported",
            ));
        }
        let project = inputs
            .get("project")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
        Ok(ResourceScopes::from([(
            "repository".to_string(),
            vec![project.to_string()],
        )]))
    }
}

#[async_trait::async_trait]
impl Provider for TestGitlabSuggestionApplyProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        assert_eq!(request.action(), "merge_request.suggestion.apply");
        assert_eq!(
            request.inputs()["commitMessage"],
            GITLAB_SUGGESTION_COMMIT_SECRET_SENTINEL
        );
        Ok(ProviderResult::new(json!({
            "mutationStatus":"applied",
            "retrySafe":false,
            "suggestionIds":[456]
        }))
        .with_audit(json!({
            "provider":"gitlab","operation":"merge_request.suggestion.apply",
            "repository":"sip/service","mergeRequestIid":5,"suggestionCount":1
        }))
        .with_upstream(Some(200), Some(5))
        .with_object_ids(json!({
            "mergeRequestIid":5,"suggestionIds":[456]
        })))
    }
}

async fn multipart_upload_request(
    app: Router,
    request_id: &str,
    remote: &str,
    boundary: &str,
    body: String,
) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/invoke/jira/attachment.add")
            .extension(ConnectInfo(remote.parse::<SocketAddr>().unwrap()))
            .header(REQUEST_ID_HEADER, request_id)
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap(),
    )
    .await
    .unwrap()
}

impl agent_access_provider::test_support::DescribedProvider for TestCredentialVerificationProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("jira", "Credential Verification Provider").with_credentials(
            CredentialDescriptor::default().profile("jira-cloud-api-token", "basic_api_token"),
        )
    }
}

impl TestCredentialVerificationProvider {
    fn local_scopes(
        &self,
        _action: &str,
        _inputs: &Value,
    ) -> Result<ResourceScopes, ProviderError> {
        Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "test provider does not invoke actions",
        ))
    }
}

#[async_trait::async_trait]
impl Provider for TestCredentialVerificationProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn verify_execution_credential(
        &self,
        credential: &agent_access_provider::ExecutionCredential,
        _correlation: &agent_access_provider::CorrelationContext,
    ) -> Result<Option<agent_access_provider::ProviderCredentialVerification>, ProviderError> {
        assert_eq!(credential.kind().as_str(), "basic_api_token");
        assert_eq!(credential_username(credential), Some("alice@example.com"));
        assert_eq!(credential_token(credential), "jira-token");
        Ok(Some(
            agent_access_provider::ProviderCredentialVerification::new(
                200,
                1,
                json!({"provider": "jira", "operation": "credential.verify"}),
            ),
        ))
    }

    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "test provider does not invoke actions",
        ))
    }
}

impl agent_access_provider::test_support::DescribedProvider
    for TestFailingCredentialVerificationProvider
{
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("jira", "Failing Credential Verification Provider").with_credentials(
            CredentialDescriptor::default().profile("jira-cloud-api-token", "basic_api_token"),
        )
    }
}

impl TestFailingCredentialVerificationProvider {
    fn local_scopes(
        &self,
        _action: &str,
        _inputs: &Value,
    ) -> Result<ResourceScopes, ProviderError> {
        Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "test provider does not invoke actions",
        ))
    }
}

#[async_trait::async_trait]
impl Provider for TestFailingCredentialVerificationProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn verify_execution_credential(
        &self,
        _credential: &agent_access_provider::ExecutionCredential,
        _correlation: &agent_access_provider::CorrelationContext,
    ) -> Result<Option<agent_access_provider::ProviderCredentialVerification>, ProviderError> {
        Err(ProviderError::error(
            ReasonCode::UpstreamUnauthorized,
            "Jira rejected the selected credential",
        ))
    }

    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "test provider does not invoke actions",
        ))
    }
}

impl agent_access_provider::test_support::DescribedProvider
    for TestLocalCredentialVerificationFailureProvider
{
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("jira", "Local Credential Verification Failure Provider")
            .with_credentials(
                CredentialDescriptor::default().profile("jira-cloud-api-token", "basic_api_token"),
            )
    }
}

impl TestLocalCredentialVerificationFailureProvider {
    fn local_scopes(
        &self,
        _action: &str,
        _inputs: &Value,
    ) -> Result<ResourceScopes, ProviderError> {
        Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "test provider does not invoke actions",
        ))
    }
}

#[async_trait::async_trait]
impl Provider for TestLocalCredentialVerificationFailureProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn verify_execution_credential(
        &self,
        _credential: &agent_access_provider::ExecutionCredential,
        _correlation: &agent_access_provider::CorrelationContext,
    ) -> Result<Option<agent_access_provider::ProviderCredentialVerification>, ProviderError> {
        Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "credential verification input is invalid",
        ))
    }

    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "test provider does not invoke actions",
        ))
    }
}

impl agent_access_provider::test_support::DescribedProvider for TestMultipartProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("jira", "Upload Provider").with_resource_scopes(fixture_scope_capabilities("project")).with_actions(vec![
                ActionDescriptor::new(
                    "attachment.add",
                    "Upload test attachment",
                    json!({
                        "type": "object",
                        "required": ["project"],
                        "properties": {
                            "project": { "type": "string" },
                            "attachments": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["field", "filename", "contentType", "size", "sha256"],
                                    "properties": {
                                        "field": { "type": "string" },
                                        "filename": { "type": "string" },
                                        "contentType": { "type": "string" },
                                        "size": { "type": "integer" },
                                        "sha256": { "type": "string" }
                                    },
                                    "additionalProperties": true
                                }
                            }
                        },
                        "additionalProperties": false
                    }),
                )
                .scope("project")
                .credential_modes(["service"])
                .multipart_upload(attachment_upload_plan(&["project"], None)),
            ]).with_credentials(CredentialDescriptor::without_execution_credential())
    }
}

impl TestMultipartProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if action != "attachment.add" {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "upload action is not supported",
            ));
        }
        let project = inputs
            .get("project")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
        Ok(ResourceScopes::from([(
            "project".to_string(),
            vec![project.to_string()],
        )]))
    }
}

#[async_trait::async_trait]
impl Provider for TestMultipartProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn authorize_body_parts(
        &self,
        request: &AdmittedRequest,
        _state: Option<&ProviderState>,
    ) -> Result<BodyAdmission, ProviderError> {
        if request.action() == "attachment.add" {
            let attachments = request
                .inputs()
                .get("attachments")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    ProviderError::deny(
                        ReasonCode::InputInvalid,
                        "attachments metadata is required",
                    )
                })?;
            let specs = attachments
                .iter()
                .map(|attachment| {
                    Ok(BrokerBodyPartSpec::new(
                        attachment
                            .get("field")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                ProviderError::deny(
                                    ReasonCode::InputInvalid,
                                    "attachment field is required",
                                )
                            })?
                            .to_string(),
                        attachment
                            .get("filename")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                ProviderError::deny(
                                    ReasonCode::InputInvalid,
                                    "attachment filename is required",
                                )
                            })?
                            .to_string(),
                        attachment
                            .get("contentType")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                ProviderError::deny(
                                    ReasonCode::InputInvalid,
                                    "attachment content type is required",
                                )
                            })?
                            .to_string(),
                        attachment
                            .get("size")
                            .and_then(Value::as_u64)
                            .ok_or_else(|| {
                                ProviderError::deny(
                                    ReasonCode::InputInvalid,
                                    "attachment size is required",
                                )
                            })?,
                        attachment
                            .get("sha256")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                ProviderError::deny(
                                    ReasonCode::InputInvalid,
                                    "attachment sha256 is required",
                                )
                            })?
                            .to_string(),
                    ))
                })
                .collect::<Result<Vec<_>, ProviderError>>()?;
            Ok(BodyAdmission::new(specs, StateDisposition::Keep))
        } else {
            Err(ProviderError::deny(
                ReasonCode::BodyFormatUnsupported,
                "action does not accept multipart body parts",
            ))
        }
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        let part = request.body_parts().first().ok_or_else(|| {
            ProviderError::deny(ReasonCode::BodyMalformed, "attachment file part is missing")
        })?;
        let path = part.temp_file_path().ok_or_else(|| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "multipart file part was not spooled",
            )
        })?;
        let read_back = std::fs::read_to_string(path).map_err(|error| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                format!("failed to read spooled multipart file: {error}"),
            )
        })?;
        let mut result = json!({
            "bytesInMemory": part.bytes.len(),
            "tempFileBacked": true,
            "readBack": read_back.trim_end_matches("\r\n"),
            "tempPath": path.display().to_string(),
        });
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .map_err(|error| {
                    ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        format!("failed to stat spooled multipart file: {error}"),
                    )
                })?
                .permissions()
                .mode()
                & 0o777;
            result["tempFileMode"] = json!(format!("{mode:o}"));
        }
        Ok(ProviderResult::new(result).with_audit(json!({
            "provider": "upload",
            "operation": "upload",
            "bytesInMemory": part.bytes.len(),
            "tempFileBacked": true,
        })))
    }
}

impl agent_access_provider::test_support::DescribedProvider for TestDownloadProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("jira", "Download Provider")
            .with_resource_scopes(fixture_scope_capabilities("project"))
            .with_actions(vec![
                ActionDescriptor::new(
                    "attachment.download",
                    "Download test attachment",
                    json!({
                        "type": "object",
                        "required": ["project"],
                        "properties": {
                            "project": { "type": "string" }
                        },
                        "additionalProperties": false
                    }),
                )
                .scope("project")
                .credential_modes(["service"])
                .raw_download(),
            ])
            .with_credentials(CredentialDescriptor::without_execution_credential())
    }
}

impl TestDownloadProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if action != "attachment.download" {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "download action is not supported",
            ));
        }
        let project = inputs
            .get("project")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
        Ok(ResourceScopes::from([(
            "project".to_string(),
            vec![project.to_string()],
        )]))
    }
}

#[async_trait::async_trait]
impl Provider for TestDownloadProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        let project = request
            .resource_scopes()
            .unwrap()
            .get("project")
            .and_then(|values| values.first())
            .cloned()
            .unwrap_or_default();
        let stream = self.with_stream.then(|| {
            if self.live_stream {
                ProviderResultStream::from_stream(
                    "text/plain",
                    stream::iter([
                        Ok(Bytes::from_static(b"download ")),
                        Ok(Bytes::from_static(b"bytes")),
                    ]),
                )
            } else {
                ProviderResultStream::from_bytes("text/plain", b"download bytes".to_vec())
            }
        });
        let mut provider_result = ProviderResult::new(json!({
            "project": project,
            "filename": "evidence.txt",
            "contentType": "text/plain",
            "size": 14,
            "sha256": "metadata-only",
        }))
        .with_audit(json!({
            "provider": "download",
            "operation": "attachment.download",
            "filename": "evidence.txt",
            "size": 14,
        }))
        .with_upstream(Some(200), Some(1))
        .with_object_ids(json!({
            "attachmentId": "att1",
        }));
        provider_result.stream = stream;
        Ok(provider_result)
    }
}

fn download_config(audit_file: &str) -> BrokerConfig {
    let mut config = fake_config(audit_file);
    config
        .providers
        .insert(agent_access_jira::JiraProviderConfig {
            tenant_host: "example.atlassian.net".to_string(),
            cloud_id: None,
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".to_string()],
            attachments: agent_access_provider::AttachmentLimitsConfig {
                media_types: vec!["text/plain".to_string()],
                ..agent_access_provider::AttachmentLimitsConfig::default()
            },
            content: agent_access_jira::JiraContentConfig {
                comment_formats: vec!["adf".to_string()],
                ..agent_access_jira::JiraContentConfig::default()
            },
            search: agent_access_provider::SearchLimitsConfig::default(),
            comments: agent_access_jira::JiraCommentsConfig::default(),
            issue_links: agent_access_jira::JiraIssueLinksConfig::default(),
        });
    config.credentials.service.insert(
        "jira".to_string(),
        CredentialConfig {
            kind: "basic_api_token".to_string(),
            username_ref: Some("env:JIRA_SERVICE_USERNAME".to_string()),
            token_ref: Some("env:JIRA_SERVICE_TOKEN".to_string()),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config.credentials.lookup.insert(
        "jira".to_string(),
        CredentialConfig {
            kind: "basic_api_token".to_string(),
            username_ref: Some("env:JIRA_LOOKUP_USERNAME".to_string()),
            token_ref: Some("env:JIRA_LOOKUP_TOKEN".to_string()),
            provider: None,
            path: None,
            read_only: Some(true),
            credential_name: None,
            profile: None,
        },
    );
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        execution_contexts: None,
        service: "jira".to_string(),
        actions: vec!["attachment.download".to_string()],
        resources: selected_resources(&[("jira-project", &["TEST"])]),
        credential_mode: "service".to_string(),
        priority: None,
    });
    config
}

fn fake_config(audit_file: &str) -> BrokerConfig {
    let audit = (!audit_file.is_empty()).then(|| {
        agent_access_core::AuditConfig::new(audit_store_type_for(Path::new(audit_file)), audit_file)
    });
    let limits = agent_access_core::LimitsConfig {
        upload_spool_dir: temp_path("upload-spool").display().to_string(),
        ..agent_access_core::LimitsConfig::default()
    };
    let key_path = temp_path("identity-inventory-key");
    std::fs::write(
        &key_path,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([19_u8; 32]),
    )
    .unwrap();
    BrokerConfig {
        imports: Default::default(),
        oauth: Default::default(),
        deployment: DeploymentConfig {
            enable_fake_service: true,
            ..DeploymentConfig::default()
        },
        execution_context: None,
        network: agent_access_core::NetworkConfig::default(),
        identity: IdentityConfig {
            trusted_callers: Default::default(),
            mode: "anonymous".to_string(),
            authority: "toml".to_string(),
            sources: vec![],
            groups: vec![],
        },
        credentials: CredentialsConfig {
            imported_modes: Default::default(),
            service: BTreeMap::from([(
                "fake".to_string(),
                CredentialConfig {
                    kind: "bearer_token".to_string(),
                    username_ref: None,
                    token_ref: Some("env:FAKE_SERVICE_TOKEN".to_string()),
                    provider: None,
                    path: None,
                    read_only: None,
                    credential_name: None,
                    profile: None,
                },
            )]),
            per_user: BTreeMap::new(),
            lookup: BTreeMap::new(),
        },
        managed_store: None,
        credential_encryption: Some(agent_access_core::CredentialEncryptionConfig {
            active_key: "fixture".into(),
            keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
                id: "fixture".into(),
                provider: "file".into(),
                env: None,
                path: Some(key_path.display().to_string()),
            }],
        }),
        management: agent_access_core::ManagementConfig::default(),
        broker_tokens: None,
        browser_auth: agent_access_core::BrowserAuthConfig::default(),
        portal: agent_access_core::PortalConfig::default(),
        mcp: Default::default(),
        policy: PolicyConfig {
            resources: fixture_resources(&["default"]),
            resource_groups: vec![],
            authority: "toml".to_string(),
            default_decision: "deny".to_string(),
            grants: vec![PolicyGrantConfig {
                subjects: vec!["group:anonymous".to_string()],
                execution_contexts: None,
                service: "fake".to_string(),
                actions: vec!["echo".to_string()],
                resources: selected_resources(&[("project", &["TEST"])]),
                credential_mode: "service".to_string(),
                priority: None,
            }],
        },
        attribution: Default::default(),
        providers: agent_access_core::ProvidersConfig::new(std::sync::Arc::new(
            crate::backend_registry(),
        ))
        .with(agent_access_fake::FakeProviderConfig::default()),
        gateways: BTreeMap::new(),
        limits,
        audit,
    }
}

struct JiraReadPresentationFixture {
    _broker: TestBroker,
    app: Router,
    scope_resolutions: Arc<AtomicUsize>,
    invocations: Arc<AtomicUsize>,
}

async fn jira_read_presentation_fixture(audit_file: &str) -> JiraReadPresentationFixture {
    let scope_resolutions = Arc::new(AtomicUsize::new(0));
    let invocations = Arc::new(AtomicUsize::new(0));
    let provider = TestJiraReadPresentationProvider {
        scope_resolutions: scope_resolutions.clone(),
        invocations: invocations.clone(),
    };
    let mut config = fake_config(audit_file);
    config.credentials.service.insert(
        "jira".to_string(),
        CredentialConfig {
            kind: "basic_api_token".to_string(),
            username_ref: Some("env:JIRA_READ_TEST_SERVICE_USERNAME".to_string()),
            token_ref: Some("env:JIRA_READ_TEST_SERVICE_TOKEN".to_string()),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config.credentials.lookup.insert(
        "jira".to_string(),
        CredentialConfig {
            kind: "basic_api_token".to_string(),
            username_ref: Some("env:JIRA_READ_TEST_LOOKUP_USERNAME".to_string()),
            token_ref: Some("env:JIRA_READ_TEST_LOOKUP_TOKEN".to_string()),
            provider: None,
            path: None,
            read_only: Some(true),
            credential_name: None,
            profile: None,
        },
    );
    config
        .providers
        .insert(agent_access_jira::JiraProviderConfig {
            tenant_host: "example.atlassian.net".to_string(),
            cloud_id: None,
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".to_string()],
            attachments: agent_access_provider::AttachmentLimitsConfig::default(),
            content: agent_access_jira::JiraContentConfig {
                comment_formats: vec!["adf".to_string()],
                ..agent_access_jira::JiraContentConfig::default()
            },
            search: agent_access_provider::SearchLimitsConfig::default(),
            comments: agent_access_jira::JiraCommentsConfig::default(),
            issue_links: agent_access_jira::JiraIssueLinksConfig::default(),
        });
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        execution_contexts: None,
        service: "jira".to_string(),
        actions: vec![
            "issue.view".to_string(),
            "issue.update".to_string(),
            "verify".to_string(),
        ],
        resources: selected_resources(&[("jira-project", &["PROJ"])]),
        credential_mode: "service".to_string(),
        priority: None,
    });
    let broker = TestBroker::start_with_providers(&config, vec![Arc::new(provider)]).await;
    JiraReadPresentationFixture {
        app: broker.app(),
        _broker: broker,
        scope_resolutions,
        invocations,
    }
}

async fn jira_read_presentation_request(
    app: Router,
    request_id: &str,
    action: &str,
    body: Value,
) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/invoke/jira/{action}"))
            .extension(ConnectInfo(
                "127.0.0.1:43140".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, request_id)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
}

const CONTEXT_CALLER_HEADER: &str = "x-agent-access-caller-authorization";
const CONTEXT_CALLER_AUTH: &str = "Bearer test-context-caller-secret";

fn install_context_caller(config: &mut BrokerConfig) {
    let path = temp_path("context-caller.secret");
    std::fs::write(&path, "test-context-caller-secret").unwrap();
    config.identity.trusted_callers.insert(
        "context_test".into(),
        agent_access_core::TrustedCallerConfig {
            credential_transport: Default::default(),
            username_namespace: None,
            credential_ref: format!("file:{}", path.display()),
            context_mode: agent_access_core::TrustedCallerContextMode::Asserted,
            execution_context: None,
            allowed_execution_contexts: Some(
                config
                    .execution_context
                    .as_ref()
                    .unwrap()
                    .allowed_values
                    .clone(),
            ),
            allow_forwarded_identity: false,
        },
    );
}

fn context_aware_fake_config(audit_file: &str) -> BrokerConfig {
    let mut config = fake_config(audit_file);
    config.execution_context = Some(ExecutionContextConfig {
        allowed_values: vec!["internal".to_string(), "external".to_string()],
        default_context: None,
    });
    config.policy.resources = fixture_resources(
        &config
            .execution_context
            .as_ref()
            .unwrap()
            .allowed_values
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    config.policy.grants[0].execution_contexts = Some(vec!["internal".to_string()]);
    install_context_caller(&mut config);
    config
}

struct GatewayRouterFixture {
    _broker: TestBroker,
    app: Router,
    agent_token: String,
    audit_path: PathBuf,
}

struct SpecAgentFixture {
    _broker: TestBroker,
    app: Router,
    agent_token: String,
}

async fn spec_agent_fixture(allowed_services: &[&str], include_gateway: bool) -> SpecAgentFixture {
    spec_token_fixture_with_restrictions(
        allowed_services,
        include_gateway,
        agent_access_core::BrokerTokenClass::AgentInvoke,
        false,
        None,
    )
    .await
}

async fn spec_agent_fixture_with_restrictions(
    allowed_services: &[&str],
    service_restrictions: serde_json::Value,
) -> SpecAgentFixture {
    spec_token_fixture_with_restrictions(
        allowed_services,
        false,
        agent_access_core::BrokerTokenClass::AgentInvoke,
        false,
        Some(service_restrictions),
    )
    .await
}

async fn spec_token_fixture(
    allowed_services: &[&str],
    include_gateway: bool,
    token_class: agent_access_core::BrokerTokenClass,
    admin_role: bool,
) -> SpecAgentFixture {
    spec_token_fixture_with_restrictions(
        allowed_services,
        include_gateway,
        token_class,
        admin_role,
        None,
    )
    .await
}

async fn spec_token_fixture_with_restrictions(
    allowed_services: &[&str],
    include_gateway: bool,
    token_class: agent_access_core::BrokerTokenClass,
    admin_role: bool,
    service_restrictions: Option<serde_json::Value>,
) -> SpecAgentFixture {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let hash_key_path = temp_path("spec-agent-hash-key");
    let store_path = temp_path("spec-agent-store.sqlite");
    let audit_path = temp_path("spec-agent.audit.jsonl");
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([29_u8; 32])).unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    let managed_store_config = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(managed_store_config.clone());
    config.management = agent_access_core::ManagementConfig {
        enabled: true,
        initial_admin: agent_access_core::InitialAdminConfig::default(),
        ..agent_access_core::ManagementConfig::default()
    };
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        default_agent_invoke_ttl: None,
        default_user_manage_ttl: Some("8h".to_string()),
        default_admin_ttl: None,
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["user:spec-user".to_string()],
        execution_contexts: None,
        service: "fake".to_string(),
        actions: vec!["echo".to_string()],
        resources: selected_resources(&[("project", &["TEST"])]),
        credential_mode: "service".to_string(),
        priority: None,
    }];
    if include_gateway {
        config
            .gateways
            .insert("gitlab_git".to_string(), test_git_gateway_config());
        config.credentials.service.insert(
            "gitlab_git".to_string(),
            CredentialConfig {
                kind: "bearer_token".to_string(),
                username_ref: None,
                token_ref: Some(synthetic_credential_ref()),
                provider: None,
                path: None,
                read_only: None,
                credential_name: None,
                profile: None,
            },
        );
        config.policy.grants.push(PolicyGrantConfig {
            subjects: vec!["user:spec-user".to_string()],
            execution_contexts: None,
            service: "gitlab_git".to_string(),
            actions: vec!["repo.fetch".to_string()],
            resources: selected_resources(&[("repository", &["sip/service"])]),
            credential_mode: "service".to_string(),
            priority: None,
        });
    }
    if allowed_services.contains(&"jira") {
        config.credentials.service.insert(
            "jira".to_string(),
            CredentialConfig {
                kind: "basic_api_token".to_string(),
                username_ref: Some(synthetic_credential_ref()),
                token_ref: Some(synthetic_credential_ref()),
                provider: None,
                path: None,
                read_only: None,
                credential_name: None,
                profile: None,
            },
        );
        config.credentials.lookup.insert(
            "jira".to_string(),
            CredentialConfig {
                kind: "basic_api_token".to_string(),
                username_ref: Some(synthetic_credential_ref()),
                token_ref: Some(synthetic_credential_ref()),
                provider: None,
                path: None,
                read_only: Some(true),
                credential_name: None,
                profile: None,
            },
        );
        config
            .providers
            .insert(agent_access_jira::JiraProviderConfig {
                tenant_host: "example.atlassian.net".to_string(),
                cloud_id: None,
                egress_proxy: None,
                allowed_upstream_hosts: vec![
                    "https://example.atlassian.net/rest/api/3/**".to_string(),
                ],
                attachments: agent_access_provider::AttachmentLimitsConfig::default(),
                content: agent_access_jira::JiraContentConfig {
                    comment_formats: vec!["adf".to_string()],
                    ..agent_access_jira::JiraContentConfig::default()
                },
                search: agent_access_provider::SearchLimitsConfig::default(),
                comments: agent_access_jira::JiraCommentsConfig::default(),
                issue_links: agent_access_jira::JiraIssueLinksConfig::default(),
            });
        config.policy.grants.push(PolicyGrantConfig {
            subjects: vec!["user:spec-user".to_string()],
            execution_contexts: None,
            service: "jira".to_string(),
            actions: vec![
                "issue_type.list".to_string(),
                "issue.create".to_string(),
                "issue.child.create".to_string(),
                "issue.update".to_string(),
                "issue.view".to_string(),
                "search".to_string(),
                "issue.dependency.add".to_string(),
                "issue.parent.set".to_string(),
                "comment.add".to_string(),
                "comment.reply".to_string(),
                "comment.update".to_string(),
                "comment.list".to_string(),
                "comment.view".to_string(),
                "comment.property.list".to_string(),
                "comment.property.get".to_string(),
                "attachment.add".to_string(),
                "attachment.list".to_string(),
                "verify".to_string(),
            ],
            resources: selected_resources(&[("jira-project", &["PROJ"])]),
            credential_mode: "service".to_string(),
            priority: None,
        });
    }
    if allowed_services.contains(&"confluence") {
        config.credentials.service.insert(
            "confluence".to_string(),
            CredentialConfig {
                kind: "basic_api_token".to_string(),
                username_ref: Some(synthetic_credential_ref()),
                token_ref: Some(synthetic_credential_ref()),
                provider: None,
                path: None,
                read_only: None,
                credential_name: None,
                profile: None,
            },
        );
        config.credentials.lookup.insert(
            "confluence".to_string(),
            CredentialConfig {
                kind: "basic_api_token".to_string(),
                username_ref: Some(synthetic_credential_ref()),
                token_ref: Some(synthetic_credential_ref()),
                provider: None,
                path: None,
                read_only: Some(true),
                credential_name: None,
                profile: None,
            },
        );
        config
            .providers
            .insert(agent_access_confluence::ConfluenceProviderConfig {
                tenant_host: "example.atlassian.net".to_string(),
                cloud_id: None,
                egress_proxy: None,
                allowed_upstream_hosts: vec![
                    "https://example.atlassian.net/wiki/api/v2/**".to_string(),
                    "https://example.atlassian.net/wiki/rest/api/**".to_string(),
                ],
                attachments: agent_access_provider::AttachmentLimitsConfig::default(),
                content: agent_access_confluence::ConfluenceContentConfig {
                    page_formats: vec!["storage".to_string(), "atlas_doc_format".to_string()],
                    ..agent_access_confluence::ConfluenceContentConfig::default()
                },
                search: agent_access_provider::SearchLimitsConfig::default(),
            });
        let actions = agent_access_confluence::confluence_descriptor(
            config
                .providers
                .get::<agent_access_confluence::ConfluenceProviderConfig>()
                .unwrap(),
        )
        .actions
        .into_iter()
        .map(|action| action.action)
        .collect();
        config.policy.grants.push(PolicyGrantConfig {
            subjects: vec!["user:spec-user".to_string()],
            execution_contexts: None,
            service: "confluence".to_string(),
            actions,
            resources: selected_resources(&[("space", &["ENG"])]),
            credential_mode: "service".to_string(),
            priority: None,
        });
    }
    if allowed_services.contains(&"gitlab") {
        config.credentials.service.insert(
            "gitlab".to_string(),
            CredentialConfig {
                kind: "bearer_token".to_string(),
                username_ref: None,
                token_ref: Some(synthetic_credential_ref()),
                provider: None,
                path: None,
                read_only: None,
                credential_name: None,
                profile: None,
            },
        );
        config.credentials.lookup.insert(
            "gitlab".to_string(),
            CredentialConfig {
                kind: "bearer_token".to_string(),
                username_ref: None,
                token_ref: Some(synthetic_credential_ref()),
                provider: None,
                path: None,
                read_only: Some(true),
                credential_name: None,
                profile: None,
            },
        );
        config
            .providers
            .insert(agent_access_gitlab::GitlabProviderConfig {
                provisioning: agent_access_gitlab::GitlabProvisioningConfig::default(),
                attachments: Default::default(),
                api_base_url: "https://gitlab.example.com/api/v4".to_string(),
                web_base_url: "https://gitlab.example.com".to_string(),
                egress_proxy: None,
                allowed_upstream_hosts: vec!["https://gitlab.example.com/api/v4/**".to_string()],
                webhooks: agent_access_gitlab::GitlabWebhooksConfig::default(),
                content: agent_access_gitlab::GitlabContentConfig::default(),
                search: agent_access_provider::SearchLimitsConfig::default(),
            });
        let actions = agent_access_gitlab::gitlab_descriptor(
            config
                .providers
                .get::<agent_access_gitlab::GitlabProviderConfig>()
                .unwrap(),
        )
        .actions
        .into_iter()
        .map(|action| action.action)
        .collect();
        config.policy.grants.push(PolicyGrantConfig {
            subjects: vec!["user:spec-user".to_string()],
            execution_contexts: None,
            service: "gitlab".to_string(),
            actions,
            resources: selected_resources(&[("repository", &["sip/service"])]),
            credential_mode: "service".to_string(),
            priority: None,
        });
    }

    let store = agent_access_core::ManagedStore::open(
        &managed_store_config,
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "spec-user".to_string(),
            kind: "user".to_string(),
            display_name: Some("Spec User".to_string()),
            email: None,
            external_subject: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "spec-admin".to_string(),
            kind: "user".to_string(),
            display_name: Some("Spec Admin".to_string()),
            email: None,
            external_subject: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: ("spec-admin").into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("test").into(),
        })
        .unwrap();
    if admin_role {
        store
            .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
                principal_id: ("spec-user").into(),
                role: Some(agent_access_core::PrincipalRole::Admin),
                self_service_enabled: None,
                actor: ("test").into(),
            })
            .unwrap();
    }
    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let mut scopes = if token_class == agent_access_core::BrokerTokenClass::AgentInvoke {
        json!({
            "allowedServices": allowed_services,
            "allowedExecutionContexts": ["default"]
        })
    } else {
        json!({})
    };
    if let Some(service_restrictions) = service_restrictions {
        scopes["serviceRestrictions"] = service_restrictions;
    }
    let issued = store
        .issue_broker_token_with_catalog(
            &hasher,
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: "spec-user".to_string(),
                name: "spec token".to_string(),
                token_class,
                scopes,
                expires_at: None,
                created_by: "test".to_string(),
            },
            Some(&agent_access_core::ManagedResourceCatalog {
                attribute_bindings: Vec::new(),
                resources: config.policy.resources.clone(),
                resource_groups: config.policy.resource_groups.clone(),
            }),
        )
        .unwrap();
    drop(store);

    let broker = TestBroker::start_config(&config).await;
    SpecAgentFixture {
        app: broker.app(),
        _broker: broker,
        agent_token: issued.token,
    }
}

struct ManagedPolicyAdminFixture {
    _broker: TestBroker,
    app: Router,
    admin_token: String,
    audit_path: PathBuf,
}

struct ServicePolicyManagementFixture {
    _broker: TestBroker,
    app: Router,
    admin_token: String,
    alice_user_token: String,
    bob_user_token: String,
}

struct TokenContextFixture {
    _broker: TestBroker,
    state: Arc<ReloadableState>,
    app: Router,
    alice_user_token: String,
    bob_user_token: String,
    admin_token: String,
    corrupt_agent_token: String,
    audit_path: PathBuf,
}

async fn token_context_fixture() -> TokenContextFixture {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let hash_key_path = temp_path("token-context-hash-key");
    let store_path = temp_path("token-context-store.sqlite");
    let audit_path = temp_path("token-context.audit.sqlite");
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([37_u8; 32])).unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.execution_context = Some(ExecutionContextConfig {
        allowed_values: vec![
            "external".to_string(),
            "internal".to_string(),
            "partner".to_string(),
            "workstation".to_string(),
        ],
        default_context: None,
    });
    config.policy.resources = fixture_resources(
        &config
            .execution_context
            .as_ref()
            .unwrap()
            .allowed_values
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    install_context_caller(&mut config);
    let managed_store_config = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(managed_store_config.clone());
    config.management.enabled = true;
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        default_agent_invoke_ttl: None,
        default_user_manage_ttl: Some("8h".to_string()),
        default_admin_ttl: None,
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    config.policy.grants = vec![
        PolicyGrantConfig {
            subjects: vec!["user:alice".to_string()],
            execution_contexts: Some(vec!["external".to_string()]),
            service: "fake".to_string(),
            actions: vec!["echo".to_string()],
            resources: selected_resources(&[("project", &["TEST"])]),
            credential_mode: "service".to_string(),
            priority: None,
        },
        PolicyGrantConfig {
            subjects: vec!["group:operators".to_string()],
            execution_contexts: Some(vec!["internal".to_string()]),
            service: "fake".to_string(),
            actions: vec!["echo".to_string()],
            resources: selected_resources(&[("project", &["OPS"])]),
            credential_mode: "service".to_string(),
            priority: None,
        },
        PolicyGrantConfig {
            subjects: vec!["user:svc-app".to_string()],
            execution_contexts: Some(vec!["external".to_string()]),
            service: "fake".to_string(),
            actions: vec!["echo".to_string()],
            resources: selected_resources(&[("project", &["SVC"])]),
            credential_mode: "service".to_string(),
            priority: None,
        },
        PolicyGrantConfig {
            subjects: vec!["user:alice".to_string()],
            execution_contexts: Some(vec!["partner".to_string()]),
            service: "fake".to_string(),
            actions: vec!["echo".to_string()],
            resources: selected_resources(&[("project", &["PARTNER"])]),
            credential_mode: "service".to_string(),
            priority: None,
        },
    ];
    let store = agent_access_core::ManagedStore::open(
        &managed_store_config,
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    for principal in ["alice", "bob", "admin"] {
        store
            .create_principal(agent_access_core::PrincipalWriteRequest {
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: principal.to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".to_string(),
            })
            .unwrap();
    }
    store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "svc-app".to_string(),
            kind: "service_account".to_string(),
            display_name: Some("Service Application".to_string()),
            email: None,
            external_subject: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    store
        .create_group(agent_access_core::GroupWriteRequest {
            group_id: "operators".to_string(),
            display_name: None,
            description: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    store.add_group("alice", "operators", "test").unwrap();
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: "bob".into(),
            role: Some(agent_access_core::PrincipalRole::ServicePolicyManager),
            self_service_enabled: None,
            actor: "test".into(),
        })
        .unwrap();
    store
        .put_service_policy_management_assignment(
            agent_access_core::ServicePolicyManagementAssignmentPutRequest {
                service: "fake".to_string(),
                principal_id: "bob".to_string(),
                created_by: "test".to_string(),
            },
        )
        .unwrap();
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: ("admin").into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("test").into(),
        })
        .unwrap();
    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issue = |principal: &str, token_class: agent_access_core::BrokerTokenClass| {
        store
            .issue_broker_token(
                &hasher,
                agent_access_core::BrokerTokenIssueRequest {
                    principal_id: principal.to_string(),
                    name: format!("{principal} fixture"),
                    token_class,
                    scopes: json!({}),
                    expires_at: None,
                    created_by: "test".to_string(),
                },
            )
            .unwrap()
            .token
    };
    let alice_user_token = issue("alice", agent_access_core::BrokerTokenClass::UserManage);
    let bob_user_token = issue("bob", agent_access_core::BrokerTokenClass::UserManage);
    let admin_token = issue("admin", agent_access_core::BrokerTokenClass::Admin);
    let _stale_agent_token = store
        .issue_broker_token(
            &hasher,
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: "alice".to_string(),
                name: "stale agent".to_string(),
                token_class: agent_access_core::BrokerTokenClass::AgentInvoke,
                scopes: json!({"allowedExecutionContexts": ["retired"]}),
                expires_at: None,
                created_by: "test".to_string(),
            },
        )
        .unwrap()
        .token;
    let corrupt_agent_token = "aab_ai_corrupt_fixture".to_string();
    let conn = rusqlite::Connection::open(&store_path).unwrap();
    for (token_id, raw_token, name, scopes) in [
        (
            "11111111-1111-4111-8111-111111111111",
            "aab_ai_legacy_fixture",
            "legacy agent",
            json!({}),
        ),
        (
            "22222222-2222-4222-8222-222222222222",
            corrupt_agent_token.as_str(),
            "corrupt agent",
            json!({
                "allowedServices": ["fake"],
                "allowedExecutionContexts": ["internal"],
                "serviceRestrictions": {
                    "fake": {"actions": "echo"}
                }
            }),
        ),
    ] {
        conn.execute(
            "INSERT INTO broker_tokens
             (token_id, token_hash, principal_id, name, token_class, scopes_json, created_at,
              expires_at, revoked_at, revoked_by, last_used_at, created_by)
             VALUES (?1, ?2, 'alice', ?3, 'agent_invoke', ?4, '2026-01-01T00:00:00Z',
                     NULL, NULL, NULL, NULL, 'test')",
            rusqlite::params![
                token_id,
                hasher.hash(raw_token).unwrap(),
                name,
                scopes.to_string()
            ],
        )
        .unwrap();
    }
    drop(conn);
    drop(store);

    let broker = TestBroker::start_config(&config).await;
    let state = broker.state();
    TokenContextFixture {
        app: broker.app(),
        _broker: broker,
        state,
        alice_user_token,
        bob_user_token,
        admin_token,
        corrupt_agent_token,
        audit_path,
    }
}

async fn managed_policy_admin_fixture() -> ManagedPolicyAdminFixture {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let hash_key_path = temp_path("managed-policy-admin-hash-key");
    let store_path = temp_path("managed-policy-admin-store.sqlite");
    let audit_path = temp_path("managed-policy-admin.audit.jsonl");
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([21_u8; 32])).unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    let managed_store_config = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(managed_store_config.clone());
    config.management = agent_access_core::ManagementConfig {
        enabled: true,
        initial_admin: agent_access_core::InitialAdminConfig::default(),
        ..agent_access_core::ManagementConfig::default()
    };
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        default_agent_invoke_ttl: None,
        default_user_manage_ttl: Some("8h".to_string()),
        default_admin_ttl: None,
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    config.policy = PolicyConfig {
        resources: vec![],
        resource_groups: vec![],
        authority: "managed".to_string(),
        default_decision: "deny".to_string(),
        grants: vec![],
    };

    let store = agent_access_core::ManagedStore::open(
        &managed_store_config,
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    seed_managed_fixture_resources(&store);
    store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "admin".to_string(),
            kind: "user".to_string(),
            display_name: Some("Admin".to_string()),
            email: None,
            external_subject: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "nogroups".to_string(),
            kind: "user".to_string(),
            display_name: Some("No Groups".to_string()),
            email: None,
            external_subject: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: ("admin").into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("test").into(),
        })
        .unwrap();
    store
        .create_group(agent_access_core::GroupWriteRequest {
            group_id: "agents".to_string(),
            display_name: Some("Agents".to_string()),
            description: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    store.add_group("admin", "agents", "test").unwrap();
    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issued = store
        .issue_broker_token(
            &hasher,
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: "admin".to_string(),
                name: "admin token".to_string(),
                token_class: agent_access_core::BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "test".to_string(),
            },
        )
        .unwrap();
    drop(store);

    let broker = TestBroker::start_config(&config).await;
    ManagedPolicyAdminFixture {
        app: broker.app(),
        _broker: broker,
        admin_token: issued.token,
        audit_path,
    }
}

async fn service_policy_management_fixture() -> ServicePolicyManagementFixture {
    service_policy_management_fixture_with_policy_authority("managed").await
}

async fn service_policy_management_fixture_with_policy_authority(
    policy_authority: &str,
) -> ServicePolicyManagementFixture {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let hash_key_path = temp_path("service-policy-management-hash-key");
    let store_path = temp_path("service-policy-management-store.sqlite");
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([42_u8; 32])).unwrap();

    let mut config = fake_config("");
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    let managed_store_config = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(managed_store_config.clone());
    config.management.enabled = true;
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        default_agent_invoke_ttl: None,
        default_user_manage_ttl: Some("8h".to_string()),
        default_admin_ttl: None,
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    config.policy = PolicyConfig {
        resources: vec![],
        resource_groups: vec![],
        authority: policy_authority.to_string(),
        default_decision: "deny".to_string(),
        grants: vec![],
    };
    config
        .gateways
        .insert("gitlab_git".to_string(), test_git_gateway_config());
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some("env:GITLAB_GATEWAY_TOKEN".to_string()),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );

    let store = agent_access_core::ManagedStore::open(
        &managed_store_config,
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    if policy_authority == "managed" {
        seed_managed_fixture_resources(&store);
    } else {
        config.policy.resources = fixture_resources(&["default"]);
    }
    for principal in ["admin", "alice", "bob"] {
        store
            .create_principal(agent_access_core::PrincipalWriteRequest {
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: principal.to_string(),
                kind: "user".to_string(),
                display_name: Some(format!("{principal} display")),
                email: None,
                external_subject: None,
                created_by: "test".to_string(),
            })
            .unwrap();
    }
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: ("admin").into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("test").into(),
        })
        .unwrap();
    store
        .create_group(agent_access_core::GroupWriteRequest {
            group_id: "service-managers".to_string(),
            display_name: Some("Service Managers".to_string()),
            description: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    store
        .add_group("alice", "service-managers", "test")
        .unwrap();
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: "bob".into(),
            role: Some(agent_access_core::PrincipalRole::ServicePolicyManager),
            self_service_enabled: None,
            actor: "test".into(),
        })
        .unwrap();
    store
        .put_service_policy_management_assignment(
            agent_access_core::ServicePolicyManagementAssignmentPutRequest {
                service: "retired".to_string(),
                principal_id: "bob".to_string(),
                created_by: "test".to_string(),
            },
        )
        .unwrap();
    if policy_authority != "managed" {
        store
            .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
                principal_id: "bob".into(),
                role: Some(agent_access_core::PrincipalRole::ServicePolicyManager),
                self_service_enabled: None,
                actor: "test".into(),
            })
            .unwrap();
        store
            .put_service_policy_management_assignment(
                agent_access_core::ServicePolicyManagementAssignmentPutRequest {
                    service: "fake".to_string(),
                    principal_id: "bob".to_string(),
                    created_by: "test".to_string(),
                },
            )
            .unwrap();
    }

    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issue = |principal: &str, token_class: agent_access_core::BrokerTokenClass| {
        store
            .issue_broker_token(
                &hasher,
                agent_access_core::BrokerTokenIssueRequest {
                    principal_id: principal.to_string(),
                    name: format!("{principal} fixture"),
                    token_class,
                    scopes: json!({}),
                    expires_at: None,
                    created_by: "test".to_string(),
                },
            )
            .unwrap()
            .token
    };
    let admin_token = issue("admin", agent_access_core::BrokerTokenClass::Admin);
    let alice_user_token = issue("alice", agent_access_core::BrokerTokenClass::UserManage);
    let bob_user_token = issue("bob", agent_access_core::BrokerTokenClass::UserManage);
    drop(store);

    let broker = TestBroker::start_config(&config).await;
    ServicePolicyManagementFixture {
        app: broker.app(),
        _broker: broker,
        admin_token,
        alice_user_token,
        bob_user_token,
    }
}

const RECEIVE_PACK_TEST_OLD: &str = "1111111111111111111111111111111111111111";
const RECEIVE_PACK_TEST_NEW: &str = "2222222222222222222222222222222222222222";

fn receive_pack_test_payload(capabilities: &str) -> Vec<u8> {
    let command = format!(
        "{RECEIVE_PACK_TEST_OLD} {RECEIVE_PACK_TEST_NEW} refs/heads/feature\0{capabilities}"
    );
    let mut payload = receive_pack_test_pkt_line(command.as_bytes());
    payload.extend_from_slice(b"0000");
    payload
}

fn receive_pack_test_pkt_line(payload: &[u8]) -> Vec<u8> {
    let mut packet = format!("{:04x}", payload.len() + 4).into_bytes();
    packet.extend_from_slice(payload);
    packet
}

async fn test_gateway_router() -> GatewayRouterFixture {
    test_gateway_router_with_options(false, &["repo.fetch"]).await
}

async fn test_gateway_router_with_options(
    allow_push: bool,
    grant_actions: &[&str],
) -> GatewayRouterFixture {
    test_gateway_router_with_config(allow_push, grant_actions, |_| {}).await
}

async fn test_gateway_router_with_config<F>(
    allow_push: bool,
    grant_actions: &[&str],
    configure: F,
) -> GatewayRouterFixture
where
    F: FnOnce(&mut BrokerConfig),
{
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let service_token_path = temp_path("gateway-service-token");
    let hash_key_path = temp_path("gateway-hash-key");
    let store_path = temp_path("gateway-store.sqlite");
    let audit_path = temp_path("gateway.audit.jsonl");
    std::fs::write(&service_token_path, "git-service-token").unwrap();
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([17_u8; 32])).unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    let managed_store_config = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(managed_store_config.clone());
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        default_agent_invoke_ttl: None,
        default_user_manage_ttl: Some("8h".to_string()),
        default_admin_ttl: None,
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some(format!("file:{}", service_token_path.display())),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    let mut gateway = test_git_gateway_config();
    gateway.git.as_mut().unwrap().allow_push = allow_push;
    config.gateways.insert("gitlab_git".to_string(), gateway);
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:gateway-user".to_string()],
        execution_contexts: None,
        service: "gitlab_git".to_string(),
        actions: grant_actions
            .iter()
            .map(|action| (*action).to_string())
            .collect(),
        resources: selected_resources(&[("repository", &["sip/service"])]),
        credential_mode: "service".to_string(),
        priority: None,
    });
    configure(&mut config);

    let store = agent_access_core::ManagedStore::open(
        &managed_store_config,
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "gateway-user".to_string(),
            kind: "user".to_string(),
            display_name: Some("Gateway User".to_string()),
            email: None,
            external_subject: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issued = store
        .issue_broker_token(
            &hasher,
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: "gateway-user".to_string(),
                name: "gateway token".to_string(),
                token_class: agent_access_core::BrokerTokenClass::AgentInvoke,
                scopes: json!({
                    "allowedServices": ["gitlab_git"],
                    "allowedExecutionContexts": ["default"]
                }),
                expires_at: None,
                created_by: "test".to_string(),
            },
        )
        .unwrap();
    drop(store);

    let broker = TestBroker::start_with(
        TestBroker::config_builder(&config)
            .gateway_listener()
            .expect("loopback gateway listener"),
    )
    .await;
    GatewayRouterFixture {
        app: broker.gateway_app(),
        _broker: broker,
        agent_token: issued.token,
        audit_path,
    }
}

fn test_git_gateway_config() -> agent_access_core::GatewayConfig {
    agent_access_core::GatewayConfig {
        allow_forwarded_identity: false,
        kind: "git_http".to_string(),
        display_name: "GitLab Git".to_string(),
        broker_hosts: vec!["git.example.test".to_string()],
        upstream_base_url: "https://gitlab.example.com".to_string(),
        allowed_upstream_hosts: vec!["https://blocked.example.com/**".to_string()],
        egress_proxy: None,
        auth_modes: vec!["basic_broker_token".to_string()],
        basic_broker_token_username: "agent-access".to_string(),
        credential_modes: vec!["service".to_string()],
        redirect_policy: "none".to_string(),
        request_body_max_bytes: Some(1024 * 1024),
        response_body_max_bytes: Some(1024 * 1024),
        streaming_idle_timeout_ms: Some(30_000),
        correlation_headers: true,
        git: Some(agent_access_core::GatewayGitConfig {
            allow_fetch: true,
            allow_push: false,
            deny_ref_patterns: vec![],
            deny_delete_refs: true,
            receive_pack_prefix_max_bytes: Some(65_536),
        }),
    }
}

async fn gateway_get(
    app: Router,
    uri: &str,
    host: &str,
    request_id: &str,
    authorization: Option<&str>,
) -> axum::response::Response {
    gateway_request(GatewayRequestSpec {
        app,
        method: Method::GET,
        uri: uri.parse().unwrap(),
        host: Some(host),
        request_id: Some(request_id),
        authorization,
        headers: &[],
        body: Body::empty(),
    })
    .await
}

async fn spec_get(
    app: Router,
    uri: &str,
    request_id: &str,
    token: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .extension(ConnectInfo(
            "127.0.0.1:41081".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, request_id);
    if let Some(token) = token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    app.oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn governed_get(
    app: Router,
    uri: &str,
    request_id: &str,
    headers: &[(&str, &str)],
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .extension(ConnectInfo(
            "127.0.0.1:41082".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, request_id);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    app.oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn catalog_has_route(catalog: &Value, method: &str, route: &str) -> bool {
    catalog["routes"].as_array().unwrap().iter().any(|entry| {
        entry["method"].as_str() == Some(method) && entry["route"].as_str() == Some(route)
    })
}

fn catalog_has_service(catalog: &Value, service: &str) -> bool {
    catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["service"].as_str() == Some(service))
}

fn catalog_has_action(catalog: &Value, service: &str, action: &str) -> bool {
    catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["service"].as_str() == Some(service))
        .and_then(|entry| entry["actions"].as_array())
        .is_some_and(|actions| actions.iter().any(|entry| entry["action"] == action))
}

#[test]
fn jira_capabilities_omit_content_writes_without_a_native_comment_target() {
    let mut config = agent_access_jira::JiraProviderConfig {
        tenant_host: "example.atlassian.net".to_string(),
        cloud_id: None,
        egress_proxy: None,
        allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".to_string()],
        attachments: agent_access_provider::AttachmentLimitsConfig::default(),
        content: agent_access_jira::JiraContentConfig {
            comment_formats: vec![],
            ..agent_access_jira::JiraContentConfig::default()
        },
        search: agent_access_provider::SearchLimitsConfig::default(),
        comments: agent_access_jira::JiraCommentsConfig::default(),
        issue_links: agent_access_jira::JiraIssueLinksConfig::default(),
    };
    let descriptor = agent_access_jira::jira_descriptor(&config);
    for action in ["comment.add", "comment.reply", "comment.update"] {
        assert!(
            descriptor
                .actions
                .iter()
                .all(|candidate| candidate.action != action),
            "{action} was advertised without an enabled ADF target"
        );
    }
    for action in ["issue.create", "issue.child.create", "issue.update"] {
        let schema = &descriptor
            .actions
            .iter()
            .find(|candidate| candidate.action == action)
            .unwrap_or_else(|| panic!("missing hardcoded issue action {action}"))
            .input_schema;
        assert_jira_normalized_content_schema(schema, false);
    }

    config.content.comment_formats = vec!["adf".to_string()];
    let descriptor = agent_access_jira::jira_descriptor(&config);
    for action in ["comment.add", "comment.reply", "comment.update"] {
        let schema = &descriptor
            .actions
            .iter()
            .find(|candidate| candidate.action == action)
            .unwrap_or_else(|| panic!("missing configured comment action {action}"))
            .input_schema;
        assert_jira_normalized_content_schema(schema, true);
    }
}

#[test]
fn confluence_capabilities_advertise_only_effective_content_write_formats() {
    let config = agent_access_confluence::ConfluenceProviderConfig {
        tenant_host: "example.atlassian.net".to_string(),
        cloud_id: None,
        egress_proxy: None,
        allowed_upstream_hosts: vec![
            "https://example.atlassian.net/wiki/api/v2/**".to_string(),
            "https://example.atlassian.net/wiki/rest/api/**".to_string(),
        ],
        attachments: agent_access_provider::AttachmentLimitsConfig::default(),
        content: agent_access_confluence::ConfluenceContentConfig {
            page_formats: vec![],
            blog_formats: vec![],
            comment_formats: vec![],
            max_body_bytes: 2 * 1024 * 1024,
        },
        search: agent_access_provider::SearchLimitsConfig::default(),
    };

    let descriptor = agent_access_confluence::confluence_descriptor(&config);
    for action in CONFLUENCE_NORMALIZED_WRITE_ACTIONS {
        let advertised = descriptor
            .actions
            .iter()
            .find(|candidate| candidate.action == *action);
        if action.starts_with("page.draft.") {
            let schema = &advertised
                .unwrap_or_else(|| panic!("missing hardcoded storage action {action}"))
                .input_schema;
            assert_eq!(
                schema["properties"]["contentFormat"]["enum"],
                json!(["storage", "markdown", "plain_text"])
            );
        } else {
            assert!(
                advertised.is_none(),
                "{action} advertised without an enabled native target"
            );
        }
    }

    let mut atlas_only = config.clone();
    atlas_only.content.page_formats = vec!["atlas_doc_format".to_string()];
    let descriptor = agent_access_confluence::confluence_descriptor(&atlas_only);
    for action in ["page.create", "page.update"] {
        let schema = &descriptor
            .actions
            .iter()
            .find(|candidate| candidate.action == action)
            .unwrap_or_else(|| panic!("missing atlas-only action {action}"))
            .input_schema;
        assert_eq!(
            schema["properties"]["contentFormat"]["enum"],
            json!(["atlas_doc_format"])
        );
    }

    let mut all_native = config;
    all_native.content.page_formats = vec!["storage".to_string(), "atlas_doc_format".to_string()];
    all_native.content.blog_formats = vec!["storage".to_string()];
    all_native.content.comment_formats = vec!["storage".to_string()];
    let descriptor = agent_access_confluence::confluence_descriptor(&all_native);
    for action in CONFLUENCE_NORMALIZED_WRITE_ACTIONS {
        let schema = &descriptor
            .actions
            .iter()
            .find(|candidate| candidate.action == *action)
            .unwrap_or_else(|| panic!("missing fully configured action {action}"))
            .input_schema;
        assert_confluence_normalized_content_schema(schema, action);
    }
}

fn assert_jira_normalized_content_schema(schema: &Value, content_required: bool) {
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["contentFormat"]["enum"],
        json!(["adf", "markdown", "plain_text"])
    );
    assert!(schema["properties"].get("content").is_some());
    for removed in ["body", "bodyFormat", "description", "descriptionFormat"] {
        assert!(
            schema["properties"].get(removed).is_none(),
            "legacy property {removed} survived"
        );
    }

    let all_of = schema["allOf"].as_array().expect("content schema allOf");
    assert!(all_of.iter().any(|branch| {
        branch["if"]["properties"]["contentFormat"]["const"] == "adf"
            && branch["then"]["properties"]["content"]["type"] == "object"
    }));
    assert!(all_of.iter().any(|branch| {
        branch["if"]["properties"]["contentFormat"]["enum"] == json!(["markdown", "plain_text"])
            && branch["then"]["properties"]["content"]["type"] == "string"
    }));

    let required = schema["required"]
        .as_array()
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if content_required {
        assert!(required.contains(&"content"));
        assert!(required.contains(&"contentFormat"));
    } else {
        assert!(!required.contains(&"content"));
        assert!(!required.contains(&"contentFormat"));
        assert!(all_of.iter().any(|branch| {
            branch["oneOf"].as_array().is_some_and(|variants| {
                variants
                    .iter()
                    .any(|variant| variant["required"] == json!(["content", "contentFormat"]))
            })
        }));
    }
}

const CONFLUENCE_NORMALIZED_WRITE_ACTIONS: &[&str] = &[
    "page.create",
    "page.update",
    "blog.create",
    "blog.update",
    "page.draft.create",
    "page.draft.stage",
    "page.draft.update",
    "blog.draft.create",
    "blog.draft.stage",
    "blog.draft.update",
    "page.footer_comment.add",
    "page.footer_comment.update",
    "page.footer_comment.reply.add",
    "page.inline_comment.update",
    "page.inline_comment.reply.add",
    "blog.footer_comment.add",
    "blog.footer_comment.update",
    "blog.footer_comment.reply.add",
    "blog.inline_comment.update",
    "blog.inline_comment.reply.add",
];

fn assert_confluence_normalized_content_schema(schema: &Value, action: &str) {
    assert_eq!(schema["type"], "object", "wrong type for {action}");
    assert_eq!(
        schema["additionalProperties"], false,
        "open inputs for {action}"
    );
    let expected_formats = if matches!(action, "page.create" | "page.update") {
        json!(["storage", "atlas_doc_format", "markdown", "plain_text"])
    } else {
        json!(["storage", "markdown", "plain_text"])
    };
    assert_eq!(
        schema["properties"]["contentFormat"]["enum"], expected_formats,
        "wrong format enum for {action}"
    );
    assert!(schema["properties"].get("content").is_some());
    for removed in ["body", "bodyFormat", "description", "descriptionFormat"] {
        assert!(
            schema["properties"].get(removed).is_none(),
            "legacy property {removed} survived on {action}"
        );
    }

    let required = schema["required"]
        .as_array()
        .expect("Confluence write schemas require content")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(
        required.contains(&"content"),
        "content optional on {action}"
    );
    assert!(
        required.contains(&"contentFormat"),
        "contentFormat optional on {action}"
    );

    let all_of = schema["allOf"].as_array().expect("content schema allOf");
    for format in expected_formats.as_array().unwrap() {
        let format = format.as_str().unwrap();
        let expected_type = if format == "atlas_doc_format" {
            "object"
        } else {
            "string"
        };
        assert!(all_of.iter().any(|branch| {
            branch["if"]["properties"]["contentFormat"]["const"] == format
                && branch["then"]["properties"]["content"]["type"] == expected_type
        }));
    }
}

const GITLAB_NORMALIZED_WRITE_ACTIONS: &[&str] = &[
    "issue.create",
    "issue.update",
    "issue.note.add",
    "issue.note.update",
    "merge_request.create",
    "merge_request.update",
    "merge_request.note.add",
    "merge_request.note.update",
    "merge_request.discussion.add",
    "merge_request.discussion.inline.add",
    "merge_request.discussion.note.add",
    "merge_request.discussion.note.update",
    "merge_request.draft_note.add",
    "merge_request.draft_note.update",
    "merge_request.draft_note.publish_all",
    "merge_request.review.submit",
];

const GITLAB_M1_REVIEW_READ_ACTIONS: &[&str] = &[
    "merge_request.reviewer.list",
    "merge_request.commit.list",
    "merge_request.pipeline.list",
    "merge_request.diff.list",
    "merge_request.diff.raw.download",
    "merge_request.diff_version.list",
    "merge_request.diff_version.view",
    "merge_request.discussion.list",
    "merge_request.discussion.view",
];

const GITLAB_M2_REVIEW_ACTIONS: &[&str] = &[
    "merge_request.discussion.inline.add",
    "merge_request.discussion.note.add",
    "merge_request.draft_note.list",
    "merge_request.draft_note.view",
    "merge_request.draft_note.add",
    "merge_request.draft_note.update",
    "merge_request.draft_note.delete",
    "merge_request.draft_note.publish",
    "merge_request.draft_note.publish_all",
    "merge_request.review.submit",
];

const GITLAB_M3_REVIEW_ACTIONS: &[&str] = &[
    "merge_request.approval.view",
    "merge_request.approval_state.view",
    "merge_request.approval_rule.list",
    "merge_request.approval_rule.view",
    "merge_request.approve",
    "merge_request.unapprove",
    "merge_request.suggestion.apply",
    "merge_request.suggestion.batch_apply",
];

fn gitlab_content_is_required(action: &str) -> bool {
    !matches!(
        action,
        "issue.create"
            | "issue.update"
            | "merge_request.create"
            | "merge_request.update"
            | "merge_request.draft_note.update"
            | "merge_request.draft_note.publish_all"
            | "merge_request.review.submit"
    )
}

fn assert_gitlab_normalized_content_schema(schema: &Value, content_required: bool) {
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["contentFormat"]["enum"],
        json!(["markdown", "plain_text"])
    );
    assert_eq!(schema["properties"]["content"]["type"], "string");
    for removed in ["body", "bodyFormat", "description", "descriptionFormat"] {
        assert!(
            schema["properties"].get(removed).is_none(),
            "legacy property {removed} survived"
        );
    }

    let required = schema["required"]
        .as_array()
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if content_required {
        assert!(required.contains(&"content"));
        assert!(required.contains(&"contentFormat"));
    } else {
        assert!(!required.contains(&"content"));
        assert!(!required.contains(&"contentFormat"));
        let all_of = schema["allOf"].as_array().expect("content schema allOf");
        assert!(all_of.iter().any(|branch| {
            branch["oneOf"]
                .as_array()
                .or_else(|| branch["anyOf"].as_array())
                .is_some_and(|variants| {
                    variants
                        .iter()
                        .any(|variant| variant["required"] == json!(["content", "contentFormat"]))
                })
        }));
    }
}

fn catalog_action<'a>(catalog: &'a Value, service: &str, action: &str) -> &'a Value {
    catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["service"].as_str() == Some(service))
        .and_then(|entry| entry["actions"].as_array())
        .and_then(|actions| actions.iter().find(|entry| entry["action"] == action))
        .unwrap_or_else(|| panic!("missing catalog action {service}.{action}"))
}

fn assert_jira_read_response_capability_matrix(
    catalog: &Value,
    openapi: &Value,
    send_schema: &Value,
) {
    const EMBEDDED: &[&str] = &[
        "comment.add",
        "comment.reply",
        "comment.update",
        "comment.view",
        "issue.create",
        "issue.update",
        "issue.view",
    ];
    const WHOLE: &[&str] = &[
        "attachment.list",
        "comment.list",
        "comment.property.get",
        "comment.property.list",
        "comment.view",
        "issue.view",
        "issue_type.list",
        "search",
        "verify",
    ];

    let jira_actions = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "jira")
        .and_then(|service| service["actions"].as_array())
        .expect("Jira catalog actions");
    let embedded = jira_actions
        .iter()
        .filter(|action| action.get("readContentFormats").is_some())
        .map(|action| action["action"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let whole = jira_actions
        .iter()
        .filter(|action| action.get("responseFormats").is_some())
        .map(|action| action["action"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(embedded, EMBEDDED.iter().copied().collect());
    assert_eq!(whole, WHOLE.iter().copied().collect());
    let owners = jira_actions
        .iter()
        .filter_map(|action| {
            Some((
                action["action"].as_str()?,
                action.get("renderedBodyOwners")?.clone(),
            ))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        owners,
        std::collections::BTreeMap::from([
            ("comment.add", json!(["/result/comment"])),
            ("comment.reply", json!(["/result/comment"])),
            ("comment.update", json!(["/result/comment"])),
            ("comment.view", json!(["/result/comment"])),
            ("issue.create", json!(["/result/issue"])),
            ("issue.update", json!(["/result/issue"])),
            ("issue.view", json!(["/result"])),
        ])
    );

    for action in jira_actions {
        let action_name = action["action"].as_str().unwrap();
        let expected_read = EMBEDDED.contains(&action_name);
        let expected_whole = WHOLE.contains(&action_name);
        assert_optional_format_enum(
            action.get("readContentFormats"),
            expected_read,
            json!(["native", "markdown", "text"]),
            &format!("catalog jira.{action_name} readContentFormats"),
        );
        assert_optional_format_enum(
            action.get("responseFormats"),
            expected_whole,
            json!(["json", "markdown"]),
            &format!("catalog jira.{action_name} responseFormats"),
        );

        let request_content = &openapi["paths"][format!("/v1/invoke/jira/{action_name}")]["post"]["requestBody"]
            ["content"];
        let request_properties = if request_content.get("application/json").is_some() {
            &request_content["application/json"]["schema"]["properties"]
        } else {
            &request_content["multipart/form-data"]["schema"]["properties"]["request"]["contentSchema"]
                ["properties"]
        };
        assert_eq!(
            request_properties["readContentFormat"]["enum"],
            if expected_read {
                json!(["native", "markdown", "text"])
            } else {
                json!(["native"])
            },
            "OpenAPI jira.{action_name} readContentFormat"
        );
        assert_eq!(
            request_properties["responseFormat"]["enum"],
            if expected_whole {
                json!(["json", "markdown"])
            } else {
                json!(["json"])
            },
            "OpenAPI jira.{action_name} responseFormat"
        );
        let send_properties = &send_action_variant(send_schema, "jira", action_name)["properties"];
        assert_eq!(
            send_properties["readContentFormat"]["enum"],
            if expected_read {
                json!(["native", "markdown", "text"])
            } else {
                json!(["native"])
            },
            "send schema jira.{action_name} readContentFormat"
        );
        assert_eq!(
            send_properties["responseFormat"]["enum"],
            if expected_whole {
                json!(["json", "markdown"])
            } else {
                json!(["json"])
            },
            "send schema jira.{action_name} responseFormat"
        );
        assert_eq!(
            send_action_variant(send_schema, "jira", action_name)["additionalProperties"],
            false,
            "send invoke envelope must be closed for jira.{action_name}"
        );
    }
}

fn assert_gitlab_read_response_capability_matrix(
    catalog: &Value,
    openapi: &Value,
    send_schema: &Value,
) {
    const EMBEDDED: &[&str] = &[
        "issue.create",
        "issue.note.add",
        "issue.note.list",
        "issue.note.update",
        "issue.note.view",
        "issue.search",
        "issue.update",
        "issue.view",
        "merge_request.create",
        "merge_request.discussion.add",
        "merge_request.discussion.inline.add",
        "merge_request.discussion.list",
        "merge_request.discussion.view",
        "merge_request.discussion.note.add",
        "merge_request.discussion.note.update",
        "merge_request.discussion.reopen",
        "merge_request.discussion.resolve",
        "merge_request.draft_note.list",
        "merge_request.draft_note.view",
        "merge_request.draft_note.add",
        "merge_request.draft_note.update",
        "merge_request.note.add",
        "merge_request.note.list",
        "merge_request.note.update",
        "merge_request.note.view",
        "merge_request.search",
        "merge_request.update",
        "merge_request.view",
    ];
    const WHOLE: &[&str] = &[
        "branch.list",
        "branch.view",
        "commit.list",
        "commit.view",
        "file.view",
        "issue.note.list",
        "issue.note.view",
        "issue.search",
        "issue.view",
        "job.list",
        "job.view",
        "merge_request.discussion.list",
        "merge_request.discussion.view",
        "merge_request.reviewer.list",
        "merge_request.commit.list",
        "merge_request.pipeline.list",
        "merge_request.diff.list",
        "merge_request.diff_version.list",
        "merge_request.diff_version.view",
        "merge_request.draft_note.list",
        "merge_request.draft_note.view",
        "merge_request.approval.view",
        "merge_request.approval_state.view",
        "merge_request.approval_rule.list",
        "merge_request.approval_rule.view",
        "merge_request.note.list",
        "merge_request.note.view",
        "merge_request.search",
        "merge_request.view",
        "pipeline.list",
        "pipeline.view",
        "project.view",
        "protected_branch.list",
        "protected_branch.verify",
        "protected_branch.view",
    ];

    let actions = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "gitlab")
        .and_then(|service| service["actions"].as_array())
        .expect("GitLab catalog actions");
    let embedded = actions
        .iter()
        .filter(|action| action.get("readContentFormats").is_some())
        .map(|action| action["action"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let whole = actions
        .iter()
        .filter(|action| action.get("responseFormats").is_some())
        .map(|action| action["action"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(embedded, EMBEDDED.iter().copied().collect());
    assert_eq!(whole, WHOLE.iter().copied().collect());

    for action_name in [
        "issue.note.list",
        "merge_request.note.list",
        "merge_request.discussion.list",
        "merge_request.draft_note.list",
    ] {
        let action = actions
            .iter()
            .find(|action| action["action"] == action_name)
            .expect("GitLab projected list action");
        for projection in [
            &action["inputSchema"]["properties"]["projection"],
            &openapi["paths"][format!("/v1/invoke/gitlab/{action_name}")]["post"]["requestBody"]["content"]
                ["application/json"]["schema"]["properties"]["inputs"]["properties"]["projection"],
            &send_action_variant(send_schema, "gitlab", action_name)["properties"]["inputs"]["properties"]
                ["projection"],
        ] {
            assert_eq!(projection["enum"], json!(["full", "summary"]));
            assert_eq!(projection["default"], "full");
        }
    }

    let raw_diff = actions
        .iter()
        .find(|action| action["action"] == "merge_request.diff.raw.download")
        .expect("raw merge request diff action");
    assert_eq!(raw_diff["io"]["type"], "raw_download");
    assert_eq!(raw_diff["responseKind"], "raw_stream");
    assert_eq!(raw_diff["exitPolicy"], "raw_stream");
    assert!(raw_diff.get("readContentFormats").is_none());
    assert!(raw_diff.get("responseFormats").is_none());
    let raw_diff_operation =
        &openapi["paths"]["/v1/invoke/gitlab/merge_request.diff.raw.download"]["post"];
    assert!(
        raw_diff_operation["responses"]["200"]["content"]
            .get("application/octet-stream")
            .is_some()
    );
    assert!(
        raw_diff_operation["responses"]["200"]["content"]
            .get("application/json")
            .is_none()
    );
    let raw_diff_send =
        send_action_variant(send_schema, "gitlab", "merge_request.diff.raw.download");
    assert_eq!(
        raw_diff_send["properties"]["responseMode"]["const"],
        "stream"
    );
    assert_eq!(raw_diff_send["x-agent-access-response-kind"], "raw_stream");
    assert_eq!(raw_diff_send["x-agent-access-exit-policy"], "raw_stream");
    let raw_diff_required = raw_diff_send["required"]
        .as_array()
        .expect("raw diff send required fields");
    assert!(
        raw_diff_required
            .iter()
            .any(|value| value == "responseMode")
    );
    assert!(raw_diff_required.iter().any(|value| value == "output"));

    for action in actions {
        let action_name = action["action"].as_str().unwrap();
        let expected_read = EMBEDDED.contains(&action_name);
        let expected_whole = WHOLE.contains(&action_name);
        assert_optional_format_enum(
            action.get("readContentFormats"),
            expected_read,
            json!(["native", "markdown", "text"]),
            &format!("catalog gitlab.{action_name} readContentFormats"),
        );
        assert_optional_format_enum(
            action.get("responseFormats"),
            expected_whole,
            json!(["json", "markdown"]),
            &format!("catalog gitlab.{action_name} responseFormats"),
        );

        let request_content = &openapi["paths"][format!("/v1/invoke/gitlab/{action_name}")]["post"]
            ["requestBody"]["content"];
        let request_properties = if request_content.get("application/json").is_some() {
            &request_content["application/json"]["schema"]["properties"]
        } else {
            &request_content["multipart/form-data"]["schema"]["properties"]["request"]["contentSchema"]
                ["properties"]
        };
        assert_eq!(
            request_properties["readContentFormat"]["enum"],
            if expected_read {
                json!(["native", "markdown", "text"])
            } else {
                json!(["native"])
            },
            "OpenAPI gitlab.{action_name} readContentFormat"
        );
        assert_eq!(
            request_properties["responseFormat"]["enum"],
            if expected_whole {
                json!(["json", "markdown"])
            } else {
                json!(["json"])
            },
            "OpenAPI gitlab.{action_name} responseFormat"
        );

        let send_variant = send_action_variant(send_schema, "gitlab", action_name);
        let send_properties = &send_variant["properties"];
        assert_eq!(
            send_properties["readContentFormat"]["enum"],
            if expected_read {
                json!(["native", "markdown", "text"])
            } else {
                json!(["native"])
            },
            "send schema gitlab.{action_name} readContentFormat"
        );
        assert_eq!(
            send_properties["responseFormat"]["enum"],
            if expected_whole {
                json!(["json", "markdown"])
            } else {
                json!(["json"])
            },
            "send schema gitlab.{action_name} responseFormat"
        );
        assert_eq!(
            send_variant["additionalProperties"], false,
            "send invoke envelope must be closed for gitlab.{action_name}"
        );
    }

    for action_name in GITLAB_M1_REVIEW_READ_ACTIONS
        .iter()
        .chain(GITLAB_M2_REVIEW_ACTIONS)
        .chain(GITLAB_M3_REVIEW_ACTIONS)
    {
        let catalog_inputs = &catalog_action(catalog, "gitlab", action_name)["inputSchema"];
        assert_eq!(
            catalog_inputs["additionalProperties"], false,
            "catalog input schema must be closed for gitlab.{action_name}"
        );

        let request_content = &openapi["paths"][format!("/v1/invoke/gitlab/{action_name}")]["post"]
            ["requestBody"]["content"];
        let openapi_inputs = if request_content.get("application/json").is_some() {
            &request_content["application/json"]["schema"]["properties"]["inputs"]
        } else {
            &request_content["multipart/form-data"]["schema"]["properties"]["request"]["contentSchema"]
                ["properties"]["inputs"]
        };
        assert_eq!(
            openapi_inputs, catalog_inputs,
            "catalog and OpenAPI diverged for gitlab.{action_name}"
        );

        let send_inputs =
            &send_action_variant(send_schema, "gitlab", action_name)["properties"]["inputs"];
        assert_eq!(
            send_inputs, catalog_inputs,
            "catalog and send schema diverged for gitlab.{action_name}"
        );
    }

    for action_name in GITLAB_M2_REVIEW_ACTIONS
        .iter()
        .chain(GITLAB_M3_REVIEW_ACTIONS)
    {
        let action = catalog_action(catalog, "gitlab", action_name);
        assert_eq!(action["io"]["type"], "json");
        assert_eq!(action["responseKind"], "response_envelope");
        assert_eq!(action["exitPolicy"], "invoke_decision");
    }

    let approve = &catalog_action(catalog, "gitlab", "merge_request.approve")["inputSchema"];
    assert_eq!(approve["additionalProperties"], false);
    assert_eq!(approve["properties"]["headSha"]["type"], "string");
    assert!(approve["properties"].get("approvalPassword").is_none());

    let batch =
        &catalog_action(catalog, "gitlab", "merge_request.suggestion.batch_apply")["inputSchema"];
    assert_eq!(batch["additionalProperties"], false);
    assert_eq!(batch["properties"]["suggestions"]["minItems"], 1);
    assert_eq!(batch["properties"]["suggestions"]["maxItems"], 100);
    assert_eq!(batch["properties"]["suggestions"]["uniqueItems"], true);
    assert_eq!(
        batch["properties"]["suggestions"]["items"]["additionalProperties"],
        false
    );
}

fn assert_optional_format_enum(
    actual: Option<&Value>,
    expected_present: bool,
    expected: Value,
    context: &str,
) {
    if expected_present {
        assert_eq!(actual, Some(&expected), "{context}");
    } else {
        assert!(actual.is_none(), "{context} must be absent, got {actual:?}");
    }
}

fn send_action_variant<'a>(schema: &'a Value, service: &str, action: &str) -> &'a Value {
    schema["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| {
            variant["properties"]["service"]["const"].as_str() == Some(service)
                && variant["properties"]["action"]["const"].as_str() == Some(action)
        })
        .unwrap_or_else(|| panic!("missing send schema action {service}.{action}"))
}

fn send_schema_has_action(schema: &Value, service: &str, action: &str) -> bool {
    schema["oneOf"].as_array().unwrap().iter().any(|variant| {
        variant["properties"]["service"]["const"].as_str() == Some(service)
            && variant["properties"]["action"]["const"].as_str() == Some(action)
    })
}

struct GatewayRequestSpec<'a> {
    app: Router,
    method: Method,
    uri: Uri,
    host: Option<&'a str>,
    request_id: Option<&'a str>,
    authorization: Option<&'a str>,
    headers: &'a [(&'a str, &'a str)],
    body: Body,
}

async fn gateway_request(spec: GatewayRequestSpec<'_>) -> axum::response::Response {
    let GatewayRequestSpec {
        app,
        method,
        uri,
        host,
        request_id,
        authorization,
        headers,
        body,
    } = spec;
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(
            "127.0.0.1:41080".parse::<SocketAddr>().unwrap(),
        ));
    if let Some(request_id) = request_id {
        builder = builder.header(REQUEST_ID_HEADER, request_id);
    }
    if let Some(host) = host {
        builder = builder.header("Host", host);
    }
    if let Some(authorization) = authorization {
        builder = builder.header(AUTHORIZATION, authorization);
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    app.oneshot(builder.body(body).unwrap()).await.unwrap()
}

fn temp_path(name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("agent-access-broker-{}", uuid::Uuid::new_v4()));
    create_private_dir(&dir);
    dir.join(name)
}

fn create_private_dir(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

async fn invoke_fake(
    app: Router,
    remote: &str,
    request_id: &str,
    headers: &[(&str, &str)],
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/v1/invoke/fake/echo")
        .extension(ConnectInfo(remote.parse::<SocketAddr>().unwrap()))
        .header(REQUEST_ID_HEADER, request_id)
        .header("Content-Type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    app.oneshot(
        builder
            .body(Body::from(
                r#"{"inputs":{"project":"TEST","message":"hello"}}"#,
            ))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn invoke_fake_project(
    app: Router,
    remote: &str,
    request_id: &str,
    project: &str,
) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/invoke/fake/echo")
            .extension(ConnectInfo(remote.parse::<SocketAddr>().unwrap()))
            .header(REQUEST_ID_HEADER, request_id)
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"inputs":{{"project":"{project}","message":"hello"}}}}"#
            )))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn admin_request(
    app: Router,
    method: Method,
    uri: &str,
    request_id: Option<&str>,
    token: Option<&str>,
) -> axum::response::Response {
    admin_request_with_remote(app, method, uri, request_id, token, "127.0.0.1:43000").await
}

async fn admin_request_with_remote(
    app: Router,
    method: Method,
    uri: &str,
    request_id: Option<&str>,
    token: Option<&str>,
    remote: &str,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(remote.parse::<SocketAddr>().unwrap()));
    if let Some(request_id) = request_id {
        builder = builder.header(REQUEST_ID_HEADER, request_id);
    }
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    app.oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn services_request(app: Router, remote: &str, request_id: &str) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method(Method::GET)
            .uri("/v1/services")
            .extension(ConnectInfo(remote.parse::<SocketAddr>().unwrap()))
            .header(REQUEST_ID_HEADER, request_id)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
}

// Behavior tests perform real filesystem work and runtime construction under
// parallel suite load. Use production admission budgets; deadline-specific
// tests set explicit reload and shutdown timeouts on their test brokers.
/// A test broker serving the configuration file at `config_path`.
async fn reload_test_broker(
    config_path: PathBuf,
    body_hard_cap: Option<u64>,
) -> anyhow::Result<TestBroker> {
    let application = TestBroker::builder_at(config_path);
    TestBroker::try_start_with(match body_hard_cap {
        Some(body_hard_cap) => application.body_hard_cap(body_hard_cap),
        None => application,
    })
    .await
}

fn write_reload_config(
    config_path: &Path,
    project: &str,
    audit_path: &Path,
    service_token: &Path,
    spool_dir: &Path,
    max_http_body_bytes: u64,
) {
    write_reload_config_with_extra_limits(
        config_path,
        project,
        audit_path,
        service_token,
        spool_dir,
        max_http_body_bytes,
        "",
    );
}

fn write_reload_config_with_source_rate(
    config_path: &Path,
    project: &str,
    audit_path: &Path,
    service_token: &Path,
    spool_dir: &Path,
    max_http_body_bytes: u64,
    auth_requests_per_source_per_minute: u32,
) {
    write_reload_config_with_extra_limits(
        config_path,
        project,
        audit_path,
        service_token,
        spool_dir,
        max_http_body_bytes,
        &format!("auth_requests_per_source_per_minute = {auth_requests_per_source_per_minute}\n"),
    );
}

fn write_reload_config_with_extra_limits(
    config_path: &Path,
    project: &str,
    audit_path: &Path,
    service_token: &Path,
    spool_dir: &Path,
    max_http_body_bytes: u64,
    extra_limits: &str,
) {
    let admin_token = config_path.with_extension("admin-token");
    std::fs::write(&admin_token, "admin-token").unwrap();
    let config = format!(
        r#"[deployment]
environment = "test"
enable_fake_service = true

[providers.fake]

[identity]
mode = "optional"
authority = "toml"

[[identity.sources]]
name = "reload-admin"
type = "static_principals"
header = "Authorization"
scheme = "Bearer"

[[identity.sources.principals]]
principal = "admin"
token_refs = ["file:{admin_token}"]

[[identity.groups]]
id = "broker-admins"
status = "active"
members = ["admin"]

[management]
enabled = true
admin_principals = ["admin"]
admin_groups = ["broker-admins"]
allow_classless_admin_identities = true

[credentials.service.fake]
type = "bearer_token"
token_ref = "file:{service_token}"

[policy]
authority = "toml"
default_decision = "deny"

[[policy.resources]]
id = "reload-project"
resource_type = "fake_project"
selector = {{ kind = "exact", value = "{project}" }}
allowed_execution_contexts = ["default"]

[[policy.grants]]
subjects = ["group:anonymous"]
service = "fake"
actions = ["echo"]
resources = {{ resource_ids = ["reload-project"] }}
credential_mode = "service"

[limits]
max_http_body_bytes = {max_http_body_bytes}
upload_spool_dir = "{spool_dir}"
{extra_limits}

[audit]
type = "{audit_type}"
path = "{audit_path}"
"#,
        admin_token = admin_token.display(),
        service_token = service_token.display(),
        spool_dir = spool_dir.display(),
        audit_type = audit_store_type_for(audit_path).as_str(),
        audit_path = audit_path.display(),
        extra_limits = extra_limits,
    );
    std::fs::write(config_path, config).unwrap();
}

fn write_reload_config_with_managed_store(
    config_path: &Path,
    project: &str,
    audit_path: &Path,
    service_token: &Path,
    spool_dir: &Path,
    max_http_body_bytes: u64,
    managed_store_path: &Path,
) {
    let key_path = config_path.with_extension("identity-key");
    std::fs::write(
        &key_path,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([19_u8; 32]),
    )
    .unwrap();
    write_reload_config_with_extra_limits(
        config_path,
        project,
        audit_path,
        service_token,
        spool_dir,
        max_http_body_bytes,
        &format!(
            r#"
[managed_store]
type = "sqlite"
path = "{}"
auto_migrate = true
[credential_encryption]
active_key="fixture"
[[credential_encryption.keys]]
id="fixture"
provider="file"
path="{}"
"#,
            managed_store_path.display(),
            key_path.display()
        ),
    );
}

fn event_by_name_and_agent<'a>(
    events: &'a [Value],
    name: &str,
    agent_request_id: &str,
) -> &'a Value {
    events
        .iter()
        .find(|event| {
            string_field(event, "event") == Some(name)
                && string_field(event, "agentRequestId") == Some(agent_request_id)
        })
        .unwrap_or_else(|| panic!("event {name} for {agent_request_id} is captured in {events:?}"))
}

fn string_field<'a>(event: &'a Value, field: &str) -> Option<&'a str> {
    event.get(field).and_then(Value::as_str)
}

fn number_field(event: &Value, field: &str) -> Option<u64> {
    event.get(field).and_then(Value::as_u64)
}

struct JsonVisitor<'a>(&'a mut BTreeMap<String, Value>);

impl Visit for JsonVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0
            .insert(field.name().to_string(), Value::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(
            field.name().to_string(),
            Value::String(format!("{value:?}")),
        );
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0
            .insert(field.name().to_string(), Value::Number(value.into()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0
            .insert(field.name().to_string(), Value::Number(value.into()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_string(), Value::Bool(value));
    }
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn wait_for_path_absent(path: &Path) {
    for _ in 0..100 {
        if !path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!path.exists(), "{} still exists", path.display());
}

fn assert_no_secret_storage_fields(value: &Value) {
    const FORBIDDEN_KEYS: &[&str] = &[
        "keyId",
        "secretBackend",
        "secretRef",
        "materialVersion",
        "secretCiphertext",
        "secretNonce",
    ];
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                assert!(
                    !FORBIDDEN_KEYS.contains(&key.as_str()),
                    "secret storage field leaked: {key}"
                );
                assert_no_secret_storage_fields(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                assert_no_secret_storage_fields(child);
            }
        }
        _ => {}
    }
}

async fn authed_json_request(
    app: Router,
    method: Method,
    uri: impl Into<String>,
    request_id: &str,
    auth_header: &str,
    auth_value: impl Into<String>,
    body: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri.into())
        .extension(ConnectInfo(
            "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, request_id)
        .header(auth_header, auth_value.into());
    if body.is_some() {
        builder = builder.header("Content-Type", "application/json");
    }
    let body = body
        .map(|value| Body::from(value.to_string()))
        .unwrap_or_else(Body::empty);
    app.oneshot(builder.body(body).unwrap()).await.unwrap()
}

async fn invoke_fake_project_with_token(
    app: Router,
    request_id: &str,
    token: &str,
    project: &str,
) -> axum::response::Response {
    let body = json!({"inputs": {"project": project, "message": request_id}}).to_string();
    authed_json_request(
        app,
        Method::POST,
        "/v1/invoke/fake/echo",
        request_id,
        "Authorization",
        format!("Bearer {token}"),
        Some(&body),
    )
    .await
}

async fn authed_context_json_request(
    app: Router,
    method: Method,
    uri: &str,
    request_id: &str,
    token: &str,
    execution_context: &str,
    body: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(
            "127.0.0.1:43101".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, request_id)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(EXECUTION_CONTEXT_HEADER, execution_context)
        .header(CONTEXT_CALLER_HEADER, CONTEXT_CALLER_AUTH);
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    app.oneshot(
        builder
            .body(body.map_or_else(Body::empty, |value| Body::from(value.to_string())))
            .unwrap(),
    )
    .await
    .unwrap()
}

/// The audit backend a test path selects: `*.sqlite` paths use the SQLite
/// backend and every other path JSONL, so a test switches backends by its
/// audit file name alone.
fn audit_store_type_for(path: &Path) -> agent_access_core::AuditStoreType {
    if path
        .extension()
        .is_some_and(|extension| extension == "sqlite")
    {
        agent_access_core::AuditStoreType::Sqlite
    } else {
        agent_access_core::AuditStoreType::Jsonl
    }
}

fn read_audit_records(path: &Path) -> Vec<Value> {
    agent_access_core::test_support::read_audit_records(audit_store_type_for(path), path)
}

/// The stored records as JSONL text, whichever backend `path` selects.
fn read_audit_text(path: &Path) -> String {
    agent_access_core::test_support::read_audit_text(audit_store_type_for(path), path)
}

/// Whether `record` is the audit record of a configuration reload, which a
/// test broker's real reload path appends.
fn is_config_reload_record(record: &Value) -> bool {
    record["service"] == "broker" && record["action"] == "config.reload"
}

/// The records at `path` other than configuration reload records.
fn read_audit_records_without_reloads(path: &Path) -> Vec<Value> {
    read_audit_records(path)
        .into_iter()
        .filter(|record| !is_config_reload_record(record))
        .collect()
}

fn read_audit_record(path: &Path) -> Value {
    read_audit_records(path).into_iter().next().unwrap()
}

#[tokio::test]
async fn token_issuance_waits_for_policy_coordinator_and_all_concurrent_requests_succeed() {
    let fixture = token_context_fixture().await;
    let guard = fixture.state.policy_mutation_lock.lock().await;
    let queued = fixture
        .state
        .token_store_call_from_snapshot(fixture.state.current(), |runtime| {
            Ok(runtime.policy_generation())
        });
    tokio::pin!(queued);
    assert!(matches!(
        futures_util::poll!(&mut queued),
        std::task::Poll::Pending
    ));
    let first = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/tokens",
        "queued-token-first",
        "Authorization",
        format!("Bearer {}", fixture.alice_user_token),
        Some(
            r#"{"name":"first","allowedServices":["fake"],"allowedExecutionContexts":["external"]}"#,
        ),
    );
    let second = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/tokens",
        "queued-token-second",
        "Authorization",
        format!("Bearer {}", fixture.alice_user_token),
        Some(
            r#"{"name":"second","allowedServices":["fake"],"allowedExecutionContexts":["external"]}"#,
        ),
    );
    tokio::pin!(first, second);
    // Poll both requests while holding the coordinator; neither may reject contention.
    assert!(matches!(
        futures_util::poll!(&mut first),
        std::task::Poll::Pending
    ));
    assert!(matches!(
        futures_util::poll!(&mut second),
        std::task::Poll::Pending
    ));
    drop(guard);
    let (first, second, queued) = tokio::join!(first, second, queued);
    queued.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    let first = response_json(first).await;
    let second = response_json(second).await;
    assert_ne!(
        first["result"]["record"]["tokenId"],
        second["result"]["record"]["tokenId"]
    );
}

mod managed_identity;

mod imports_management;

// Real descriptors in discovery fixtures need locally usable credential material.
fn synthetic_credential_ref() -> String {
    let path = temp_path("discovery-credential");
    std::fs::write(&path, "synthetic-discovery-credential").unwrap();
    format!("file:{}", path.display())
}
