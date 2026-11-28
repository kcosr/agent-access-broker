//! Access key types through the production router: the complete setting
//! on an account and on a group, the resolved policy an account's detail
//! reports, the audit of every change, its effect on tokens that already
//! exist, and the reload checks that keep saved references configured.

use super::audit_query::{AuditFixture, Backend, audit_fixture_with};
use super::*;
use crate::handlers::management::admin::{committed_group_mutation, committed_principal_mutation};
use crate::handlers::management::common::{
    ManagementAccess, ManagementContext, management_context, management_write_audit_preflight,
};
use crate::state::AppState;
use agent_access_core::{
    AccessKeyRefusal, AccessKeyTypeConfig, AccessKeyTypesWrite, AdministratorAccessKeyRequest,
    GroupAccessKeyTypes, GroupWriteRequest, PrincipalAccessKeyTypes, PrincipalAccessPatchRequest,
    TrustedCallerConfig, TrustedCallerContextMode, http_route_specs,
};
use axum::http::{HeaderMap, HeaderValue};

const CALLER_HEADER: &str = "x-agent-access-caller-authorization";
const RESOLVER: &str = "Bearer access-resolver-credential-0123456789";

/// `batch`, `inference` and `packages` are configured, a trusted caller may
/// resolve keys, and `robot` is a service account.
async fn fixture() -> AuditFixture {
    let secret = temp_path("access-key-types-caller");
    std::fs::write(&secret, RESOLVER.strip_prefix("Bearer ").unwrap()).unwrap();
    let fixture = audit_fixture_with(Backend::Sqlite, |config, _| {
        for (id, display_name) in [
            ("batch", "Batch jobs"),
            ("inference", "Model inference"),
            ("packages", "Package mirrors"),
        ] {
            config.access_key_types.insert(
                id.to_string(),
                AccessKeyTypeConfig {
                    display_name: display_name.to_string(),
                    description: None,
                    lifetime_options: vec!["1s".into(), "1h".into(), "30d".into()],
                    default_lifetime: "30d".into(),
                    self_service: id != "batch",
                },
            );
        }
        config.identity.trusted_callers.insert(
            "proxy".to_string(),
            TrustedCallerConfig {
                credential_ref: format!("file:{}", secret.display()),
                credential_transport: Default::default(),
                username_namespace: None,
                context_mode: TrustedCallerContextMode::Fixed,
                execution_context: Some("default".to_string()),
                allowed_execution_contexts: None,
                allow_forwarded_identity: false,
                allow_access_key_resolution: true,
            },
        );
    })
    .await;
    store(&fixture)
        .create_principal(
            PrincipalWriteRequest {
                agent_token_issuance: Default::default(),
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: Some(false),
                principal_id: "robot".to_string(),
                kind: "service_account".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            },
            &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
        .unwrap();
    fixture
}

fn store(fixture: &AuditFixture) -> agent_access_core::ManagedStore {
    fixture.broker.runtime().managed_store().unwrap().clone()
}

/// An administrator's request.
async fn admin(
    fixture: &AuditFixture,
    method: Method,
    uri: &str,
    body: Option<Value>,
    request_id: &str,
) -> (StatusCode, Value) {
    fixture
        .request(
            method,
            &fixture.admin,
            uri,
            body.map(|body| body.to_string()).as_deref(),
            request_id,
        )
        .await
}

/// The `result` of an administrator's successful request. A result the
/// catalog publishes a schema for must satisfy it.
async fn ok(
    fixture: &AuditFixture,
    method: Method,
    uri: &str,
    body: Option<Value>,
    request_id: &str,
) -> Value {
    let (status, envelope) = admin(fixture, method, uri, body, request_id).await;
    assert_eq!(status, StatusCode::OK, "{uri}: {envelope}");
    let operation = envelope["operation"].as_str().unwrap();
    let routes = http_route_specs(fixture.broker.runtime().resource_types());
    if let Some(schema) = routes
        .iter()
        .find(|route| route.operation == operation)
        .and_then(|route| route.result_schema.as_ref())
    {
        let validator = jsonschema::validator_for(schema).unwrap();
        let errors = validator
            .iter_errors(&envelope["result"])
            .map(|error| format!("{}: {error}", error.instance_path()))
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "{operation}: {errors:?}");
    }
    envelope["result"].clone()
}

async fn set_account(fixture: &AuditFixture, principal: &str, access: Value, request_id: &str) {
    let result = ok(
        fixture,
        Method::PATCH,
        &format!("/v1/admin/principals/{principal}/access"),
        Some(json!({ "accessKeyTypes": access })),
        request_id,
    )
    .await;
    assert_eq!(result["accessKeyTypes"], access, "{request_id}");
}

async fn set_group(fixture: &AuditFixture, group: &str, access: Value, request_id: &str) {
    let result = ok(
        fixture,
        Method::PATCH,
        &format!("/v1/admin/groups/{group}"),
        Some(json!({ "accessKeyTypes": access })),
        request_id,
    )
    .await;
    assert_eq!(result["accessKeyTypes"], access, "{request_id}");
}

/// The account's detail: its configured setting and what it resolves to.
async fn detail(fixture: &AuditFixture, principal: &str) -> (Value, Value) {
    let detail = ok(
        fixture,
        Method::GET,
        &format!("/v1/admin/principals/{principal}"),
        None,
        "access-key-types-detail",
    )
    .await;
    (
        detail["accessKeyTypes"].clone(),
        detail["accessKeyTypePolicy"].clone(),
    )
}

fn decision(access_key_type: &str, allowed: bool, source: &str, groups: &[&str]) -> Value {
    json!({"accessKeyType": access_key_type, "allowed": allowed, "source": source, "groupIds": groups})
}

/// What the completion record of `request_id` says about its target, once
/// the mutation's owner has written it.
async fn completion(fixture: &AuditFixture, request_id: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(event) = fixture.records().into_iter().find(|event| {
                event["agentRequestId"] == request_id
                    && event["providerAudit"]["management"]["phase"] == "success"
            }) {
                return event["providerAudit"]["management"]["target"].clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

async fn resolve(fixture: &AuditFixture, request_id: &str, token: &str) -> Value {
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/access-keys/resolve")
                .extension(ConnectInfo(
                    "127.0.0.1:43140".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, request_id)
                .header(CONTENT_TYPE, "application/json")
                .header(CALLER_HEADER, RESOLVER)
                .body(Body::from(json!({ "key": token }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{request_id}");
    response_json(response).await
}

/// A management context admitted against the current generation, as a
/// request that has passed its audit preflight holds one.
async fn admitted(
    fixture: &AuditFixture,
    operation: &'static str,
    request: &'static str,
) -> ManagementContext {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", fixture.admin)).unwrap(),
    );
    headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static(request));
    let context = management_context(
        &AppState {
            reloadable: fixture.state.clone(),
        },
        "127.0.0.1:43141".parse().unwrap(),
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    .unwrap();
    management_write_audit_preflight(&context, operation, None)
        .await
        .unwrap();
    context
}

/// Rewrites the configuration without `access_key_type` and reloads; whether
/// the candidate was published.
async fn reload_without(fixture: &AuditFixture, access_key_type: &str) -> bool {
    let mut config = fixture.broker.runtime().config().clone();
    config.access_key_types.remove(access_key_type);
    // The fixture's service credential must be readable again at a reload.
    let credential = fixture
        .broker
        .running()
        .directory()
        .secret_file("access-key-types-reload.token", "synthetic-reload-token")
        .unwrap();
    config
        .credentials
        .service
        .get_mut("fake")
        .unwrap()
        .token_ref = Some(format!("file:{}", credential.display()));
    fixture
        .broker
        .running()
        .rewrite_config(super::broker::ConfigDoc::from_config(&config).render())
        .unwrap();
    let outcome = fixture.broker.running().reload().await.unwrap();
    if !outcome.is_success() {
        // The only refusal these tests provoke is the reference check. It
        // is the configuration's refusal and says what stands in the way:
        // nothing about the store being unavailable, invalid or in need of
        // a migration.
        let message = outcome.message().unwrap_or_default();
        assert!(
            message.contains(&format!(
                "access key type {access_key_type} is not in [access_key_types] and is still named by"
            )),
            "{outcome:?}"
        );
        for misleading in ["unavailable", "schema", "igration"] {
            assert!(!message.contains(misleading), "{outcome:?}");
        }
    }
    outcome.is_success()
}

#[tokio::test]
async fn each_type_is_decided_by_the_account_or_else_by_its_groups_and_the_detail_says_which() {
    let fixture = fixture().await;

    // A new account says nothing about any type, and no type is on.
    assert_eq!(
        detail(&fixture, "alice").await,
        (
            json!({"allow": [], "deny": []}),
            json!({"accessKeyTypes": [
                decision("batch", false, "none", &[]),
                decision("inference", false, "none", &[]),
                decision("packages", false, "none", &[]),
            ]})
        )
    );

    // A new group allows what its creation names, and nothing otherwise.
    let platform = ok(
        &fixture,
        Method::POST,
        "/v1/admin/groups",
        Some(json!({
            "groupId": "platform",
            "accessKeyTypes": {"allow": ["packages", "inference"]},
        })),
        "access-key-types-group-create",
    )
    .await;
    assert_eq!(
        platform["accessKeyTypes"],
        json!({"allow": ["inference", "packages"]})
    );
    let plain = ok(
        &fixture,
        Method::POST,
        "/v1/admin/groups",
        Some(json!({"groupId": "plain"})),
        "access-key-types-group-plain",
    )
    .await;
    assert_eq!(plain["accessKeyTypes"], json!({"allow": []}));
    for group in ["platform", "plain"] {
        store(&fixture).add_group("alice", group, "admin").unwrap();
    }
    assert_eq!(
        detail(&fixture, "alice").await.1,
        json!({"accessKeyTypes": [
            decision("batch", false, "none", &[]),
            decision("inference", true, "groups", &["platform"]),
            decision("packages", true, "groups", &["platform"]),
        ]})
    );

    // The account decides two types itself and leaves the third to its
    // groups: its deny wins over the group and its allow needs no group.
    set_account(
        &fixture,
        "alice",
        json!({"allow": ["batch"], "deny": ["packages"]}),
        "access-key-types-account",
    )
    .await;
    assert_eq!(
        detail(&fixture, "alice").await,
        (
            json!({"allow": ["batch"], "deny": ["packages"]}),
            json!({"accessKeyTypes": [
                decision("batch", true, "account", &[]),
                decision("inference", true, "groups", &["platform"]),
                decision("packages", false, "account", &[]),
            ]})
        )
    );

    // Every group route reports the group's setting.
    let groups = ok(
        &fixture,
        Method::GET,
        "/v1/admin/groups",
        None,
        "access-key-types-group-list",
    )
    .await;
    let listed = |group: &str| {
        groups
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["groupId"] == group)
            .unwrap()["accessKeyTypes"]
            .clone()
    };
    assert_eq!(
        listed("platform"),
        json!({"allow": ["inference", "packages"]})
    );
    assert_eq!(listed("plain"), json!({"allow": []}));
    let inspected = ok(
        &fixture,
        Method::GET,
        "/v1/admin/groups/platform",
        None,
        "access-key-types-group-inspect",
    )
    .await;
    assert_eq!(
        inspected["accessKeyTypes"],
        json!({"allow": ["inference", "packages"]})
    );

    // A second group that allows the type is named beside the first.
    set_group(
        &fixture,
        "plain",
        json!({"allow": ["inference"]}),
        "access-key-types-group-second",
    )
    .await;
    assert_eq!(
        detail(&fixture, "alice").await.1["accessKeyTypes"][1],
        decision("inference", true, "groups", &["plain", "platform"])
    );

    // A change to another field replaces neither setting.
    let result = ok(
        &fixture,
        Method::PATCH,
        "/v1/admin/principals/alice/access",
        Some(json!({"selfServiceEnabled": true})),
        "access-key-types-other-field",
    )
    .await;
    assert_eq!(
        result["accessKeyTypes"],
        json!({"allow": ["batch"], "deny": ["packages"]})
    );
    let result = ok(
        &fixture,
        Method::PATCH,
        "/v1/admin/groups/platform",
        Some(json!({"description": "Platform engineering"})),
        "access-key-types-group-other-field",
    )
    .await;
    assert_eq!(
        result["accessKeyTypes"],
        json!({"allow": ["inference", "packages"]})
    );

    // A replacement is the whole setting: what it leaves out is no longer
    // allowed, and a disabled group allows nothing.
    set_group(
        &fixture,
        "platform",
        json!({"allow": ["packages"]}),
        "access-key-types-group-narrowed",
    )
    .await;
    ok(
        &fixture,
        Method::PATCH,
        "/v1/admin/groups/plain",
        Some(json!({"status": "disabled"})),
        "access-key-types-group-disabled",
    )
    .await;
    set_account(
        &fixture,
        "alice",
        json!({"allow": [], "deny": []}),
        "access-key-types-account-cleared",
    )
    .await;
    assert_eq!(
        detail(&fixture, "alice").await.1,
        json!({"accessKeyTypes": [
            decision("batch", false, "none", &[]),
            decision("inference", false, "none", &[]),
            decision("packages", true, "groups", &["platform"]),
        ]})
    );
}

#[tokio::test]
async fn a_setting_is_refused_unless_it_is_the_complete_object_of_configured_access_key_types() {
    let fixture = fixture().await;
    ok(
        &fixture,
        Method::POST,
        "/v1/admin/groups",
        Some(json!({"groupId": "platform"})),
        "access-key-types-refusal-group",
    )
    .await;
    let account = "/v1/admin/principals/alice/access";
    let group = "/v1/admin/groups/platform";
    for (uri, access) in [
        // An access key type is allowed or denied, never both.
        (
            account,
            json!({"allow": ["inference"], "deny": ["inference"]}),
        ),
        // Only configured access key types are named.
        (account, json!({"allow": ["later-type"], "deny": []})),
        (account, json!({"allow": [], "deny": ["later-type"]})),
        (group, json!({"allow": ["later-type"]})),
        // The object is complete and has no other member.
        (account, json!({"allow": ["inference"]})),
        (account, json!({"deny": ["inference"]})),
        (account, json!({})),
        (account, json!(null)),
        (account, json!({"mode": "inherit", "accessKeyTypes": []})),
        (account, json!({"allow": [], "deny": [], "mode": "inherit"})),
        (
            account,
            json!({"allow": ["inference", "inference"], "deny": []}),
        ),
        (account, json!({"allow": ["Inference"], "deny": []})),
        (group, json!({})),
        (group, json!(null)),
        (group, json!(["inference"])),
        (group, json!({"allow": ["inference", "inference"]})),
        // A group cannot deny.
        (group, json!({"allow": [], "deny": ["inference"]})),
        (group, json!({"allow": ["inference"], "deny": []})),
    ] {
        // A body the route cannot read is refused before the envelope.
        let status = authed_json_request(
            fixture.app.clone(),
            Method::PATCH,
            uri,
            "access-key-types-refused",
            "Authorization",
            format!("Bearer {}", fixture.admin),
            Some(&json!({ "accessKeyTypes": access }).to_string()),
        )
        .await
        .status();
        assert!(
            matches!(
                status,
                StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
            ),
            "{uri} {access}: {status}"
        );
    }
    // A group's creation is refused whole: no group is left behind.
    let (status, envelope) = admin(
        &fixture,
        Method::POST,
        "/v1/admin/groups",
        Some(json!({"groupId": "later", "accessKeyTypes": {"allow": ["later-type"]}})),
        "access-key-types-refused-create",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{envelope}");
    assert_eq!(envelope["reasonCode"], "input_invalid");
    let (status, _) = admin(
        &fixture,
        Method::GET,
        "/v1/admin/groups/later",
        None,
        "access-key-types-refused-create-read",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Nothing was written by any refusal.
    assert_eq!(
        detail(&fixture, "alice").await.0,
        json!({"allow": [], "deny": []})
    );
    assert!(store(&fixture).group_access_key_types().unwrap().is_empty());

    // Only an administrator changes the setting.
    let (status, envelope) = fixture
        .request(
            Method::PATCH,
            &fixture.alice,
            account,
            Some(r#"{"accessKeyTypes":{"allow":["inference"],"deny":[]}}"#),
            "access-key-types-not-admin",
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(
        detail(&fixture, "alice").await.0,
        json!({"allow": [], "deny": []})
    );
}

/// The status of an administrator's request whose body the route may refuse
/// before the management envelope.
async fn status_of(fixture: &AuditFixture, method: Method, uri: &str, body: &Value) -> StatusCode {
    authed_json_request(
        fixture.app.clone(),
        method,
        uri,
        "access-key-types-positional",
        "Authorization",
        format!("Bearer {}", fixture.admin),
        Some(&body.to_string()),
    )
    .await
    .status()
}

#[tokio::test]
async fn a_positional_array_is_never_read_as_a_setting_or_as_the_body_that_carries_it() {
    let fixture = fixture().await;
    ok(
        &fixture,
        Method::POST,
        "/v1/admin/groups",
        Some(json!({"groupId": "platform", "displayName": "Platform"})),
        "access-key-types-positional-group",
    )
    .await;
    let account = "/v1/admin/principals/alice/access";
    let group = "/v1/admin/groups/platform";
    let groups = "/v1/admin/groups";
    let before = (
        ok(
            &fixture,
            Method::GET,
            "/v1/admin/principals/alice",
            None,
            "access-key-types-positional-before",
        )
        .await,
        ok(
            &fixture,
            Method::GET,
            group,
            None,
            "access-key-types-positional-before",
        )
        .await,
    );
    let issuance = json!({"mode": "disabled", "allowedExecutionContexts": []});
    for (method, uri, body) in [
        // The setting as its members in order, on each route that takes it.
        (
            Method::PATCH,
            account,
            json!({"accessKeyTypes": [["inference"], []]}),
        ),
        (
            Method::PATCH,
            account,
            json!({"accessKeyTypes": [[], ["inference"]]}),
        ),
        (
            Method::PATCH,
            account,
            json!({"accessKeyTypes": [["inference"]]}),
        ),
        (
            Method::PATCH,
            group,
            json!({"accessKeyTypes": [["inference"]]}),
        ),
        (
            Method::PATCH,
            group,
            json!({"accessKeyTypes": ["inference"]}),
        ),
        (
            Method::POST,
            groups,
            json!({"groupId": "positional", "accessKeyTypes": [["inference"]]}),
        ),
        // The whole body as its members in order, with values each member
        // would accept in an object.
        (
            Method::PATCH,
            account,
            json!(["auditor", true, issuance, {"allow": ["inference"], "deny": []}]),
        ),
        (
            Method::PATCH,
            account,
            json!(["auditor", true, issuance, [["inference"], []]]),
        ),
        (
            Method::PATCH,
            group,
            json!(["Renamed", "By position", "disabled", false, issuance, {"allow": ["inference"]}]),
        ),
        (
            Method::POST,
            groups,
            json!(["positional", "Positional", null, false, issuance, {"allow": ["inference"]}]),
        ),
        (Method::PATCH, account, json!([])),
        (Method::PATCH, group, json!([])),
        (Method::POST, groups, json!(["positional"])),
        // The members beside the setting are read as strictly: an object
        // where an enumerated string belongs, and an object's members in
        // order, are no spelling of them.
        (Method::PATCH, account, json!({"role": {"auditor": null}})),
        (
            Method::PATCH,
            account,
            json!({"agentTokenIssuance": ["disabled", []]}),
        ),
        (
            Method::PATCH,
            account,
            json!({"agentTokenIssuance": {"mode": {"disabled": null},
                "allowedExecutionContexts": []}}),
        ),
        (
            Method::PATCH,
            group,
            json!({"agentTokenIssuance": ["disabled", []]}),
        ),
        (
            Method::PATCH,
            group,
            json!({"agentTokenIssuance": {"mode": {"disabled": null},
                "allowedExecutionContexts": []}}),
        ),
        (
            Method::POST,
            groups,
            json!({"groupId": "positional", "agentTokenIssuance": ["disabled", []]}),
        ),
        // The profile PATCH, whose email renames a person, and principal
        // creation, which names one.
        (
            Method::PATCH,
            "/v1/admin/principals/alice",
            json!([null, "renamed@example.com", null]),
        ),
        (
            Method::PATCH,
            "/v1/admin/principals/alice",
            json!(["Renamed By Position"]),
        ),
        (
            Method::POST,
            "/v1/admin/principals",
            json!([
                "positional",
                "user",
                "By Position",
                "positional@example.com"
            ]),
        ),
        (
            Method::POST,
            "/v1/admin/principals",
            json!({"principalId": "positional", "kind": "user", "role": {"admin": null}}),
        ),
        (
            Method::POST,
            "/v1/admin/principals",
            json!({"principalId": "positional", "kind": "user",
                "agentTokenIssuance": ["disabled", []]}),
        ),
    ] {
        let status = status_of(&fixture, method.clone(), uri, &body).await;
        assert!(
            matches!(
                status,
                StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
            ),
            "{method} {uri} {body}: {status}"
        );
    }

    // No request changed an account or a group, or created one.
    let after = (
        ok(
            &fixture,
            Method::GET,
            "/v1/admin/principals/alice",
            None,
            "access-key-types-positional-after",
        )
        .await,
        ok(
            &fixture,
            Method::GET,
            group,
            None,
            "access-key-types-positional-after",
        )
        .await,
    );
    assert_eq!(before, after);
    assert_eq!(after.0["accessKeyTypes"], json!({"allow": [], "deny": []}));
    assert_eq!(after.1["accessKeyTypes"], json!({"allow": []}));
    assert_eq!(after.1["displayName"], "Platform");
    assert!(store(&fixture).group_access_key_types().unwrap().is_empty());
    let (status, _) = admin(
        &fixture,
        Method::GET,
        "/v1/admin/groups/positional",
        None,
        "access-key-types-positional-created",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = admin(
        &fixture,
        Method::GET,
        "/v1/admin/principals/positional",
        None,
        "access-key-types-positional-principal",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The same members as objects are accepted.
    set_account(
        &fixture,
        "alice",
        json!({"allow": ["inference"], "deny": []}),
        "access-key-types-positional-object",
    )
    .await;
    set_group(
        &fixture,
        "platform",
        json!({"allow": ["inference"]}),
        "access-key-types-positional-object-group",
    )
    .await;
}

#[tokio::test]
async fn every_change_is_audited_with_the_setting_before_and_after() {
    let fixture = fixture().await;

    set_account(
        &fixture,
        "alice",
        json!({"allow": ["inference"], "deny": ["packages"]}),
        "access-key-types-audit-account",
    )
    .await;
    let target = completion(&fixture, "access-key-types-audit-account").await;
    assert_eq!(target["principal"], "alice");
    assert_eq!(
        target["previousAccessKeyTypes"],
        json!({"allow": [], "deny": []})
    );
    assert_eq!(
        target["accessKeyTypes"],
        json!({"allow": ["inference"], "deny": ["packages"]})
    );

    // A change to another field records the setting it left alone.
    ok(
        &fixture,
        Method::PATCH,
        "/v1/admin/principals/alice/access",
        Some(json!({"selfServiceEnabled": true})),
        "access-key-types-audit-other",
    )
    .await;
    let target = completion(&fixture, "access-key-types-audit-other").await;
    assert_eq!(target["previousAccessKeyTypes"], target["accessKeyTypes"]);
    assert_eq!(
        target["accessKeyTypes"],
        json!({"allow": ["inference"], "deny": ["packages"]})
    );

    ok(
        &fixture,
        Method::POST,
        "/v1/admin/groups",
        Some(json!({"groupId": "platform", "accessKeyTypes": {"allow": ["inference"]}})),
        "access-key-types-audit-group-create",
    )
    .await;
    assert_eq!(
        completion(&fixture, "access-key-types-audit-group-create").await["accessKeyTypes"],
        json!({"previous": {"allow": []}, "current": {"allow": ["inference"]}})
    );
    set_group(
        &fixture,
        "platform",
        json!({"allow": ["batch", "packages"]}),
        "access-key-types-audit-group",
    )
    .await;
    assert_eq!(
        completion(&fixture, "access-key-types-audit-group").await["accessKeyTypes"],
        json!({
            "previous": {"allow": ["inference"]},
            "current": {"allow": ["batch", "packages"]},
        })
    );

    // Writing the setting a group already has changes nothing and records
    // no change.
    set_group(
        &fixture,
        "platform",
        json!({"allow": ["batch", "packages"]}),
        "access-key-types-audit-group-same",
    )
    .await;
    ok(
        &fixture,
        Method::PATCH,
        "/v1/admin/groups/platform",
        Some(json!({"description": "Platform engineering"})),
        "access-key-types-audit-group-after",
    )
    .await;
    assert!(!fixture.records().into_iter().any(|event| {
        matches!(
            event["agentRequestId"].as_str(),
            Some("access-key-types-audit-group-same" | "access-key-types-audit-group-after")
        ) && !event["providerAudit"]["management"]["target"]["accessKeyTypes"].is_null()
    }));
}

#[tokio::test]
async fn withdrawn_access_stops_a_token_that_exists_and_restored_access_resumes_it() {
    let fixture = fixture().await;
    let runtime = fixture.broker.runtime();
    let store = store(&fixture);
    let request = AdministratorAccessKeyRequest {
        principal_id: "robot".to_string(),
        name: "nightly job".to_string(),
        access_key_types: vec!["inference".to_string()],
        lifetime: "3600s".into(),
        created_by: "admin".to_string(),
    };
    let mint = || {
        store
            .mint_administrator_access_key(
                runtime.broker_token_hasher().unwrap(),
                runtime.access_key_types(),
                &request,
            )
            .unwrap()
    };

    // An administrator cannot issue a type the service account may not
    // hold, although the type is configured.
    assert_eq!(
        mint().unwrap_err().refusal,
        AccessKeyRefusal::AccessKeyTypeNotEligible
    );
    set_account(
        &fixture,
        "robot",
        json!({"allow": ["inference"], "deny": []}),
        "access-key-types-robot-allowed",
    )
    .await;
    let issued = mint().unwrap();
    let token = issued.key;
    let key_id = issued.record.key_id;
    let active = async |request_id: &str| {
        let answer = resolve(&fixture, request_id, &token).await;
        assert_eq!(answer["active"], true, "{request_id}: {answer}");
        assert_eq!(answer["subject"]["id"], "robot");
        assert_eq!(
            answer["types"]
                .as_array()
                .unwrap()
                .iter()
                .map(|access_key_type| access_key_type["name"].clone())
                .collect::<Vec<_>>(),
            vec![json!("inference")],
            "{request_id}"
        );
    };
    let inactive = async |request_id: &str| {
        assert_eq!(
            resolve(&fixture, request_id, &token).await,
            json!({
                "active": false,
                "keyId": key_id,
                "owner": {"kind": "service_account", "id": "robot"},
                "reason": "no_access_key_type"
            }),
            "{request_id}"
        );
        assert!(
            fixture
                .records()
                .into_iter()
                .all(|record| record["agentRequestId"] != request_id)
        );
    };
    active("access-key-types-resolve-allowed").await;

    // The account's deny stops the token; nothing about the token changed.
    set_account(
        &fixture,
        "robot",
        json!({"allow": [], "deny": ["inference"]}),
        "access-key-types-robot-denied",
    )
    .await;
    inactive("access-key-types-resolve-denied").await;

    // With no word of its own the account follows its groups: an active
    // group it belongs to locally allows the type.
    set_account(
        &fixture,
        "robot",
        json!({"allow": [], "deny": []}),
        "access-key-types-robot-inherits",
    )
    .await;
    inactive("access-key-types-resolve-no-group").await;
    ok(
        &fixture,
        Method::POST,
        "/v1/admin/groups",
        Some(json!({"groupId": "automation", "accessKeyTypes": {"allow": ["inference"]}})),
        "access-key-types-automation",
    )
    .await;
    inactive("access-key-types-resolve-not-member").await;
    store.add_group("robot", "automation", "admin").unwrap();
    active("access-key-types-resolve-group").await;

    // A disabled group contributes nothing, and contributes again enabled.
    for (status, request_id) in [
        ("disabled", "access-key-types-group-off"),
        ("active", "access-key-types-group-on"),
    ] {
        ok(
            &fixture,
            Method::PATCH,
            "/v1/admin/groups/automation",
            Some(json!({ "status": status })),
            request_id,
        )
        .await;
        if status == "disabled" {
            inactive("access-key-types-resolve-group-off").await;
        } else {
            active("access-key-types-resolve-group-on").await;
        }
    }

    // The group stops allowing the type, then the account is denied
    // although the group allows it again.
    set_group(
        &fixture,
        "automation",
        json!({"allow": ["packages"]}),
        "access-key-types-group-narrowed",
    )
    .await;
    inactive("access-key-types-resolve-group-narrowed").await;
    set_group(
        &fixture,
        "automation",
        json!({"allow": ["inference", "packages"]}),
        "access-key-types-group-widened",
    )
    .await;
    active("access-key-types-resolve-group-widened").await;
    set_account(
        &fixture,
        "robot",
        json!({"allow": [], "deny": ["inference"]}),
        "access-key-types-robot-denied-again",
    )
    .await;
    inactive("access-key-types-resolve-denied-over-group").await;
    assert_eq!(
        mint().unwrap_err().refusal,
        AccessKeyRefusal::AccessKeyTypeNotEligible
    );
}

#[tokio::test]
async fn a_reload_is_refused_while_a_saved_setting_names_an_access_key_type_it_removes() {
    let fixture = fixture().await;
    let generation = fixture.state.current();

    // An account's reference blocks the reload, on either list.
    for access in [
        json!({"allow": ["packages"], "deny": []}),
        json!({"allow": [], "deny": ["packages"]}),
    ] {
        set_account(&fixture, "alice", access, "access-key-types-reload-account").await;
        assert!(!reload_without(&fixture, "packages").await);
        assert!(Arc::ptr_eq(&generation, &fixture.state.current()));
    }
    set_account(
        &fixture,
        "alice",
        json!({"allow": [], "deny": []}),
        "access-key-types-reload-account-cleared",
    )
    .await;

    // So does a group's, whether or not the group is enabled.
    ok(
        &fixture,
        Method::POST,
        "/v1/admin/groups",
        Some(json!({"groupId": "platform", "accessKeyTypes": {"allow": ["packages"]}})),
        "access-key-types-reload-group",
    )
    .await;
    assert!(!reload_without(&fixture, "packages").await);
    ok(
        &fixture,
        Method::PATCH,
        "/v1/admin/groups/platform",
        Some(json!({"status": "disabled"})),
        "access-key-types-reload-group-disabled",
    )
    .await;
    assert!(!reload_without(&fixture, "packages").await);
    assert!(Arc::ptr_eq(&generation, &fixture.state.current()));

    // With no reference left the access key type retires, and a setting can no
    // longer name it.
    set_group(
        &fixture,
        "platform",
        json!({"allow": []}),
        "access-key-types-reload-group-cleared",
    )
    .await;
    assert!(reload_without(&fixture, "packages").await);
    assert!(!Arc::ptr_eq(&generation, &fixture.state.current()));
    assert_eq!(
        detail(&fixture, "alice").await.1,
        json!({"accessKeyTypes": [
            decision("batch", false, "none", &[]),
            decision("inference", false, "none", &[]),
        ]})
    );
    let (status, envelope) = admin(
        &fixture,
        Method::PATCH,
        "/v1/admin/principals/alice/access",
        Some(json!({"accessKeyTypes": {"allow": ["packages"], "deny": []}})),
        "access-key-types-reload-retired",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{envelope}");
    assert_eq!(envelope["reasonCode"], "input_invalid");
}

#[tokio::test]
async fn a_start_is_refused_while_a_saved_setting_names_an_access_key_type_the_configuration_lacks()
{
    let fixture = fixture().await;
    // An account's setting, a group's setting and a live key name `packages`.
    set_account(
        &fixture,
        "robot",
        json!({"allow": ["packages"], "deny": []}),
        "access-key-types-start-account",
    )
    .await;
    set_account(
        &fixture,
        "alice",
        json!({"allow": [], "deny": ["packages"]}),
        "access-key-types-start-denied",
    )
    .await;
    ok(
        &fixture,
        Method::POST,
        "/v1/admin/groups",
        Some(json!({"groupId": "platform", "accessKeyTypes": {"allow": ["packages"]}})),
        "access-key-types-start-group",
    )
    .await;
    let issued = ok(
        &fixture,
        Method::POST,
        "/v1/admin/principals/robot/access-keys",
        Some(json!({"name": "nightly", "accessKeyTypes": ["packages"], "lifetime": "1h"})),
        "access-key-types-start-key",
    )
    .await;
    let key = issued["key"].as_str().unwrap().to_string();
    assert_eq!(
        resolve(&fixture, "access-key-types-start-live", &key).await["active"],
        true
    );

    // The Broker is stopped and started on a configuration without the
    // type. The fixture's service credential must be readable again.
    let mut config = fixture.broker.runtime().config().clone();
    let credential = temp_path("access-key-types-start-token");
    std::fs::write(&credential, "synthetic-start-token").unwrap();
    config
        .credentials
        .service
        .get_mut("fake")
        .unwrap()
        .token_ref = Some(format!("file:{}", credential.display()));
    let AuditFixture {
        broker, app, state, ..
    } = fixture;
    drop((app, state));
    broker.stop().await;
    let mut without = config.clone();
    without.access_key_types.remove("packages");
    let refused = match TestBroker::try_start_with(TestBroker::config_builder(&without)).await {
        Ok(_) => panic!("the Broker started without a type that saved settings name"),
        Err(error) => error,
    };
    // What the process prints: which type, who still names it and how many
    // live keys carry it, and what to do. Nothing says that the store is
    // unavailable, invalid or in need of a migration.
    let printed = format!("{refused:?}");
    assert!(
        printed.contains(
            "access key type packages is not in [access_key_types] and is still named by \
             2 account settings (alice, robot) and 1 group setting (platform); \
             1 unexpired access key carries it. Take it out of those settings, or keep its \
             table, then reload or start again"
        ),
        "{printed}"
    );
    for misleading in ["unavailable", "schema", "igration"] {
        assert!(!printed.contains(misleading), "{printed}");
    }
    // It is the configuration that is refused.
    assert!(
        refused.chain().any(|cause| matches!(
            cause.downcast_ref::<agent_access_core::RuntimeError>(),
            Some(agent_access_core::RuntimeError::Config(_))
        )),
        "{printed}"
    );

    // The same store starts on the configuration that keeps the type, and
    // nothing was changed by the refused start: the key still resolves.
    let broker = TestBroker::start_config(&config).await;
    let response = broker
        .app()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/access-keys/resolve")
                .extension(ConnectInfo(
                    "127.0.0.1:43140".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "access-key-types-start-restored")
                .header(CONTENT_TYPE, "application/json")
                .header(CALLER_HEADER, RESOLVER)
                .body(Body::from(json!({ "key": key }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["active"], true);
}

#[tokio::test]
async fn a_write_admitted_before_a_reload_never_saves_what_the_retired_access_key_types_allowed() {
    for group in [false, true] {
        let fixture = fixture().await;
        let operation = if group {
            "admin.groups.create"
        } else {
            "admin.principals.access.patch"
        };
        // The request is admitted, and reads its access key type setting, while
        // `packages` is still configured.
        let context = admitted(&fixture, operation, "access-key-types-stale-write").await;
        let retired = context.snapshot.runtime.clone();
        assert!(retired.access_key_types().get("packages").is_some());
        assert!(reload_without(&fixture, "packages").await);
        let state = AppState {
            reloadable: fixture.state.clone(),
        };
        let response = if group {
            committed_group_mutation(
                state,
                context,
                operation,
                None,
                move |store, environment| {
                    store.create_group_with_access(
                        GroupWriteRequest {
                            group_id: "platform".into(),
                            display_name: None,
                            description: None,
                            auto_enroll_new_microsoft_users: false,
                            agent_token_issuance: Default::default(),
                            created_by: "admin".into(),
                        },
                        Some(AccessKeyTypesWrite {
                            setting: &GroupAccessKeyTypes::new(vec!["packages".into()]).unwrap(),
                            configured: retired.access_key_types(),
                        }),
                        environment.contexts(),
                    )
                },
            )
            .await
        } else {
            committed_principal_mutation(
                state,
                context,
                operation,
                None,
                move |store, environment| {
                    let change = store.patch_principal_access_with_access_key_types(
                        PrincipalAccessPatchRequest {
                            agent_token_issuance: None,
                            principal_id: "alice".into(),
                            role: None,
                            self_service_enabled: None,
                            actor: "admin".into(),
                        },
                        Some(AccessKeyTypesWrite {
                            setting: &PrincipalAccessKeyTypes::new(
                                vec!["packages".into()],
                                Vec::new(),
                            )
                            .unwrap(),
                            configured: retired.access_key_types(),
                        }),
                        environment.contexts(),
                    )?;
                    Ok((json!(change.principal), json!({})))
                },
            )
            .await
        };
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response_json(response).await["reasonCode"],
            "version_conflict"
        );
        let store = store(&fixture);
        assert_eq!(
            store.principal_access_key_types("alice").unwrap(),
            PrincipalAccessKeyTypes::default()
        );
        assert!(store.group_access_key_types().unwrap().is_empty());
        assert!(store.group("platform").is_err());
    }
}
