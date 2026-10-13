use super::*;
use crate::state::AppState;
use axum::http::{HeaderMap, HeaderValue};

async fn catalog_request(
    app: &Router,
    token: &str,
    method: Method,
    path: &str,
    request_id: &str,
    body: Option<Value>,
) -> axum::response::Response {
    authed_json_request(
        app.clone(),
        method,
        path,
        request_id,
        "Authorization",
        format!("Bearer {token}"),
        body.as_ref().map(Value::to_string).as_deref(),
    )
    .await
}

#[tokio::test]
async fn resource_catalog_crud_preserves_versions_uniqueness_and_manual_unlink() {
    let fixture = managed_policy_admin_fixture();
    let app = &fixture.app;
    let token = &fixture.admin_token;
    let resource = json!({"id":"all-repositories","resourceType":"git_repository",
        "selector":{"kind":"all"},"allowedExecutionContexts":["default"]});
    let created = catalog_request(
        app,
        token,
        Method::POST,
        "/v1/admin/policy/resources",
        "catalog-create-all",
        Some(resource.clone()),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let created = response_json(created).await;
    assert_eq!(created["result"]["record"]["id"], "all-repositories");
    assert_eq!(
        created["result"]["record"]["selector"],
        json!({"kind":"all"})
    );
    assert_eq!(created["result"]["record"]["version"], 1);

    let mut duplicate = resource;
    duplicate["id"] = json!("same-selector-different-label");
    duplicate["displayName"] = json!("A different label");
    duplicate["enabled"] = json!(false);
    let duplicate = catalog_request(
        app,
        token,
        Method::POST,
        "/v1/admin/policy/resources",
        "catalog-duplicate-selector",
        Some(duplicate),
    )
    .await;
    assert!(!duplicate.status().is_success());

    let patched = catalog_request(
        app,
        token,
        Method::PATCH,
        "/v1/admin/policy/resources/all-repositories",
        "catalog-disable-resource",
        Some(json!({"expectedVersion":1,"enabled":false})),
    )
    .await;
    assert_eq!(patched.status(), StatusCode::OK);
    assert_eq!(
        response_json(patched).await["result"]["record"]["version"],
        2
    );
    let stale = catalog_request(
        app,
        token,
        Method::PATCH,
        "/v1/admin/policy/resources/all-repositories",
        "catalog-stale-version",
        Some(json!({"expectedVersion":1,"enabled":true})),
    )
    .await;
    assert_eq!(stale.status(), StatusCode::CONFLICT);

    let group = catalog_request(app, token, Method::POST, "/v1/admin/policy/resource-groups",
        "catalog-create-group", Some(json!({"id":"catalog-group","name":"Catalog test",
            "includedResourceIds":["all-repositories"],"excludedResourceIds":["repository-sip-service"]}))).await;
    assert_eq!(group.status(), StatusCode::OK);
    let references = catalog_request(
        app,
        token,
        Method::GET,
        "/v1/admin/policy/resources/all-repositories/used-by",
        "catalog-used-by",
        None,
    )
    .await;
    assert_eq!(references.status(), StatusCode::OK);
    let references = response_json(references).await;
    assert!(
        references["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reference| reference["id"] == "catalog-group")
    );

    let blocked = catalog_request(
        app,
        token,
        Method::DELETE,
        "/v1/admin/policy/resources/all-repositories?expectedVersion=2",
        "catalog-referenced-delete",
        None,
    )
    .await;
    assert!(!blocked.status().is_success());
    assert!(response_json(blocked).await.to_string().contains("in use"));
    let still_present = catalog_request(
        app,
        token,
        Method::GET,
        "/v1/admin/policy/resources/all-repositories",
        "catalog-referenced-resource-preserved",
        None,
    )
    .await;
    assert_eq!(still_present.status(), StatusCode::OK);
    assert_eq!(
        response_json(still_present).await["result"]["enabled"],
        false
    );

    let unlinked = catalog_request(
        app,
        token,
        Method::PATCH,
        "/v1/admin/policy/resource-groups/catalog-group",
        "catalog-manual-unlink",
        Some(json!({"expectedVersion":1,"includedResourceIds":[]})),
    )
    .await;
    assert_eq!(unlinked.status(), StatusCode::OK);
    let deleted = catalog_request(
        app,
        token,
        Method::DELETE,
        "/v1/admin/policy/resources/all-repositories?expectedVersion=2",
        "catalog-delete-unreferenced",
        None,
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::OK);
    let missing = catalog_request(
        app,
        token,
        Method::GET,
        "/v1/admin/policy/resources/all-repositories",
        "catalog-deleted-resource-missing",
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let deleted_group = catalog_request(
        app,
        token,
        Method::DELETE,
        "/v1/admin/policy/resource-groups/catalog-group?expectedVersion=2",
        "catalog-delete-group",
        None,
    )
    .await;
    assert_eq!(deleted_group.status(), StatusCode::OK);
}

#[tokio::test]
async fn delegated_catalog_reads_filter_types_and_catalog_mutations_require_global_admin() {
    let fixture = service_policy_management_fixture();
    let app = &fixture.app;
    let assigned = catalog_request(
        app,
        &fixture.admin_token,
        Method::PUT,
        "/v1/admin/policy/services/fake/managers/bob",
        "catalog-delegate-fake",
        None,
    )
    .await;
    assert_eq!(assigned.status(), StatusCode::OK);
    for (id, included, excluded) in [
        (
            "mixed-catalog-group",
            vec!["project-test", "repository-sip-service"],
            vec!["project-ops", "space-eng"],
        ),
        (
            "repository-only-group",
            vec!["repository-sip-service"],
            vec![],
        ),
        ("fresh-empty-group", vec![], vec![]),
    ] {
        let created = catalog_request(app, &fixture.admin_token, Method::POST,
            "/v1/admin/policy/resource-groups", &format!("catalog-create-{id}"),
            Some(json!({"id":id,"name":id,"includedResourceIds":included,"excludedResourceIds":excluded}))).await;
        assert_eq!(created.status(), StatusCode::OK);
    }
    let list = catalog_request(
        app,
        &fixture.bob_user_token,
        Method::GET,
        "/v1/admin/policy/resources",
        "catalog-delegated-resource-list",
        None,
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);
    let list = response_json(list).await;
    let resources = list["result"].as_array().unwrap();
    assert!(!resources.is_empty());
    assert!(
        resources
            .iter()
            .all(|resource| resource["resourceType"] == "fake_project")
    );
    let groups = catalog_request(
        app,
        &fixture.bob_user_token,
        Method::GET,
        "/v1/admin/policy/resource-groups",
        "catalog-delegated-group-list",
        None,
    )
    .await;
    assert_eq!(groups.status(), StatusCode::OK);
    let groups = response_json(groups).await;
    let groups = groups["result"].as_array().unwrap();
    assert_eq!(groups.len(), 2);
    assert!(
        groups
            .iter()
            .any(|group| group["id"] == "fresh-empty-group")
    );
    let mixed = groups
        .iter()
        .find(|group| group["id"] == "mixed-catalog-group")
        .unwrap();
    assert_eq!(mixed["includedResourceIds"], json!(["project-test"]));
    assert_eq!(mixed["excludedResourceIds"], json!(["project-ops"]));
    for path in [
        "/v1/admin/policy/resources/repository-sip-service",
        "/v1/admin/policy/resource-groups/repository-only-group",
    ] {
        let hidden = catalog_request(
            app,
            &fixture.bob_user_token,
            Method::GET,
            path,
            "catalog-hidden-entry",
            None,
        )
        .await;
        assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
    }
    for (method, path, body) in [
        (
            Method::POST,
            "/v1/admin/policy/resources",
            Some(
                json!({"id":"forbidden-new","resourceType":"fake_project","selector":{"kind":"all"},"allowedExecutionContexts":["default"]}),
            ),
        ),
        (
            Method::PATCH,
            "/v1/admin/policy/resources/project-test",
            Some(json!({"expectedVersion":1,"enabled":false})),
        ),
        (
            Method::DELETE,
            "/v1/admin/policy/resources/project-test?expectedVersion=1",
            None,
        ),
        (
            Method::POST,
            "/v1/admin/policy/resource-groups",
            Some(json!({"id":"forbidden-group","name":"Forbidden"})),
        ),
        (
            Method::PATCH,
            "/v1/admin/policy/resource-groups/mixed-catalog-group",
            Some(json!({"expectedVersion":1,"includedResourceIds":[]})),
        ),
        (
            Method::DELETE,
            "/v1/admin/policy/resource-groups/mixed-catalog-group?expectedVersion=1",
            None,
        ),
        (
            Method::GET,
            "/v1/admin/policy/resources/project-test/used-by",
            None,
        ),
        (
            Method::GET,
            "/v1/admin/policy/resource-groups/mixed-catalog-group/used-by",
            None,
        ),
    ] {
        let denied = catalog_request(
            app,
            &fixture.bob_user_token,
            method,
            path,
            "catalog-delegated-mutation-denied",
            body,
        )
        .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let unrelated = catalog_request(
        app,
        &fixture.alice_user_token,
        Method::GET,
        "/v1/admin/policy/resources",
        "catalog-unassigned-user-denied",
        None,
    )
    .await;
    assert_eq!(unrelated.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn resource_policy_api_rejects_retired_scopes_and_invalid_selector_shapes() {
    let fixture = managed_policy_admin_fixture();
    for body in [
        json!({"id":"page","resourceType":"confluence_page","selector":{"kind":"exact","value":"12345"},"allowedExecutionContexts":["default"]}),
        json!({"id":"issue","resourceType":"jira_issue","selector":{"kind":"exact","value":"TEST-1"},"allowedExecutionContexts":["default"]}),
        json!({"id":"project-namespace","resourceType":"jira_project","selector":{"kind":"namespace","value":"TEST"},"allowedExecutionContexts":["default"]}),
        json!({"id":"all-with-value","resourceType":"confluence_space","selector":{"kind":"all","value":"*"},"allowedExecutionContexts":["default"]}),
    ] {
        let invalid = catalog_request(
            &fixture.app,
            &fixture.admin_token,
            Method::POST,
            "/v1/admin/policy/resources",
            "catalog-invalid-selector",
            Some(body),
        )
        .await;
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    }
    let grant = catalog_request(&fixture.app, &fixture.admin_token, Method::POST,
        "/v1/admin/policy/grants", "catalog-retired-grant-scopes",
        Some(json!({"subjects":["user:admin"],"service":"fake","actions":["echo"],
            "executionContexts":["default"],"credentialMode":"service","resourceScopes":{"project":["TEST"]}}))).await;
    assert_eq!(grant.status(), StatusCode::BAD_REQUEST);
    let token = catalog_request(&fixture.app, &fixture.admin_token, Method::POST,
        "/v1/admin/principals/admin/agent-tokens", "catalog-retired-token-scopes",
        Some(json!({"name":"retired scopes","allowedServices":["fake"],"allowedExecutionContexts":["default"],
            "serviceRestrictions":{"fake":{"actions":["echo"],"resourceScopes":{"project":["TEST"]}}},"never":true}))).await;
    assert_eq!(token.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn runtime_catalog_and_resource_types_route_publish_registered_types() {
    let registered = serde_json::to_value(
        crate::backend_registry()
            .resource_types()
            .clone()
            .metadata(),
    )
    .unwrap();
    let ids = registered
        .as_array()
        .unwrap()
        .iter()
        .map(|resource_type| resource_type["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        // Registration order; clients treat the first type as the default.
        [
            "git_repository",
            "jira_project",
            "confluence_space",
            "cloudbees_ci_job",
            "fake_project",
            "teams_notification_destination",
            "oauth_collection",
        ]
    );
    let described = |id: &str| {
        registered
            .as_array()
            .unwrap()
            .iter()
            .find(|resource_type| resource_type["id"] == id)
            .unwrap()
            .clone()
    };
    let git = described("git_repository");
    assert_eq!(git["selectors"], json!(["exact", "namespace", "all"]));
    assert_eq!(git["namespace"]["example"], "engineering/platform");
    let fake = described("fake_project");
    assert_eq!(fake["selectors"], json!(["exact", "all"]));
    assert!(fake.get("namespace").is_none());
    let teams = described("teams_notification_destination");
    assert_eq!(teams["selectors"], json!(["exact", "all"]));
    assert!(teams.get("namespace").is_none());
    assert_eq!(
        teams["attributes"],
        json!([{
            "name":"webhookUrl", "label":"Webhook URL",
            "description":"Signed Microsoft Teams Workflows URL using the Anyone trigger setting",
            "required":true, "secret":true,
        }])
    );

    // Every registered type is published, including types no visible
    // service uses.
    let agent = spec_agent_fixture(&["fake"], false);
    let runtime_catalog = spec_get(
        agent.app,
        "/v1/spec/catalog",
        "catalog-resource-types",
        Some(&agent.agent_token),
    )
    .await;
    assert_eq!(runtime_catalog.status(), StatusCode::OK);
    let runtime_catalog = response_json(runtime_catalog).await;
    assert!(catalog_has_service(&runtime_catalog, "fake"));
    assert!(!catalog_has_service(&runtime_catalog, "gitlab"));
    assert_eq!(runtime_catalog["resourceTypes"], registered);

    // Resource editors and labels read the dedicated route, which needs no
    // execution context.
    let fixture = managed_policy_admin_fixture();
    let listed = catalog_request(
        &fixture.app,
        &fixture.admin_token,
        Method::GET,
        "/v1/resource-types",
        "resource-types",
        None,
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(
        response_json(listed).await,
        json!({ "resourceTypes": registered })
    );
    let admin_catalog = catalog_request(
        &fixture.app,
        &fixture.admin_token,
        Method::GET,
        "/v1/admin/policy/catalog",
        "admin-catalog-resource-types",
        None,
    )
    .await;
    assert_eq!(admin_catalog.status(), StatusCode::OK);
    assert!(
        response_json(admin_catalog).await["result"]
            .get("resourceTypes")
            .is_none()
    );
}

#[tokio::test]
async fn resource_policy_api_rejects_unregistered_types_and_type_invalid_selectors() {
    let fixture = managed_policy_admin_fixture();
    let app = &fixture.app;
    let token = &fixture.admin_token;
    for (id, resource_type, selector, message) in [
        (
            "jira-issue",
            "jira_issue",
            json!({"kind":"exact","value":"TEST-1"}),
            "resource jira-issue uses unregistered resource type jira_issue",
        ),
        (
            "jira-namespace",
            "jira_project",
            json!({"kind":"namespace","value":"ENG"}),
            "resource jira-namespace selector is invalid for jira_project",
        ),
        (
            "empty-exact",
            "git_repository",
            json!({"kind":"exact","value":""}),
            "resource empty-exact selector value must be non-empty without control characters",
        ),
        (
            "empty-namespace",
            "git_repository",
            json!({"kind":"namespace","value":""}),
            "resource empty-namespace selector value must be non-empty without control characters",
        ),
        (
            "nul-exact",
            "git_repository",
            json!({"kind":"exact","value":"\u{0}"}),
            "resource nul-exact selector value must be non-empty without control characters",
        ),
    ] {
        let rejected = catalog_request(
            app,
            token,
            Method::POST,
            "/v1/admin/policy/resources",
            "catalog-unregistered-type",
            Some(
                json!({"id":id,"resourceType":resource_type,"selector":selector,
                "allowedExecutionContexts":["default"]}),
            ),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST, "{id}");
        let rejected = response_json(rejected).await;
        assert_eq!(rejected["reasonCode"], "input_invalid", "{id}");
        assert!(rejected.to_string().contains(message), "{rejected}");
        let missing = catalog_request(
            app,
            token,
            Method::GET,
            &format!("/v1/admin/policy/resources/{id}"),
            "catalog-unregistered-type-not-stored",
            None,
        )
        .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND, "{id}");
    }

    let patched = catalog_request(
        app,
        token,
        Method::PATCH,
        "/v1/admin/policy/resources/project-test",
        "catalog-patch-unregistered-type",
        Some(json!({"expectedVersion":1,"resourceType":"jira_issue"})),
    )
    .await;
    assert_eq!(patched.status(), StatusCode::BAD_REQUEST);
    let patched = response_json(patched).await;
    assert_eq!(patched["reasonCode"], "input_invalid");
    assert!(
        patched
            .to_string()
            .contains("resource project-test uses unregistered resource type jira_issue"),
        "{patched}"
    );
    let emptied = catalog_request(
        app,
        token,
        Method::PATCH,
        "/v1/admin/policy/resources/project-test",
        "catalog-patch-empty-selector",
        Some(json!({"expectedVersion":1,"selector":{"kind":"exact","value":"engineering\u{0}"}})),
    )
    .await;
    assert_eq!(emptied.status(), StatusCode::BAD_REQUEST);
    let emptied = response_json(emptied).await;
    assert_eq!(emptied["reasonCode"], "input_invalid");
    assert!(
        emptied.to_string().contains(
            "resource project-test selector value must be non-empty without control characters"
        ),
        "{emptied}"
    );
    let unchanged = catalog_request(
        app,
        token,
        Method::GET,
        "/v1/admin/policy/resources/project-test",
        "catalog-patch-unregistered-type-unchanged",
        None,
    )
    .await;
    assert_eq!(unchanged.status(), StatusCode::OK);
    let unchanged = response_json(unchanged).await;
    assert_eq!(unchanged["result"]["resourceType"], "fake_project");
    assert_eq!(unchanged["result"]["version"], 1);
}

struct ResourceAttributeFixture {
    app: Router,
    admin_token: String,
    user_token: String,
    store: agent_access_core::ManagedStore,
    audit_path: PathBuf,
}

fn resource_attribute_fixture(fail_audit: bool) -> ResourceAttributeFixture {
    let audit_path = temp_path("resource-attribute-audit");
    if fail_audit {
        std::fs::create_dir(&audit_path).unwrap();
    }
    let hash_key = temp_path("resource-attribute-token-key");
    let csrf_key = temp_path("resource-attribute-csrf-key");
    let password_key = temp_path("resource-attribute-password-key");
    for (path, byte) in [(&hash_key, 31), (&csrf_key, 32), (&password_key, 33)] {
        std::fs::write(
            path,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32]),
        )
        .unwrap();
    }
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity.mode = "required".into();
    config.identity.authority = "managed".into();
    config.identity.sources = vec![IdentitySourceConfig {
        name: "broker".into(),
        kind: "broker_tokens".into(),
        header: "Authorization".into(),
        scheme: "Bearer".into(),
        principals: vec![],
    }];
    config.policy = PolicyConfig {
        authority: "managed".into(),
        default_decision: "deny".into(),
        resources: vec![],
        resource_groups: vec![],
        grants: vec![],
    };
    config.managed_store = Some(agent_access_core::ManagedStoreConfig {
        kind: "sqlite".into(),
        path: temp_path("resource-attribute-store.sqlite")
            .display()
            .to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key.display()),
        ..Default::default()
    });
    config.management.enabled = true;
    config.management.initial_admin = agent_access_core::InitialAdminConfig {
        mode: "create_if_empty".into(),
        principal_id: Some("admin".into()),
        initial_password: Some("admin-password".into()),
    };
    config.browser_auth = agent_access_core::BrowserAuthConfig {
        enabled: true,
        public_origin: Some("http://localhost".into()),
        csrf_key_ref: Some(format!("file:{}", csrf_key.display())),
        local_password: agent_access_core::LocalPasswordConfig {
            enabled: true,
            pepper_ref: Some(format!("file:{}", password_key.display())),
            ..Default::default()
        },
        ..Default::default()
    };
    config.providers.insert(agent_access_teams::TeamsConfig {
        allowed_upstream_hosts: vec!["https://test.environment.api.powerplatform.com/**".into()],
        egress_proxy: None,
    });
    let runtime = BrokerRuntime::new(config).unwrap();
    let store = runtime.managed_store().unwrap().clone();
    store
        .reset_local_password(
            runtime.local_password_hasher().unwrap(),
            agent_access_core::LocalPasswordWriteRequest {
                principal_id: "admin".into(),
                password: "admin-password".into(),
                min_password_length: 8,
                password_change_required: false,
                actor: "admin".into(),
            },
        )
        .unwrap();
    store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".into(),
        })
        .unwrap();
    let issue = |principal: &str, class| {
        store
            .issue_broker_token(
                runtime.broker_token_hasher().unwrap(),
                agent_access_core::BrokerTokenIssueRequest {
                    principal_id: principal.into(),
                    name: "test".into(),
                    token_class: class,
                    scopes: json!({}),
                    expires_at: None,
                    created_by: "admin".into(),
                },
            )
            .unwrap()
            .token
    };
    let admin_token = issue("admin", agent_access_core::BrokerTokenClass::Admin);
    let user_token = issue("alice", agent_access_core::BrokerTokenClass::UserManage);
    // Startup setup stays local and does not exercise the webhook.
    runtime
        .create_managed_resource(agent_access_core::CreateResourceRequest {
            id: Some("release".into()),
            display_name: Some("Release notifications".into()),
            resource_type: agent_access_teams::TEAMS_DESTINATION_RESOURCE.id.clone(),
            selector: ResourceSelector::Exact {
                value: "release-alerts".into(),
            },
            allowed_execution_contexts: vec!["default".into()],
            enabled: true,
            attributes: agent_access_core::ResourceAttributes::from(BTreeMap::from([(
                "webhookUrl".into(),
                WEBHOOK_SECRET.into(),
            )])),
            created_by: "admin".into(),
        })
        .unwrap();
    ResourceAttributeFixture {
        app: build_router(runtime, broker_build_status()),
        admin_token,
        user_token,
        store,
        audit_path,
    }
}

const WEBHOOK_SECRET: &str = "https://test.environment.api.powerplatform.com/private-path-sentinel?sig=query-secret-sentinel";
const REVEAL_ROUTE: &str = "/v1/admin/policy/resources/release/attributes/webhookUrl/reveal";

#[tokio::test]
async fn resource_attribute_admin_reveal_replace_and_redacted_reads() {
    let fixture = resource_attribute_fixture(false);
    let response = catalog_request(
        &fixture.app,
        &fixture.user_token,
        Method::POST,
        REVEAL_ROUTE,
        "attribute-user-denied",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(
        !response_json(response)
            .await
            .to_string()
            .contains(WEBHOOK_SECRET)
    );
    for path in [
        "/v1/admin/policy/resources",
        "/v1/admin/policy/resources/release",
        "/v1/admin/policy/grants/export",
    ] {
        let response = catalog_request(
            &fixture.app,
            &fixture.admin_token,
            Method::GET,
            path,
            "attribute-redacted-read",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            !response_json(response)
                .await
                .to_string()
                .contains(WEBHOOK_SECRET)
        );
    }
    let response = catalog_request(
        &fixture.app,
        &fixture.admin_token,
        Method::POST,
        REVEAL_ROUTE,
        "attribute-admin-reveal",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response_json(response).await["result"]["value"],
        WEBHOOK_SECRET
    );
    let replacement =
        WEBHOOK_SECRET.replace("query-secret-sentinel", "replacement-secret-sentinel");
    let response = catalog_request(
        &fixture.app,
        &fixture.admin_token,
        Method::PATCH,
        "/v1/admin/policy/resources/release",
        "attribute-replace",
        Some(json!({"expectedVersion":1,"attributes":{"webhookUrl":replacement}})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let result = response_json(response).await;
    assert_eq!(
        result["result"]["record"]["configuredAttributes"],
        json!(["webhookUrl"])
    );
    assert!(!result.to_string().contains(&replacement));
    for body in [
        json!({"expectedVersion":2,"attributes":{"webhookUrl":null}}),
        json!({"expectedVersion":2,"attributes":{"webhookUrl":""}}),
        json!({"expectedVersion":2,"attributes":{"webhookUrl":{"secret":WEBHOOK_SECRET}}}),
    ] {
        let response = catalog_request(
            &fixture.app,
            &fixture.admin_token,
            Method::PATCH,
            "/v1/admin/policy/resources/release",
            "attribute-invalid",
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            !response_json(response)
                .await
                .to_string()
                .contains(WEBHOOK_SECRET)
        );
    }
    assert_eq!(fixture.store.resource("release").unwrap().version, 2);
    let audit = std::fs::read_to_string(&fixture.audit_path).unwrap();
    assert!(audit.contains("admin.policy.resources.attribute.reveal"));
    assert!(audit.contains("\"phase\":\"preflight\""));
    // The reveal and the policy export stay audited when they succeed; the
    // redacted resource reads are unaudited.
    assert!(audit.contains("\"action\":\"admin.policy.grants.export\""));
    assert!(!audit.contains("\"action\":\"admin.policy.resources.list\""));
    assert!(!audit.contains("\"action\":\"admin.policy.resources.get\""));
    assert!(!audit.contains("private-path-sentinel"));
    assert!(!audit.contains("query-secret-sentinel"));
    assert!(!audit.contains("replacement-secret-sentinel"));
    let completed = completed_catalog_management(&fixture.audit_path, "attribute-replace");
    assert_eq!(
        completed["change"]["changedFields"],
        json!(["privateAttributes"])
    );
    assert!(completed["change"]["before"].get("attributes").is_none());
    assert!(
        completed["change"]["after"]
            .get("configuredAttributes")
            .is_none()
    );
}

#[tokio::test]
async fn resource_attribute_browser_reveal_requires_csrf_and_audit_before_decrypt() {
    let fixture = resource_attribute_fixture(false);
    let login = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(
                    "127.0.0.1:40111".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "attribute-login")
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"principalId":"admin","password":"admin-password"}"#,
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
        .to_owned();
    let login = response_json(login).await;
    let csrf = login["result"]["csrfToken"].as_str().unwrap();
    for with_csrf in [false, true] {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(REVEAL_ROUTE)
            .extension(ConnectInfo(
                "127.0.0.1:40112".parse::<SocketAddr>().unwrap(),
            ))
            .header(
                REQUEST_ID_HEADER,
                if with_csrf {
                    "attribute-browser-ok"
                } else {
                    "attribute-browser-denied"
                },
            )
            .header("Cookie", &cookie)
            .header("Host", "localhost")
            .header("Origin", "http://localhost");
        if with_csrf {
            request = request.header("X-Agent-Access-CSRF", csrf);
        }
        let response = fixture
            .app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.status(),
            if with_csrf {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        );
        let result = response_json(response).await;
        if with_csrf {
            assert_eq!(result["result"]["value"], WEBHOOK_SECRET);
        } else {
            assert_eq!(result["reasonCode"], "csrf_invalid");
        }
    }
    let fixture = resource_attribute_fixture(true);
    // If decryption were reached, this would return a ciphertext error instead.
    rusqlite::Connection::open(fixture.store.path())
        .unwrap()
        .execute("UPDATE resource_secret_material SET nonce=zeroblob(12)", [])
        .unwrap();
    let response = catalog_request(
        &fixture.app,
        &fixture.admin_token,
        Method::POST,
        REVEAL_ROUTE,
        "attribute-audit-denied",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let result = response_json(response).await;
    assert_eq!(result["reasonCode"], "audit_unavailable");
    assert!(!result.to_string().contains(WEBHOOK_SECRET));
    // While audit writes fail, unaudited reads still succeed and the audited
    // export fails closed like the reveal.
    for (path, status) in [
        ("/v1/admin/policy/resources", StatusCode::OK),
        ("/v1/admin/policy/resources/release", StatusCode::OK),
        (
            "/v1/admin/policy/grants/export",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        let response = catalog_request(
            &fixture.app,
            &fixture.admin_token,
            Method::GET,
            path,
            "attribute-audit-failing-read",
            None,
        )
        .await;
        assert_eq!(response.status(), status, "{path}");
    }
}

#[tokio::test]
async fn teams_policy_catalog_and_grants_need_no_separate_execution_credential() {
    let fixture = resource_attribute_fixture(false);
    let response = catalog_request(
        &fixture.app,
        &fixture.admin_token,
        Method::GET,
        "/v1/admin/policy/catalog",
        "teams-policy-catalog",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let catalog = response_json(response).await;
    let service = catalog["result"]["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "teams")
        .unwrap();
    assert_eq!(service["configuredCredentialModes"], json!(["service"]));
    let created = catalog_request(&fixture.app, &fixture.admin_token, Method::POST,
        "/v1/admin/policy/grants", "teams-policy-create", Some(json!({
            "grantId":"teams-send", "subjects":["user:alice"], "service":"teams",
            "actions":["notification.send"], "executionContexts":["default"],
            "resources":{"resourceIds":["release"],"resourceGroupIds":[]}, "credentialMode":"service"
        }))).await;
    assert_eq!(
        created.status(),
        StatusCode::OK,
        "{}",
        response_json(created).await
    );
}

async fn catalog_audit_fixture() -> BrowserRateFixture {
    browser_rate_fixture_with(LimitsConfig::default(), |config| {
        config.identity.sources[0].header = "Authorization".into();
        config.policy.authority = "managed".into();
        config.policy.grants.clear();
        config.policy.resources.clear();
        config.policy.resource_groups.clear();
    })
    .await
}

fn catalog_management_events(path: &Path, request_id: &str) -> Vec<Value> {
    read_audit_records(path)
        .into_iter()
        .filter(|event| event["agentRequestId"] == request_id)
        .collect()
}

fn completed_catalog_management(path: &Path, request_id: &str) -> Value {
    let events = catalog_management_events(path, request_id);
    assert_eq!(events.len(), 2, "preflight and completion: {events:?}");
    assert_eq!(
        events[0]["providerAudit"]["management"]["phase"],
        "preflight"
    );
    assert!(
        events[0]["providerAudit"]["management"]
            .get("change")
            .is_none()
    );
    assert_eq!(events[1]["providerAudit"]["management"]["phase"], "success");
    assert_eq!(events[0]["brokerRequestId"], events[1]["brokerRequestId"]);
    assert!(events.iter().all(|event| {
        event["providerAudit"]["management"]
            .get("targetService")
            .is_none()
    }));
    events[1]["providerAudit"]["management"].clone()
}

#[tokio::test]
async fn resource_catalog_completion_history_round_trips_sqlite_and_jsonl() {
    // The same actual HTTP create is exercised against both configured writers.
    let sqlite = catalog_audit_fixture().await;
    let jsonl = managed_policy_admin_fixture();
    for (app, token, path) in [
        (&sqlite.app, &sqlite.admin_token, &sqlite.audit_path),
        (&jsonl.app, &jsonl.admin_token, &jsonl.audit_path),
    ] {
        let create = catalog_request(app, token, Method::POST, "/v1/admin/policy/resources", "audit-resource-create", Some(json!({
            "displayName":"Payments repository", "resourceType":"git_repository",
            "selector":{"kind":"exact","value":"audit/payments"}, "allowedExecutionContexts":["default"]
        }))).await;
        assert_eq!(create.status(), StatusCode::OK);
        let create = response_json(create).await;
        let id = create["result"]["record"]["id"].as_str().unwrap();
        assert!(uuid::Uuid::parse_str(id).is_ok());
        let created = completed_catalog_management(path, "audit-resource-create");
        assert_eq!(created["target"]["id"], id);
        assert_eq!(created["target"]["kind"], "resource");
        assert_eq!(created["target"]["displayName"], "Payments repository");
        assert_eq!(created["change"]["revision"], create["result"]["revision"]);
        assert!(created["change"]["before"].is_null());
        let group = catalog_request(app, token, Method::POST, "/v1/admin/policy/resource-groups", "audit-group-create", Some(json!({
            "id":"audit-engineering", "name":"Engineering repositories", "includedResourceIds":[], "excludedResourceIds":[]
        }))).await;
        assert_eq!(group.status(), StatusCode::OK);
        let _ = response_json(group).await;
        let group_created = completed_catalog_management(path, "audit-group-create");
        assert_eq!(
            group_created["target"]["displayName"],
            "Engineering repositories"
        );
        let added = catalog_request(
            app,
            token,
            Method::PATCH,
            "/v1/admin/policy/resource-groups/audit-engineering",
            "audit-group-add",
            Some(json!({
                "expectedVersion":1,"includedResourceIds":[id]
            })),
        )
        .await;
        assert_eq!(added.status(), StatusCode::OK);
        let _ = response_json(added).await;
        let added = completed_catalog_management(path, "audit-group-add");
        assert_eq!(added["change"]["membership"]["includedAdded"]["count"], 1);
        assert_eq!(
            added["change"]["membership"]["includedAdded"]["items"][0]["id"],
            id
        );
        assert_eq!(
            added["change"]["membership"]["includedAdded"]["items"][0]["displayName"],
            "Payments repository"
        );
        assert_eq!(added["change"]["membership"]["excludedAdded"]["count"], 0);
        let rename = catalog_request(
            app,
            token,
            Method::PATCH,
            &format!("/v1/admin/policy/resources/{id}"),
            "audit-resource-rename",
            Some(json!({
                "expectedVersion":1,"displayName":"Renamed payments"
            })),
        )
        .await;
        assert_eq!(rename.status(), StatusCode::OK);
        let _ = response_json(rename).await;
        let renamed = completed_catalog_management(path, "audit-resource-rename");
        assert_eq!(
            renamed["change"]["before"]["displayName"],
            "Payments repository"
        );
        assert_eq!(
            renamed["change"]["after"]["displayName"],
            "Renamed payments"
        );
        assert_eq!(renamed["change"]["changedFields"], json!(["displayName"]));
        let stale = catalog_request(
            app,
            token,
            Method::PATCH,
            &format!("/v1/admin/policy/resources/{id}"),
            "audit-stale",
            Some(json!({"expectedVersion":1,"enabled":false})),
        )
        .await;
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        assert!(catalog_management_events(path, "audit-stale").iter().all(
            |event| event["providerAudit"]["management"]["phase"] != "success"
                && event["providerAudit"]["management"].get("change").is_none()
        ));
        let duplicate = catalog_request(app, token, Method::POST, "/v1/admin/policy/resources", "audit-duplicate", Some(json!({
            "id":"wrong-new-id","displayName":"Uncommitted duplicate","resourceType":"git_repository",
            "selector":{"kind":"exact","value":"audit/payments"},"allowedExecutionContexts":["default"],"enabled":false
        }))).await;
        assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
        let duplicate = response_json(duplicate).await;
        assert_eq!(duplicate["reasonCode"], "input_invalid");
        assert_eq!(duplicate["target"]["conflict"]["id"], id);
        assert_eq!(
            duplicate["target"]["conflict"]["displayName"],
            "Renamed payments"
        );
        assert!(
            duplicate["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Renamed payments")
        );
        assert!(
            catalog_management_events(path, "audit-duplicate")
                .iter()
                .all(|event| event["providerAudit"]["management"]["phase"] != "success")
        );
        let other = catalog_request(
            app, token, Method::POST, "/v1/admin/policy/resources", "audit-other-create",
            Some(json!({"id":"audit-other","resourceType":"git_repository",
                "selector":{"kind":"exact","value":"audit/other"},"allowedExecutionContexts":["default"]})),
        ).await;
        assert_eq!(other.status(), StatusCode::OK);
        let other = response_json(other).await;
        assert_eq!(other["result"]["record"]["version"], 1);
        let other_audit = completed_catalog_management(path, "audit-other-create");
        assert_eq!(other_audit["target"]["displayName"], Value::Null);
        assert!(other_audit["target"].get("displayName").is_some());
        assert_eq!(other_audit["target"]["displayNameTruncated"], false);
        assert_eq!(other_audit["target"]["selector"]["value"], "audit/other");
        let before_status = catalog_request(
            app,
            token,
            Method::GET,
            "/v1/admin/policy/status",
            "audit-before-conflict-status",
            None,
        )
        .await;
        assert_eq!(before_status.status(), StatusCode::OK);
        let before_status = response_json(before_status).await;
        assert_eq!(
            before_status["result"]["policyGeneration"],
            other["result"]["revision"]["generation"]
        );
        assert_eq!(
            before_status["result"]["lastUpdatedAt"],
            other["result"]["revision"]["updatedAt"]
        );
        assert_eq!(
            before_status["result"]["lastUpdatedBy"],
            other["result"]["revision"]["updatedBy"]
        );
        let before_catalog = catalog_request(
            app,
            token,
            Method::GET,
            "/v1/admin/policy/resources",
            "audit-before-conflict-catalog",
            None,
        )
        .await;
        assert_eq!(before_catalog.status(), StatusCode::OK);
        let before_catalog = response_json(before_catalog).await;
        let conflict = catalog_request(
            app,
            token,
            Method::PATCH,
            "/v1/admin/policy/resources/audit-other",
            "audit-duplicate-patch",
            Some(
                json!({"expectedVersion":1,"displayName":"Uncommitted rename","enabled":false,
                "selector":{"kind":"exact","value":"audit/payments"}}),
            ),
        )
        .await;
        assert_eq!(conflict.status(), StatusCode::BAD_REQUEST);
        let conflict = response_json(conflict).await;
        assert_eq!(conflict["reasonCode"], "input_invalid");
        assert_eq!(conflict["target"]["id"], "audit-other");
        assert_eq!(conflict["target"]["conflict"]["id"], id);
        assert_eq!(
            conflict["target"]["conflict"]["displayName"],
            "Renamed payments"
        );
        let conflict_events = catalog_management_events(path, "audit-duplicate-patch");
        assert_eq!(conflict_events.len(), 2, "{conflict_events:?}");
        let preflight = &conflict_events[0]["providerAudit"]["management"];
        assert_eq!(preflight["phase"], "preflight");
        assert_eq!(preflight["target"]["id"], "audit-other");
        let failed = &conflict_events[1]["providerAudit"]["management"];
        assert_eq!(failed["reasonCode"], "input_invalid");
        assert_eq!(failed["target"], conflict["target"]);
        assert!(conflict_events.iter().all(|event| {
            let management = &event["providerAudit"]["management"];
            management["phase"] != "success" && management.get("change").is_none()
        }));
        assert_eq!(
            conflict_events[0]["brokerRequestId"],
            conflict_events[1]["brokerRequestId"]
        );
        let after_status = catalog_request(
            app,
            token,
            Method::GET,
            "/v1/admin/policy/status",
            "audit-after-conflict-status",
            None,
        )
        .await;
        assert_eq!(after_status.status(), StatusCode::OK);
        assert_eq!(
            response_json(after_status).await["result"],
            before_status["result"]
        );
        let after_catalog = catalog_request(
            app,
            token,
            Method::GET,
            "/v1/admin/policy/resources",
            "audit-after-conflict-catalog",
            None,
        )
        .await;
        assert_eq!(after_catalog.status(), StatusCode::OK);
        let after_catalog = response_json(after_catalog).await;
        assert_eq!(after_catalog["result"], before_catalog["result"]);
        let unchanged_other = after_catalog["result"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == "audit-other")
            .unwrap();
        assert_eq!(unchanged_other, &other["result"]["record"]);
        assert_eq!(unchanged_other["version"], 1);

        let delete_group = catalog_request(
            app,
            token,
            Method::DELETE,
            "/v1/admin/policy/resource-groups/audit-engineering?expectedVersion=2",
            "audit-group-delete",
            None,
        )
        .await;
        assert_eq!(delete_group.status(), StatusCode::OK);
        let _ = response_json(delete_group).await;
        let deleted_group = completed_catalog_management(path, "audit-group-delete");
        assert_eq!(
            deleted_group["target"]["displayName"],
            "Engineering repositories"
        );
        assert_eq!(
            deleted_group["change"]["membership"]["includedRemoved"]["items"][0]["displayName"],
            "Renamed payments"
        );
        assert!(deleted_group["change"]["after"].is_null());
        let delete = catalog_request(
            app,
            token,
            Method::DELETE,
            &format!("/v1/admin/policy/resources/{id}?expectedVersion=2"),
            "audit-resource-delete",
            None,
        )
        .await;
        assert_eq!(delete.status(), StatusCode::OK);
        let _ = response_json(delete).await;
        let deleted = completed_catalog_management(path, "audit-resource-delete");
        assert_eq!(deleted["target"]["displayName"], "Renamed payments");
        assert!(deleted["change"]["after"].is_null());
        assert_eq!(completed_catalog_management(path, "audit-group-add"), added);
        assert_eq!(
            completed_catalog_management(path, "audit-resource-create"),
            created
        );
    }
    // New event-time labels are already indexed by SQLite audit search.
    let result = catalog_request(
        &sqlite.app,
        &sqlite.admin_token,
        Method::GET,
        "/v1/admin/audit/events?q=Payments%20repository",
        "audit-search-label",
        None,
    )
    .await;
    assert_eq!(result.status(), StatusCode::OK);
    let result = response_json(result).await;
    assert!(
        result["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["agentRequestId"] == "audit-group-add")
    );
}

#[tokio::test]
async fn resource_catalog_preflight_is_required_but_completion_failure_preserves_commit() {
    for failing_phase in ["preflight", "success"] {
        let fixture = catalog_audit_fixture().await;
        let conn = rusqlite::Connection::open(&fixture.audit_path).unwrap();
        conn.execute_batch(&format!("CREATE TRIGGER fail_catalog_audit BEFORE INSERT ON audit_events WHEN NEW.phase = '{failing_phase}' AND NEW.action = 'admin.policy.resources.create' BEGIN SELECT RAISE(ABORT, 'private-audit-failure'); END;")).unwrap();
        let response = catalog_request(&fixture.app, &fixture.admin_token, Method::POST,
            "/v1/admin/policy/resources", "audit-phase-failure", Some(json!({"id":"new-repo","displayName":"New repository","resourceType":"git_repository","selector":{"kind":"exact","value":"audit/new"},"allowedExecutionContexts":["default"]}))).await;
        let status = response.status();
        let response = response_json(response).await;
        let store = fixture
            .state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .clone();
        if failing_phase == "preflight" {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response["reasonCode"], "audit_unavailable");
            assert!(store.resource("new-repo").is_err());
            assert_eq!(store.policy_revision().unwrap().generation, 0);
        } else {
            assert_eq!(status, StatusCode::OK, "{response}");
            assert_eq!(
                store
                    .resource("new-repo")
                    .unwrap()
                    .definition
                    .display_name
                    .as_deref(),
                Some("New repository")
            );
            assert_eq!(store.policy_revision().unwrap().generation, 1);
            let events = catalog_management_events(&fixture.audit_path, "audit-phase-failure");
            assert_eq!(events.len(), 1);
            assert_eq!(
                events[0]["providerAudit"]["management"]["phase"],
                "preflight"
            );
        }
        assert!(!response.to_string().contains("private-audit-failure"));
    }
}

#[tokio::test]
async fn resource_catalog_mutation_owner_completes_audit_after_waiter_cancellation() {
    use crate::handlers::management::common::{
        ManagementAccess, management_context, management_write_audit_preflight,
    };
    use crate::handlers::management::resources::committed_catalog_mutation;
    let fixture = catalog_audit_fixture().await;
    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", fixture.admin_token)).unwrap(),
    );
    headers.insert(
        REQUEST_ID_HEADER,
        HeaderValue::from_static("catalog-cancelled-waiter"),
    );
    let operation = "admin.policy.resources.create";
    let context = management_context(
        &AppState {
            reloadable: fixture.state.clone(),
        },
        "127.0.0.1:43210".parse().unwrap(),
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    .unwrap();
    management_write_audit_preflight(&context, operation, None)
        .await
        .unwrap();
    let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let waiter = tokio::spawn(committed_catalog_mutation(
        fixture.state.clone(),
        context,
        operation,
        None,
        move |runtime| {
            let result =
                runtime.create_managed_resource(agent_access_core::CreateResourceRequest {
                    id: Some("cancelled-repo".into()),
                    display_name: Some("Committed after cancellation".into()),
                    resource_type: agent_access_core::GIT_REPOSITORY_RESOURCE.id.clone(),
                    selector: ResourceSelector::Exact {
                        value: "audit/cancelled".into(),
                    },
                    allowed_execution_contexts: vec!["default".into()],
                    enabled: true,
                    attributes: agent_access_core::ResourceAttributes::default(),
                    created_by: "admin".into(),
                })?;
            committed_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            Ok(result)
        },
    ));
    committed_rx.await.unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if catalog_management_events(&fixture.audit_path, "catalog-cancelled-waiter").len() == 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let completion = completed_catalog_management(&fixture.audit_path, "catalog-cancelled-waiter");
    assert_eq!(completion["target"]["id"], "cancelled-repo");
    assert_eq!(
        completion["target"]["displayName"],
        "Committed after cancellation"
    );
    assert!(
        fixture
            .state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .resource("cancelled-repo")
            .is_ok()
    );
}
