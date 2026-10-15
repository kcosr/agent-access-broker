//! Command imports through the real router, store, runtime publication and
//! the linked `command` adapter, with a fixture command that records each run.
use super::imports_foundation::{Fixture, fixture, import_broker};
use super::*;
use agent_access_core::imports::ImportedCredentialPurpose;
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, CommandImportConfig,
    ManagedPolicyGrantCreateRequest,
};
use std::path::{Path, PathBuf};

/// A command that appends each subcommand to `$MARKER` and answers
/// `describe` with the manifest in `$MANIFEST`.
const RECORDING_COMMAND: &str = r#"#!/bin/sh
echo "$1" >> "$MARKER"
[ "$1" = describe ] || exit 2
cat "$MANIFEST"
"#;

struct CommandFixture {
    imports: Fixture,
    directory: tempfile::TempDir,
    config: BrokerConfig,
}

impl CommandFixture {
    /// The import fixture with `command` allowed and `name` approved.
    fn new(name: &str, manifest: &Value) -> Self {
        let imports = fixture();
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("command.sh");
        std::fs::write(&script, RECORDING_COMMAND).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut config = imports.config.clone();
        config.imports.allowed_kinds.push("command".into());
        config.command_imports.insert(
            name.into(),
            CommandImportConfig {
                path: script.display().to_string(),
                timeout: "10s".into(),
                max_output_bytes: 1024 * 1024,
                max_concurrent: 4,
                working_dir: "/".into(),
                network: Default::default(),
                log_stderr: false,
                env: BTreeMap::from([
                    ("PATH".into(), "/usr/bin:/bin".into()),
                    (
                        "MARKER".into(),
                        directory.path().join("runs").display().to_string(),
                    ),
                    (
                        "MANIFEST".into(),
                        directory.path().join("manifest.json").display().to_string(),
                    ),
                ]),
            },
        );
        let fixture = Self {
            imports,
            directory,
            config,
        };
        fixture.write_manifest(manifest);
        fixture
    }

    fn write_manifest(&self, manifest: &Value) {
        std::fs::write(self.path("manifest.json"), manifest.to_string()).unwrap();
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    /// The subcommands the command ran, in order.
    fn runs(&self) -> Vec<String> {
        read_runs(&self.path("runs"))
    }

    fn admin_token(&self) -> String {
        self.issue("admin", BrokerTokenClass::Admin, json!({}))
    }

    fn issue(&self, principal: &str, class: BrokerTokenClass, scopes: Value) -> String {
        self.imports
            .runtime
            .managed_store()
            .unwrap()
            .issue_broker_token(
                &BrokerTokenHasher::load(self.config.broker_tokens.as_ref().unwrap()).unwrap(),
                BrokerTokenIssueRequest {
                    principal_id: principal.into(),
                    name: "command imports".into(),
                    token_class: class,
                    scopes,
                    expires_at: None,
                    created_by: "admin".into(),
                },
            )
            .unwrap()
            .token
    }
}

fn read_runs(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|runs| runs.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

async fn request(
    app: &Router,
    token: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let body = body.map(|body| body.to_string());
    let response = authed_json_request(
        app.clone(),
        method,
        path,
        "imports-command",
        "Authorization",
        format!("Bearer {token}"),
        body.as_deref(),
    )
    .await;
    (response.status(), response_json(response).await)
}

fn versions(result: &Value) -> Value {
    json!({"expectedVersion":result["service"]["version"],"expectedCatalogRevision":result["catalogRevision"]})
}

fn definition(service: &str, command: &str, modes: &[&str]) -> Value {
    json!({
        "service": service,
        "displayName": format!("{service} command"),
        "adapterKind": "command",
        "endpoint": format!("command:{command}"),
        "executionBindings": modes.iter().map(|mode| json!({
            "ownerMode": mode, "mechanism": "static_token",
            "delivery": {"kind": "stdin"}, "status": "configured"
        })).collect::<Vec<_>>(),
        "discovery": {"kind": "anonymous"}
    })
}

fn clock_manifest() -> Value {
    json!({
        "format": "agent-access-command/1",
        "version": "1.0.0",
        "oauth": {"issuer": "https://login.example.net"},
        "actions": [
            {"name": "time.now", "description": "Current time.", "readOnly": true,
             "inputSchema": {"type": "object", "additionalProperties": false}},
            {"name": "time.zone", "description": "Current zone.", "readOnly": true,
             "inputSchema": {"type": "object", "additionalProperties": false}}
        ]
    })
}

/// Discovers, accepts every supported tool as a read and returns the result.
async fn discover_and_accept(app: &Router, token: &str, service: &str, current: &Value) -> Value {
    let (status, discovered) = request(
        app,
        token,
        Method::POST,
        &format!("/v1/admin/imports/{service}/discover"),
        Some(versions(current)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{discovered}");
    let discovered = &discovered["result"];
    let mut accept = versions(discovered);
    accept["manifestHash"] = discovered["preview"]["manifestHash"].clone();
    accept["selections"] = json!(
        discovered["preview"]["manifest"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|tool| tool["unsupportedReason"].is_null())
            .map(|tool| json!({"source": tool["definition"]["source"],
                "action": tool["definition"]["action"], "readOnly": true}))
            .collect::<Vec<_>>()
    );
    let (status, accepted) = request(
        app,
        token,
        Method::POST,
        &format!("/v1/admin/imports/{service}/accept"),
        Some(accept),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    accepted["result"].clone()
}

#[cfg(unix)]
#[tokio::test]
async fn credential_free_commands_import_enable_and_publish_without_running_offline() {
    let fixture = CommandFixture::new("clock", &clock_manifest());
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();

    // Operators approve names; administrators can name only those.
    let (status, listed) = request(&app, &token, Method::GET, "/v1/admin/imports", None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(
        listed["result"]["commandImports"],
        json!([{"name": "clock"}])
    );
    assert!(
        listed["result"]["availableKinds"]
            .as_array()
            .unwrap()
            .contains(&json!("command"))
    );
    assert!(!listed.to_string().contains("command.sh"));
    for (body, case) in [
        (definition("unknown", "unknown", &[]), "unapproved name"),
        (definition("pathname", "/bin/sh", &[]), "path"),
        (
            {
                let mut body = definition("mismatch", "clock", &[]);
                body["adapterKind"] = json!("conformance_import");
                body
            },
            "endpoint form of another kind",
        ),
        (
            {
                let mut body = definition("bearer", "clock", &["service"]);
                body["executionBindings"][0]["delivery"] = json!({"kind": "bearer"});
                body
            },
            "bearer delivery",
        ),
    ] {
        let (status, rejected) =
            request(&app, &token, Method::POST, "/v1/admin/imports", Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{case}: {rejected}");
    }
    let (status, created) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports",
        Some(definition("clock", "clock", &[])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert!(fixture.runs().is_empty(), "creation never runs the command");

    // Discovery runs describe exactly once; acceptance stores its metadata.
    let accepted = discover_and_accept(&app, &token, "clock", &created["result"]).await;
    assert_eq!(fixture.runs(), ["describe"]);
    assert_eq!(accepted["commandVersion"], "1.0.0");
    assert_eq!(
        accepted["service"]["acceptedMetadata"],
        json!({"format": "agent-access-command/1", "version": "1.0.0", "credential": null,
            "verify": false, "resourceTypes": []})
    );
    assert_eq!(accepted["service"]["actions"].as_array().unwrap().len(), 2);

    // A command without a credential enables without one.
    let mut enable = versions(&accepted);
    enable["status"] = json!("enabled");
    let (status, enabled) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/clock/status",
        Some(enable),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");
    assert_eq!(enabled["result"]["available"], true, "{enabled}");
    let published = broker.runtime();
    assert_eq!(published.imported_service_unavailable_reason("clock"), None);
    assert!(published.command_provider("clock").is_some());
    drop((published, app));
    broker.stop().await;

    // Startup rebuilds the import offline, without running the command, and
    // service-mode grants select it without a credential.
    let restarted = BrokerRuntime::new(fixture.config.clone()).unwrap();
    assert_eq!(restarted.imported_service_unavailable_reason("clock"), None);
    assert!(restarted.imported_mode_available("clock", "service"));
    assert!(!restarted.imported_mode_available("clock", "per_user"));
    assert!(restarted.command_provider("clock").is_some());
    restarted
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: Some("clock-alice".into()),
            subjects: vec!["user:alice".into()],
            execution_contexts: vec!["default".into()],
            service: "clock".into(),
            actions: vec!["time.now".into()],
            resources: ResourceSelection::default(),
            credential_mode: "service".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap();
    assert_eq!(fixture.runs(), ["describe"]);

    // The call is admitted and fails closed before any process starts.
    let agent = fixture.issue(
        "alice",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedServices":["clock"],"allowedExecutionContexts":["default"]}),
    );
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let (status, failed) = request(
        &app,
        &agent,
        Method::POST,
        "/v1/invoke/clock/time.now",
        Some(json!({"inputs": {}})),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{failed}");
    assert_eq!(failed["reasonCode"], "operation_failed", "{failed}");
    // A reload stays offline too.
    broker.reload_config(&fixture.config).await;
    assert_eq!(fixture.runs(), ["describe"]);

    // Refresh: a changed action is quarantined, a missing one too, and a new
    // one stays unselected.
    let current = request(&app, &token, Method::GET, "/v1/admin/imports/clock", None)
        .await
        .1;
    let mut manifest = clock_manifest();
    manifest["actions"] = json!([
        {"name": "time.now", "description": "Current time.", "readOnly": true,
         "inputSchema": {"type": "object", "properties": {"zone": {"type": "string"}}}},
        {"name": "time.add", "description": "Add a duration.",
         "inputSchema": {"type": "object"}}
    ]);
    fixture.write_manifest(&manifest);
    let (status, refreshed) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/clock/discover",
        Some(versions(&current["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    let statuses = refreshed["result"]["service"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|action| {
            (
                action["definition"]["action"].as_str().unwrap().to_owned(),
                action["status"].as_str().unwrap().to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        statuses,
        BTreeMap::from([
            ("time.now".to_owned(), "quarantined".to_owned()),
            ("time.zone".to_owned(), "quarantined".to_owned()),
        ])
    );
    assert_eq!(fixture.runs(), ["describe", "describe"]);

    // Adding a credential, or an unknown format, fails discovery.
    for (manifest, expected) in [
        (
            {
                let mut manifest = clock_manifest();
                manifest["credential"] = json!({"kind": "token", "modes": ["service"]});
                manifest
            },
            "create a new import",
        ),
        (
            {
                let mut manifest = clock_manifest();
                manifest["format"] = json!("agent-access-command/2");
                manifest
            },
            "format",
        ),
    ] {
        fixture.write_manifest(&manifest);
        let current = request(&app, &token, Method::GET, "/v1/admin/imports/clock", None)
            .await
            .1;
        let (status, failed) = request(
            &app,
            &token,
            Method::POST,
            "/v1/admin/imports/clock/discover",
            Some(versions(&current["result"])),
        )
        .await;
        assert_ne!(status, StatusCode::OK, "{failed}");
        assert!(failed.to_string().contains(expected), "{failed}");
        assert!(!failed.to_string().contains("command.sh"), "{failed}");
    }
    drop(app);
    broker.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn username_token_commands_store_a_username_with_the_service_slot() {
    let manifest = json!({
        "format": "agent-access-command/1",
        "version": "3.1.0",
        "credential": {"kind": "username_token", "modes": ["service", "per_user"]},
        "verify": true,
        "actions": [
            {"name": "issue.view", "description": "Show one issue.", "readOnly": true,
             "inputSchema": {"type": "object", "required": ["issue"],
                "properties": {"issue": {"type": "integer"}}}}
        ]
    });
    let fixture = CommandFixture::new("tickets", &manifest);
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let (status, created) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports",
        Some(definition("tickets", "tickets", &["service"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    // The credential kind is known only once the manifest is accepted.
    let mut early = versions(&created["result"]);
    early["token"] = json!("svc-example");
    early["username"] = json!("svc-tickets");
    let (status, rejected) = request(
        &app,
        &token,
        Method::PUT,
        "/v1/admin/imports/tickets/credentials/execution",
        Some(early),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    let accepted = discover_and_accept(&app, &token, "tickets", &created["result"]).await;
    let mut enable = versions(&accepted);
    enable["status"] = json!("enabled");
    let (status, unprovisioned) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/tickets/status",
        Some(enable),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{unprovisioned}");
    let mut secret = versions(&accepted);
    secret["token"] = json!("svc-example");
    let (status, rejected) = request(
        &app,
        &token,
        Method::PUT,
        "/v1/admin/imports/tickets/credentials/execution",
        Some(secret.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    secret["username"] = json!("svc-tickets");
    let (status, stored) = request(
        &app,
        &token,
        Method::PUT,
        "/v1/admin/imports/tickets/credentials/execution",
        Some(secret),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{stored}");
    assert!(!stored.to_string().contains("svc-example"));
    let mut enable = versions(&stored["result"]);
    enable["status"] = json!("enabled");
    let (status, enabled) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/tickets/status",
        Some(enable),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");
    drop(app);
    broker.stop().await;

    let restarted = BrokerRuntime::new(fixture.config.clone()).unwrap();
    let record = restarted
        .imported_catalog()
        .service("tickets")
        .unwrap()
        .clone();
    let credential = restarted
        .managed_store()
        .unwrap()
        .resolve_imported_secret(
            "tickets",
            ImportedCredentialPurpose::Execution,
            &record.slot_versions[&ImportedCredentialPurpose::Execution],
            restarted.credential_key_ring().unwrap(),
        )
        .unwrap();
    assert_eq!(
        credential,
        agent_access_provider::test_support::basic_credential("svc-tickets", "svc-example")
    );
    assert!(restarted.imported_mode_available("tickets", "service"));
    assert_eq!(fixture.runs(), ["describe"]);
}

/// Creates, discovers, accepts and enables `clock`, returning the enabled
/// result.
async fn enabled_clock(app: &Router, token: &str) -> Value {
    let (status, created) = request(
        app,
        token,
        Method::POST,
        "/v1/admin/imports",
        Some(definition("clock", "clock", &[])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let accepted = discover_and_accept(app, token, "clock", &created["result"]).await;
    let mut enable = versions(&accepted);
    enable["status"] = json!("enabled");
    let (status, enabled) = request(
        app,
        token,
        Method::POST,
        "/v1/admin/imports/clock/status",
        Some(enable),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");
    enabled["result"].clone()
}

#[cfg(unix)]
#[tokio::test]
async fn refresh_acceptance_of_an_enabled_command_publishes_its_new_metadata() {
    let fixture = CommandFixture::new("clock", &clock_manifest());
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let enabled = enabled_clock(&app, &token).await;
    assert_eq!(enabled["commandVersion"], "1.0.0");

    // The command is upgraded in place; its actions are unchanged.
    let mut manifest = clock_manifest();
    manifest["version"] = json!("1.1.0");
    fixture.write_manifest(&manifest);
    let accepted = discover_and_accept(&app, &token, "clock", &enabled).await;
    assert_eq!(accepted["commandVersion"], "1.1.0", "{accepted}");
    assert_eq!(accepted["service"]["status"], "enabled", "{accepted}");
    assert_eq!(accepted["available"], true, "{accepted}");
    let published = broker.runtime();
    let record = published.imported_catalog().service("clock").unwrap();
    assert_eq!(record.accepted_metadata.as_ref().unwrap().version, "1.1.0");
    assert_eq!(published.imported_service_unavailable_reason("clock"), None);
    assert!(published.command_provider("clock").is_some());
    drop((published, app));
    broker.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn refresh_keeps_grants_and_reacceptance_requires_confirming_them() {
    let fixture = CommandFixture::new("clock", &clock_manifest());
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let enabled = enabled_clock(&app, &token).await;
    broker
        .runtime()
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: Some("clock-alice".into()),
            subjects: vec!["user:alice".into()],
            execution_contexts: vec!["default".into()],
            service: "clock".into(),
            actions: vec!["time.now".into()],
            resources: ResourceSelection::default(),
            credential_mode: "service".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap();
    let grant_active = || {
        fixture
            .imports
            .runtime
            .managed_store()
            .unwrap()
            .policy_grants()
            .unwrap()
            .into_iter()
            .any(|grant| grant.grant_id == "clock-alice" && grant.status == "active")
    };
    assert!(grant_active());

    // A behavioral change quarantines the action and keeps its grant.
    let mut manifest = clock_manifest();
    manifest["actions"][0]["inputSchema"] =
        json!({"type": "object", "properties": {"zone": {"type": "string"}}});
    fixture.write_manifest(&manifest);
    let (status, refreshed) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/clock/discover",
        Some(versions(&enabled)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    let refreshed = &refreshed["result"];
    let now = refreshed["service"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["definition"]["action"] == "time.now")
        .unwrap();
    assert_eq!(now["status"], "quarantined");
    assert_eq!(
        refreshed["affectedGrantsByAction"]["time.now"],
        json!(["clock-alice"])
    );
    assert!(grant_active());

    // Accepting the changed action needs confirmAffectedGrants.
    let tool = refreshed["preview"]["manifest"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["definition"]["action"] == "time.now")
        .unwrap()
        .clone();
    let mut accept = versions(refreshed);
    accept["manifestHash"] = refreshed["preview"]["manifestHash"].clone();
    accept["selections"] = json!([{"source": tool["definition"]["source"],
        "action": "time.now", "readOnly": true}]);
    let (status, unconfirmed) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/clock/accept",
        Some(accept.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{unconfirmed}");
    assert!(
        unconfirmed.to_string().contains("confirmAffectedGrants"),
        "{unconfirmed}"
    );
    accept["confirmAffectedGrants"] = json!(true);
    let (status, confirmed) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/clock/accept",
        Some(accept),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{confirmed}");
    let now = confirmed["result"]["service"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["definition"]["action"] == "time.now")
        .unwrap()
        .clone();
    assert_eq!(now["status"], "enabled");
    assert!(grant_active());
    drop(app);
    broker.stop().await;
}
