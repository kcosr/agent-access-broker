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

pub(super) struct CommandFixture {
    pub(super) imports: Fixture,
    directory: tempfile::TempDir,
    pub(super) config: BrokerConfig,
}

impl CommandFixture {
    /// The import fixture with `command` allowed and `name` approved.
    pub(super) fn new(name: &str, manifest: &Value) -> Self {
        Self::with_script(name, manifest, RECORDING_COMMAND)
    }

    /// [`Self::new`] running `script`, which gets `$MARKER` and `$MANIFEST`.
    pub(super) fn with_script(name: &str, manifest: &Value, script_text: &str) -> Self {
        let imports = fixture();
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("command.sh");
        std::fs::write(&script, script_text).unwrap();
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
                max_download_bytes: None,
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

    pub(super) fn write_manifest(&self, manifest: &Value) {
        std::fs::write(self.path("manifest.json"), manifest.to_string()).unwrap();
    }

    pub(super) fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    /// The subcommands the command ran, in order.
    pub(super) fn runs(&self) -> Vec<String> {
        read_runs(&self.path("runs"))
    }

    pub(super) fn admin_token(&self) -> String {
        self.issue("admin", BrokerTokenClass::Admin, json!({}))
    }

    pub(super) fn issue(&self, principal: &str, class: BrokerTokenClass, scopes: Value) -> String {
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

pub(super) async fn request(
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

/// Checks a successful acceptance's result against the result schema the
/// accept route publishes.
pub(super) fn assert_published_accept_result(result: &Value) {
    let routes = agent_access_core::http_route_specs(crate::backend_registry().resource_types());
    let schema = routes
        .iter()
        .find(|route| route.operation == "admin.imports.accept")
        .and_then(|route| route.result_schema.clone())
        .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors = validator
        .iter_errors(result)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "{errors:?}: {result}");
}

pub(super) fn versions(result: &Value) -> Value {
    json!({"expectedVersion":result["service"]["version"],"expectedCatalogRevision":result["catalogRevision"]})
}

pub(super) fn definition(service: &str, command: &str, modes: &[&str]) -> Value {
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

#[cfg(unix)]
#[tokio::test]
async fn command_live_listing_is_reviewed_persisted_and_advertised_only_with_its_own_authority() {
    let mut manifest = json!({
        "format": "agent-access-command/1", "version": "1.0.0",
        "resourceTypes": [{"id": "project", "label": "Project", "pluralLabel": "Projects",
            "example": "OPS", "pattern": "[A-Z]+", "maxLength": 32}],
        "actions": [
            {"name": "projects.enumerate", "description": "Enumerate projects.", "readOnly": true,
                "inputSchema": {"type": "object", "additionalProperties": false},
                "resources": {"type": "project"}, "listingOf": "project"},
            {"name": "issue.view", "description": "View an issue.", "readOnly": true,
                "inputSchema": {"type": "object", "required": ["project"],
                    "properties": {"project": {"type": "string"}}, "additionalProperties": false},
                "resources": {"type": "project", "inputs": ["/project"]}}
        ]
    });
    let fixture = CommandFixture::new("tickets", &manifest);
    let admin = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let (status, created) = request(
        &app,
        &admin,
        Method::POST,
        "/v1/admin/imports",
        Some(definition("tickets", "tickets", &[])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let (status, discovered) = request(
        &app,
        &admin,
        Method::POST,
        "/v1/admin/imports/tickets/discover",
        Some(versions(&created["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{discovered}");
    let discovered = &discovered["result"];
    let tools = discovered["preview"]["manifest"]["tools"]
        .as_array()
        .unwrap();
    let listing = tools
        .iter()
        .find(|tool| tool["definition"]["action"] == "projects.enumerate")
        .unwrap();
    assert!(listing["unsupportedReason"].is_null(), "{listing}");
    assert_eq!(
        listing["definition"]["annotations"]["command"]["listingOf"],
        "project"
    );
    assert_eq!(
        listing["definition"]["readOnly"], false,
        "source hints do not classify effects"
    );
    let mut accept = versions(discovered);
    accept["manifestHash"] = discovered["preview"]["manifestHash"].clone();
    accept["resourceTypeIds"] = json!({"project": "inventory_project"});
    accept["selections"] = json!([
        {"source": {"name": "projects.enumerate"}, "action": "projects.enumerate", "readOnly": false},
        {"source": {"name": "issue.view"}, "action": "issue.view", "readOnly": true}
    ]);
    let (status, rejected) = request(
        &app,
        &admin,
        Method::POST,
        "/v1/admin/imports/tickets/accept",
        Some(accept.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert!(
        rejected.to_string().contains("reviewed read-only"),
        "{rejected}"
    );
    accept["selections"][0]["readOnly"] = json!(true);
    let (status, accepted) = request(
        &app,
        &admin,
        Method::POST,
        "/v1/admin/imports/tickets/accept",
        Some(accept),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert_published_accept_result(&accepted["result"]);
    assert_eq!(
        accepted["result"]["service"]["acceptedMetadata"]["resourceTypes"][0]["brokerType"],
        "inventory_project"
    );
    let mut enable = versions(&accepted["result"]);
    enable["status"] = json!("enabled");
    let (status, enabled) = request(
        &app,
        &admin,
        Method::POST,
        "/v1/admin/imports/tickets/status",
        Some(enable),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");

    let resource_type = agent_access_provider::ResourceType::new("inventory_project").unwrap();
    broker
        .runtime()
        .create_managed_resource(agent_access_core::CreateResourceRequest {
            id: Some("all-projects".into()),
            display_name: None,
            resource_type,
            selector: agent_access_provider::ResourceSelector::All,
            allowed_execution_contexts: vec!["default".into()],
            enabled: true,
            attributes: Default::default(),
            created_by: "admin".into(),
        })
        .unwrap();
    let grant = |id: &str, action: &str| ManagedPolicyGrantCreateRequest {
        grant_id: Some(id.into()),
        subjects: vec!["user:alice".into()],
        execution_contexts: vec!["default".into()],
        service: "tickets".into(),
        actions: vec![action.into()],
        resources: ResourceSelection {
            resource_ids: vec!["all-projects".into()],
            resource_group_ids: vec![],
        },
        credential_mode: "service".into(),
        priority: None,
        status: None,
        description: None,
        created_by: "admin".into(),
    };
    broker
        .runtime()
        .create_managed_policy_grant(grant("inspect", "issue.view"))
        .unwrap();
    let agent = fixture.issue(
        "alice",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedServices": ["tickets"], "allowedExecutionContexts": ["default"]}),
    );
    let path = "/v1/services/tickets/resource-access?action=issue.view";
    let (status, without_listing) = request(&app, &agent, Method::GET, path, None).await;
    assert_eq!(status, StatusCode::OK, "{without_listing}");
    assert!(
        without_listing.get("liveListings").is_none(),
        "{without_listing}"
    );
    assert_eq!(
        without_listing["access"][0]["resourceType"],
        "inventory_project"
    );
    assert_eq!(without_listing["executionContext"], "default");
    assert_eq!(without_listing["availability"]["state"], "available");
    assert_eq!(without_listing["access"][0]["enforcement"], "request");
    broker
        .runtime()
        .create_managed_policy_grant(grant("enumerate", "projects.enumerate"))
        .unwrap();
    let (status, with_listing) = request(&app, &agent, Method::GET, path, None).await;
    assert_eq!(status, StatusCode::OK, "{with_listing}");
    let expected = json!([{"service": "tickets", "action": "projects.enumerate", "resourceType": "inventory_project"}]);
    assert_eq!(with_listing["liveListings"], expected);
    let (status, listing_access) = request(
        &app,
        &agent,
        Method::GET,
        "/v1/services/tickets/resource-access?action=projects.enumerate",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listing_access}");
    assert_eq!(listing_access["access"][0]["enforcement"], "command");
    let restricted = fixture.issue(
        "alice",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedServices": ["tickets"], "allowedExecutionContexts": ["default"],
            "serviceRestrictions": {"tickets": {"actions": ["issue.view"]}}}),
    );
    let (status, restricted) = request(&app, &restricted, Method::GET, path, None).await;
    assert_eq!(status, StatusCode::OK, "{restricted}");
    assert!(restricted.get("liveListings").is_none(), "{restricted}");
    assert_eq!(
        fixture.runs(),
        ["describe"],
        "local access discovery never executes the command"
    );
    drop(app);
    broker.stop().await;

    // Accepted annotations and the chosen Broker type ID survive startup and
    // reload without rediscovering or running the approved command.
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let record = broker
        .runtime()
        .imported_catalog()
        .service("tickets")
        .unwrap()
        .clone();
    let listing = record
        .actions
        .iter()
        .find(|action| action.definition.action == "projects.enumerate")
        .unwrap();
    assert_eq!(
        listing.definition.annotations["command"]["listingOf"],
        "project"
    );
    assert!(listing.definition.read_only);
    assert_eq!(
        record.accepted_metadata.unwrap().resource_types[0].broker_type,
        "inventory_project"
    );
    broker.reload_config(&fixture.config).await;
    let (status, reloaded) = request(&app, &agent, Method::GET, path, None).await;
    assert_eq!(status, StatusCode::OK, "{reloaded}");
    assert_eq!(reloaded["liveListings"], expected);
    assert_eq!(fixture.runs(), ["describe"]);

    // Removing only the explicit listing annotation changes behavior. The
    // accepted identity and grant remain, but the action is quarantined and
    // its link disappears until a fresh review accepts the declaration.
    manifest["actions"][0]
        .as_object_mut()
        .unwrap()
        .remove("listingOf");
    fixture.write_manifest(&manifest);
    let (status, current) =
        request(&app, &admin, Method::GET, "/v1/admin/imports/tickets", None).await;
    assert_eq!(status, StatusCode::OK, "{current}");
    let (status, refreshed) = request(
        &app,
        &admin,
        Method::POST,
        "/v1/admin/imports/tickets/discover",
        Some(versions(&current["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    let refreshed = &refreshed["result"];
    let listing = refreshed["service"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["definition"]["action"] == "projects.enumerate")
        .unwrap();
    assert_eq!(listing["status"], "quarantined");
    assert_eq!(
        refreshed["affectedGrantsByAction"]["projects.enumerate"],
        json!(["enumerate"])
    );
    let (status, quarantined) = request(&app, &agent, Method::GET, path, None).await;
    assert_eq!(status, StatusCode::OK, "{quarantined}");
    assert!(quarantined.get("liveListings").is_none(), "{quarantined}");
    let mut accept = versions(refreshed);
    accept["manifestHash"] = refreshed["preview"]["manifestHash"].clone();
    accept["confirmAffectedGrants"] = json!(true);
    accept["selections"] = json!([{"source": {"name": "projects.enumerate"},
        "action": "projects.enumerate", "readOnly": true}]);
    let (status, accepted) = request(
        &app,
        &admin,
        Method::POST,
        "/v1/admin/imports/tickets/accept",
        Some(accept),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    let (status, undeclared) = request(&app, &agent, Method::GET, path, None).await;
    assert_eq!(status, StatusCode::OK, "{undeclared}");
    assert!(undeclared.get("liveListings").is_none(), "{undeclared}");
    assert_eq!(fixture.runs(), ["describe", "describe"]);
    drop(app);
    broker.stop().await;
}

/// Discovers, accepts every supported tool as a read and returns the result.
pub(super) async fn discover_and_accept(
    app: &Router,
    token: &str,
    service: &str,
    current: &Value,
) -> Value {
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
    assert_published_accept_result(&accepted["result"]);
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

    // The call is admitted and runs its process, which the recording command
    // fails.
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
    assert_eq!(fixture.runs(), ["describe", "invoke"]);
    // A reload stays offline too.
    broker.reload_config(&fixture.config).await;
    assert_eq!(fixture.runs(), ["describe", "invoke"]);

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
    assert_eq!(fixture.runs(), ["describe", "invoke", "describe"]);

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

#[cfg(unix)]
#[tokio::test]
async fn credential_modes_stay_within_the_accepted_declaration() {
    let manifest = json!({
        "format": "agent-access-command/1",
        "version": "1.0.0",
        "credential": {"kind": "token", "modes": ["service"]},
        "actions": [
            {"name": "issue.view", "description": "Show one issue.", "readOnly": true,
             "inputSchema": {"type": "object"}}
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
    let accepted = discover_and_accept(&app, &token, "tickets", &created["result"]).await;
    // The command declares only service mode; a personal binding is refused.
    let mut update = versions(&accepted);
    update["definition"] = definition("tickets", "tickets", &["service", "per_user"]);
    update["confirmAffectedGrants"] = json!(true);
    let (status, refused) = request(
        &app,
        &token,
        Method::PATCH,
        "/v1/admin/imports/tickets",
        Some(update),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        refused.to_string().contains("credential modes"),
        "{refused}"
    );
    let current = request(&app, &token, Method::GET, "/v1/admin/imports/tickets", None)
        .await
        .1;
    assert_eq!(
        current["result"]["service"]["definition"]["executionBindings"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    drop(app);
    broker.stop().await;
}

/// Initializes an HTTP MCP session for `token` and returns its tool names.
pub(super) async fn mcp_tool_names(app: &Router, token: &str) -> Vec<String> {
    let send = |message: Value, session: Option<&str>| {
        let request = super::mcp::request(Method::POST, Some(token), session, Some(message));
        tower::ServiceExt::oneshot(app.clone(), request)
    };
    let initialized = send(
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "command-authority", "version": "1"}}}),
        None,
    )
    .await
    .unwrap();
    assert_eq!(initialized.status(), StatusCode::OK);
    let session = initialized.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    send(
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        Some(&session),
    )
    .await
    .unwrap();
    let listed = super::mcp::rpc_body(
        send(
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            Some(&session),
        )
        .await
        .unwrap(),
    )
    .await;
    listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect()
}

pub(super) fn command_grant(
    id: &str,
    subject: &str,
    action: &str,
    mode: &str,
    priority: i32,
) -> ManagedPolicyGrantCreateRequest {
    ManagedPolicyGrantCreateRequest {
        grant_id: Some(id.into()),
        subjects: vec![subject.into()],
        execution_contexts: vec!["default".into()],
        service: "tickets".into(),
        actions: vec![action.into()],
        resources: ResourceSelection::default(),
        credential_mode: mode.into(),
        priority: Some(priority),
        status: None,
        description: None,
        created_by: "admin".into(),
    }
}

/// An untyped command-enforced action passes every top-band grant with its
/// own credential: personal and service grants of two groups together, the
/// service grant alone while the personal credential is missing, and nothing
/// from a lower band. Catalog and MCP discovery list exactly the callers
/// invocation admits; admitted calls run their process, which the recording
/// command fails.
#[cfg(unix)]
#[tokio::test]
async fn command_enforced_grants_mix_credential_modes_and_discovery_agrees() {
    let manifest = json!({
        "format": "agent-access-command/1",
        "version": "1.0.0",
        "credential": {"kind": "token", "modes": ["service", "per_user"]},
        "actions": [
            {"name": "issue.stats", "description": "Issue statistics.", "readOnly": true,
             "inputSchema": {"type": "object", "additionalProperties": false}},
            {"name": "issue.mine", "description": "My issues.", "readOnly": true,
             "credentialModes": ["per_user"],
             "inputSchema": {"type": "object", "additionalProperties": false}}
        ]
    });
    let mut fixture = CommandFixture::new("tickets", &manifest);
    fixture.config.mcp.enabled = true;
    fixture.config.mcp.public_url = Some("https://broker.example.test/mcp".into());
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let (status, created) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports",
        Some(definition("tickets", "tickets", &["service", "per_user"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let accepted = discover_and_accept(&app, &token, "tickets", &created["result"]).await;
    let mut secret = versions(&accepted);
    secret["token"] = json!("svc-example");
    let (status, stored) = request(
        &app,
        &token,
        Method::PUT,
        "/v1/admin/imports/tickets/credentials/execution",
        Some(secret),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{stored}");
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

    let runtime = broker.runtime();
    let store = runtime.managed_store().unwrap();
    for group in ["eng", "ops"] {
        store
            .create_group(agent_access_core::GroupWriteRequest {
                group_id: group.into(),
                display_name: None,
                description: None,
                auto_enroll_new_microsoft_users: false,
                created_by: "admin".into(),
            })
            .unwrap();
    }
    for (principal, groups) in [
        ("alice", &["eng", "ops"][..]),
        ("charlie", &["eng", "ops"][..]),
        ("bob", &["eng"][..]),
    ] {
        for group in groups {
            store.add_group(principal, group, "admin").unwrap();
        }
    }
    store
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            CredentialWriteRequest {
                owner_principal_id: "alice".into(),
                service: "tickets".into(),
                name: "default".into(),
                profile: "token".into(),
                credential_kind: "bearer_token".into(),
                secret: json!({"token": "alice-example"}),
                metadata: json!({}),
                actor: "admin".into(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    for grant in [
        command_grant("stats-eng-user", "group:eng", "issue.stats", "per_user", 10),
        command_grant(
            "stats-ops-service",
            "group:ops",
            "issue.stats",
            "service",
            10,
        ),
        command_grant("stats-eng-low", "group:eng", "issue.stats", "service", 0),
        command_grant("mine-eng-user", "group:eng", "issue.mine", "per_user", 0),
        // One subject may hold both modes at one priority for a
        // command-enforced action: both grants are passed.
        command_grant(
            "stats-alice-user",
            "user:alice",
            "issue.stats",
            "per_user",
            0,
        ),
        command_grant(
            "stats-alice-service",
            "user:alice",
            "issue.stats",
            "service",
            0,
        ),
    ] {
        runtime.create_managed_policy_grant(grant).unwrap();
    }
    // The personal-only action accepts no service-mode grant.
    assert!(
        runtime
            .create_managed_policy_grant(command_grant(
                "mine-ops-service",
                "group:ops",
                "issue.mine",
                "service",
                0
            ))
            .is_err()
    );
    drop(runtime);

    let scopes = json!({"allowedServices": ["tickets"], "allowedExecutionContexts": ["default"]});
    for (principal, stats, mine, availability) in [
        // Both credentials are present: both grants are passed.
        ("alice", "operation_failed", "operation_failed", "available"),
        // No personal credential: the service grant alone is passed.
        (
            "charlie",
            "operation_failed",
            "credential_not_provisioned",
            "partial",
        ),
        // Only the personal grant is in the top band; the lower service grant
        // is never consulted.
        (
            "bob",
            "credential_not_provisioned",
            "credential_not_provisioned",
            "unavailable",
        ),
    ] {
        let agent = fixture.issue(principal, BrokerTokenClass::AgentInvoke, scopes.clone());
        for (action, expected) in [("issue.stats", stats), ("issue.mine", mine)] {
            let (_, outcome) = request(
                &app,
                &agent,
                Method::POST,
                &format!("/v1/invoke/tickets/{action}"),
                Some(json!({"inputs": {}})),
            )
            .await;
            assert_eq!(
                outcome["reasonCode"], expected,
                "{principal} {action}: {outcome}"
            );
        }
        let (status, discovered) =
            request(&app, &agent, Method::GET, "/v1/services/tickets", None).await;
        let listed = if status == StatusCode::OK {
            assert_eq!(
                discovered["availability"]["state"], availability,
                "{principal}: {discovered}"
            );
            discovered["actions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|action| action["action"].as_str().unwrap().to_owned())
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        let admitted = [("issue.stats", stats), ("issue.mine", mine)]
            .into_iter()
            .filter(|(_, outcome)| *outcome == "operation_failed")
            .map(|(action, _)| action.to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(listed, admitted, "{principal}: {discovered}");
        let tools = mcp_tool_names(&app, &agent).await;
        for action in ["issue.stats", "issue.mine"] {
            let tool = action.replace('.', "_");
            assert_eq!(
                tools.iter().any(|name| name.ends_with(&tool)),
                admitted.contains(action),
                "{principal} {action}: {tools:?}"
            );
        }
        if principal == "alice" {
            let (status, catalog) =
                request(&app, &token, Method::GET, "/v1/admin/policy/catalog", None).await;
            assert_eq!(status, StatusCode::OK, "{catalog}");
            let tickets = catalog["result"]["services"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["service"] == "tickets")
                .unwrap();
            for action in tickets["actions"].as_array().unwrap() {
                assert_eq!(action["resourcesCheckedBy"], "command", "{action}");
            }
            let mine = discovered["actions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|action| action["action"] == "issue.mine")
                .unwrap();
            assert_eq!(mine["credentialModes"], json!(["per_user"]));
        }
    }
    drop(app);
    broker.stop().await;
    // The recording command fails every call, so the passed grants are
    // visible in audit: alice's call passed both modes and records none;
    // charlie's passed the service grant alone.
    let audit = fixture.config.audit.as_ref().unwrap().path.clone();
    let modes = read_audit_records(Path::new(&audit))
        .into_iter()
        .filter(|record| record["service"] == "tickets" && record["action"] == "issue.stats")
        .map(|record| {
            (
                record["principal"].as_str().unwrap().to_owned(),
                (
                    record.get("credentialMode").cloned().unwrap_or(Value::Null),
                    record
                        .get("credentialConnection")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    // Alice's call passed her personal credential beside the service one:
    // its mode is null, but it names the import's credential connection.
    assert_eq!(modes["alice"], (Value::Null, json!("tickets")), "{modes:?}");
    // Charlie's passed only the service grant, so no connection is named.
    assert_eq!(
        modes["charlie"],
        (json!("service"), Value::Null),
        "{modes:?}"
    );
}

#[tokio::test]
async fn command_enforced_personal_grants_pass_alone_without_a_service_slot() {
    let manifest = json!({
        "format": "agent-access-command/1",
        "version": "1.0.0",
        "credential": {"kind": "token", "modes": ["service", "per_user"]},
        "actions": [
            {"name": "issue.stats", "description": "Issue statistics.", "readOnly": true,
             "inputSchema": {"type": "object", "additionalProperties": false}}
        ]
    });
    let fixture = CommandFixture::new("tickets", &manifest);
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let enabled = enabled_tickets(&app, &token, &["service", "per_user"]).await;

    let runtime = broker.runtime();
    let store = runtime.managed_store().unwrap();
    store
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            CredentialWriteRequest {
                owner_principal_id: "alice".into(),
                service: "tickets".into(),
                name: "default".into(),
                profile: "token".into(),
                credential_kind: "bearer_token".into(),
                secret: json!({"token": "alice-example"}),
                metadata: json!({}),
                actor: "admin".into(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    for grant in [
        command_grant(
            "stats-alice-user",
            "user:alice",
            "issue.stats",
            "per_user",
            0,
        ),
        command_grant(
            "stats-alice-service",
            "user:alice",
            "issue.stats",
            "service",
            0,
        ),
    ] {
        runtime.create_managed_policy_grant(grant).unwrap();
    }
    drop(runtime);
    // Removing the service slot leaves the service grant retained but its
    // credential unavailable; the personal mode stays available.
    let (status, removed) = request(
        &app,
        &token,
        Method::DELETE,
        "/v1/admin/imports/tickets/credentials/execution",
        Some(versions(&enabled)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{removed}");

    let scopes = json!({"allowedServices": ["tickets"], "allowedExecutionContexts": ["default"]});
    let agent = fixture.issue("alice", BrokerTokenClass::AgentInvoke, scopes);
    let (_, outcome) = request(
        &app,
        &agent,
        Method::POST,
        "/v1/invoke/tickets/issue.stats",
        Some(json!({"inputs": {}})),
    )
    .await;
    // The recording command fails every call it receives.
    assert_eq!(outcome["reasonCode"], "operation_failed", "{outcome}");
    drop(app);
    broker.stop().await;
    let audit = fixture.config.audit.as_ref().unwrap().path.clone();
    let record = read_audit_records(Path::new(&audit))
        .into_iter()
        .find(|record| record["service"] == "tickets" && record["action"] == "issue.stats")
        .unwrap();
    // Only the personal grant passed.
    assert_eq!(record["credentialMode"], "per_user", "{record}");
    assert_eq!(record["credentialConnection"], "tickets", "{record}");
    let grants = record["providerAudit"]["commandAuthorization"]["grants"]
        .as_array()
        .unwrap();
    assert_eq!(grants.len(), 1, "{record}");
    assert_eq!(grants[0]["credentialMode"], "per_user", "{record}");
}

/// Creates `tickets` with `modes`, discovers and accepts it, stores a
/// service credential when service mode is bound, and enables it.
pub(super) async fn enabled_tickets(app: &Router, token: &str, modes: &[&str]) -> Value {
    let (status, created) = request(
        app,
        token,
        Method::POST,
        "/v1/admin/imports",
        Some(definition("tickets", "tickets", modes)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let mut current = discover_and_accept(app, token, "tickets", &created["result"]).await;
    if modes.contains(&"service") {
        let mut secret = versions(&current);
        secret["token"] = json!("svc-example");
        let (status, stored) = request(
            app,
            token,
            Method::PUT,
            "/v1/admin/imports/tickets/credentials/execution",
            Some(secret),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{stored}");
        current = stored["result"].clone();
    }
    let mut enable = versions(&current);
    enable["status"] = json!("enabled");
    let (status, enabled) = request(
        app,
        token,
        Method::POST,
        "/v1/admin/imports/tickets/status",
        Some(enable),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");
    enabled["result"].clone()
}

fn project_type() -> Value {
    json!({"id": "project", "label": "Project", "pluralLabel": "Projects",
        "example": "OPS", "pattern": "[A-Z][A-Z0-9]{1,9}"})
}

/// A refresh whose accepted actions would leave retained grants invalid at
/// the next start is refused, naming the grants, so the administrator fixes
/// them first; nothing is published.
#[cfg(unix)]
#[tokio::test]
async fn acceptance_refuses_changes_that_would_invalidate_retained_grants() {
    let manifest = json!({
        "format": "agent-access-command/1",
        "version": "1.0.0",
        "credential": {"kind": "token", "modes": ["service", "per_user"]},
        "resourceTypes": [project_type()],
        "actions": [
            {"name": "issue.stats", "description": "Issue statistics.", "readOnly": true,
             "inputSchema": {"type": "object", "required": ["project"],
                "properties": {"project": {"type": "string"}}}}
        ]
    });
    let fixture = CommandFixture::new("tickets", &manifest);
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    enabled_tickets(&app, &token, &["service", "per_user"]).await;
    let runtime = broker.runtime();
    for grant in [
        command_grant(
            "stats-alice-user",
            "user:alice",
            "issue.stats",
            "per_user",
            0,
        ),
        command_grant(
            "stats-alice-service",
            "user:alice",
            "issue.stats",
            "service",
            0,
        ),
    ] {
        runtime.create_managed_policy_grant(grant).unwrap();
    }
    drop(runtime);
    let accepted_before = broker.runtime().imported_catalog().clone();

    for (change, grant, expected, code) in [
        // The action now names its project, so the Broker checks it and the
        // pair of modes becomes ambiguous.
        (
            json!({"resources": {"type": "project", "inputs": ["/project"]}}),
            "stats-alice-service",
            "ambiguous credential mode",
            "credential_mode_ambiguous",
        ),
        // The action no longer supports personal mode.
        (
            json!({"credentialModes": ["service"]}),
            "stats-alice-user",
            "per_user is unsupported",
            "credential_mode_invalid",
        ),
    ] {
        let mut refreshed = manifest.clone();
        for (key, value) in change.as_object().unwrap() {
            refreshed["actions"][0][key] = value.clone();
        }
        fixture.write_manifest(&refreshed);
        let current = request(&app, &token, Method::GET, "/v1/admin/imports/tickets", None)
            .await
            .1;
        let (status, discovered) = request(
            &app,
            &token,
            Method::POST,
            "/v1/admin/imports/tickets/discover",
            Some(versions(&current["result"])),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{discovered}");
        let discovered = &discovered["result"];
        let tool = &discovered["preview"]["manifest"]["tools"][0];
        assert!(tool["unsupportedReason"].is_null(), "{tool}");
        let mut accept = versions(discovered);
        accept["manifestHash"] = discovered["preview"]["manifestHash"].clone();
        accept["selections"] = json!([{"source": tool["definition"]["source"],
            "action": "issue.stats", "readOnly": true}]);
        accept["confirmAffectedGrants"] = json!(true);
        let (status, refused) = request(
            &app,
            &token,
            Method::POST,
            "/v1/admin/imports/tickets/accept",
            Some(accept),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        let message = refused.to_string();
        assert!(message.contains(grant), "{refused}");
        assert!(message.contains(expected), "{refused}");
        // The affected grants are also listed for clients.
        let affected = refused["target"]["affectedGrants"].as_array().unwrap();
        assert_eq!(affected.len(), 1, "{refused}");
        assert_eq!(affected[0]["id"], grant, "{refused}");
        assert_eq!(affected[0]["reasonCode"], code, "{refused}");
        assert!(
            affected[0]["reason"].as_str().unwrap().contains(expected),
            "{refused}"
        );
        assert!(refused["target"].get("resources").is_none(), "{refused}");
        // The refresh quarantined the action; the refused acceptance kept
        // its accepted definition.
        let published = broker.runtime();
        let action = &published
            .imported_catalog()
            .service("tickets")
            .unwrap()
            .actions[0];
        assert_eq!(
            action.definition,
            accepted_before.service("tickets").unwrap().actions[0].definition,
            "nothing was published"
        );
        assert_eq!(
            action.status,
            agent_access_core::ImportedActionStatus::Quarantined
        );
    }
    drop(app);
    broker.stop().await;
    // The retained grants still load.
    BrokerRuntime::new(fixture.config.clone()).unwrap();
}

/// Without the command adapter, a command import's actions authorize nothing,
/// and retained grants that mix modes for one subject still load.
#[cfg(unix)]
#[tokio::test]
async fn startup_keeps_mixed_mode_grants_of_an_unlinked_command_import() {
    let manifest = json!({
        "format": "agent-access-command/1",
        "version": "1.0.0",
        "credential": {"kind": "token", "modes": ["service", "per_user"]},
        "actions": [
            {"name": "issue.stats", "description": "Issue statistics.", "readOnly": true,
             "inputSchema": {"type": "object"}}
        ]
    });
    let fixture = CommandFixture::new("tickets", &manifest);
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    enabled_tickets(&app, &token, &["service", "per_user"]).await;
    let runtime = broker.runtime();
    for grant in [
        command_grant(
            "stats-alice-user",
            "user:alice",
            "issue.stats",
            "per_user",
            0,
        ),
        command_grant(
            "stats-alice-service",
            "user:alice",
            "issue.stats",
            "service",
            0,
        ),
    ] {
        runtime.create_managed_policy_grant(grant).unwrap();
    }
    drop((runtime, app));
    broker.stop().await;

    let mut unlinked = fixture.config.clone();
    unlinked.providers = agent_access_core::ProvidersConfig::new(Arc::new(
        agent_access_core::BackendRegistry::new(crate::backend_registry().registrations())
            .unwrap()
            .with_oauth_dialects([
                &agent_access_gmail::GOOGLE_OAUTH_DIALECT,
                &agent_access_fake::STUB_OAUTH_DIALECT,
            ])
            .unwrap()
            .with_imported_adapters([agent_access_core::imports::imported_adapter_registration(
                agent_access_provider::module_metadata!(),
                &super::conformance_import::CONFORMANCE_IMPORT_ADAPTER,
                None,
            )])
            .unwrap(),
    ));
    unlinked
        .imports
        .allowed_kinds
        .retain(|kind| kind != "command");
    let restarted = BrokerRuntime::new(unlinked).unwrap();
    assert!(
        restarted
            .imported_service_unavailable_reason("tickets")
            .is_some()
    );
    assert!(restarted.command_provider("tickets").is_none());
}

/// Real adapter scope resolution and credential checks at admission: inputs
/// are checked against the schema, a Broker-enforced action names at most
/// 1,000 resources, and a stored credential that cannot be decrypted denies
/// with its own reason instead of looking absent.
#[cfg(unix)]
#[tokio::test]
async fn admission_checks_inputs_bounds_resources_and_reports_credential_failures() {
    let manifest = json!({
        "format": "agent-access-command/1",
        "version": "1.0.0",
        "credential": {"kind": "token", "modes": ["service", "per_user"]},
        "resourceTypes": [project_type()],
        "actions": [
            {"name": "issue.stats", "description": "Issue statistics.", "readOnly": true,
             "inputSchema": {"type": "object", "additionalProperties": false}},
            {"name": "issue.bulk", "description": "Show issues of projects.", "readOnly": true,
             "inputSchema": {"type": "object", "required": ["projects"],
                "properties": {"projects": {"type": "array", "items": {"type": "string"}}}},
             "resources": {"type": "project", "inputs": ["/projects"]}}
        ]
    });
    let fixture = CommandFixture::new("tickets", &manifest);
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    enabled_tickets(&app, &token, &["service", "per_user"]).await;
    broker
        .runtime()
        .create_managed_policy_grant(command_grant(
            "stats-alice-service",
            "user:alice",
            "issue.stats",
            "service",
            0,
        ))
        .unwrap();
    let agent = fixture.issue(
        "alice",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedServices": ["tickets"], "allowedExecutionContexts": ["default"]}),
    );
    let invoke = |action: &'static str, inputs: Value| {
        let (app, agent) = (app.clone(), agent.clone());
        async move {
            request(
                &app,
                &agent,
                Method::POST,
                &format!("/v1/invoke/tickets/{action}"),
                Some(json!({"inputs": inputs})),
            )
            .await
            .1["reasonCode"]
                .clone()
        }
    };
    assert_eq!(
        invoke("issue.stats", json!({"extra": 1})).await,
        "input_invalid"
    );
    // The call is admitted and runs its process, which the recording
    // command fails.
    assert_eq!(invoke("issue.stats", json!({})).await, "operation_failed");
    let projects = |count: usize| json!({"projects": (0..count).map(|index| format!("P{index}")).collect::<Vec<_>>()});
    assert_eq!(invoke("issue.bulk", projects(1001)).await, "input_invalid");
    // Within the bound, policy decides; no grant covers these projects.
    assert_eq!(
        invoke("issue.bulk", projects(1000)).await,
        "service_action_denied"
    );

    // A stored service credential that cannot be decrypted is reported.
    let store = &fixture.config.managed_store.as_ref().unwrap().path;
    rusqlite::Connection::open(store)
        .unwrap()
        .execute(
            "UPDATE imported_secret_material SET ciphertext = zeroblob(length(ciphertext)) \
             WHERE service = 'tickets'",
            [],
        )
        .unwrap();
    assert_eq!(
        invoke("issue.stats", json!({})).await,
        "credential_decrypt_failed"
    );
    drop(app);
    broker.stop().await;
}
