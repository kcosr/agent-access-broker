//! The command contract end to end through the real router, store, runtime
//! publication, linked `command` adapter and process supervision: the request
//! a command reads on stdin (caller, authority, resources, credentials and
//! network), the response mapping, write receipts, verification, the final
//! checks of queued calls, cancellation and the audit facts.
//!
//! The fixture command records each run, keeps the request, arguments and
//! environment of each `invoke` and `verify` in a private directory for the
//! test to inspect, waits while a hold file exists, and exits with a status
//! or answers with a response file the test writes, or by default with a
//! checksum of the request it read, never the request itself.
#![cfg(unix)]
use super::imports_command::{CommandFixture, request, versions};
use super::imports_foundation::import_broker;
use super::*;
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, CommandImportConfig,
    ManagedPolicyGrantCreateRequest, OutboundTlsConfig, OutboundTlsTrustMode,
};
use std::os::unix::fs::PermissionsExt;

const CONTRACT_COMMAND: &str = r#"#!/bin/sh
echo "$1 $$" >> "$MARKER"
if [ "$1" = describe ]; then cat "$MANIFEST"; exit 0; fi
umask 077
run="$RUNS/$1-$$"
cat > "$run.request"
printf '%s\n' "$@" > "$run.args"
env > "$run.env"
while [ -e "$HOLD" ]; do sleep 0.05; done
if [ -e "$RESPONSES/$1.exit" ]; then exit "$(cat "$RESPONSES/$1.exit")"; fi
if [ -e "$RESPONSES/$1.json" ]; then cat "$RESPONSES/$1.json"; exit 0; fi
sum=$(cksum < "$run.request" | cut -d ' ' -f 1)
printf '{"ok":true,"result":{"cksum":"%s"}}\n' "$sum"
"#;

const SERVICE_TOKEN: &str = "svc-example-6a1f";
const PERSONAL_TOKEN: &str = "pat-example-93c2";
const WEBHOOK_SECRET: &str = "s3cr3t-example-41d8";
const REGION: &str = "eu-west-7";

fn project_type() -> Value {
    json!({"id": "project", "label": "Project", "pluralLabel": "Projects",
    "example": "OPS", "pattern": "[A-Z][A-Z0-9]{1,9}",
    "attributes": [
        {"name": "region", "label": "Region", "description": "Hosting region.",
         "required": false, "pattern": "[a-z0-9-]{1,32}"},
        {"name": "webhookSecret", "label": "Webhook secret",
         "description": "Per-project signing secret.", "required": false}
    ]})
}

fn tickets_manifest(verify: bool) -> Value {
    json!({
        "format": "agent-access-command/1",
        "version": "2.0.0",
        "credential": {"kind": "username_token", "modes": ["service", "per_user"]},
        "verify": verify,
        "resourceTypes": [project_type()],
        "actions": [
            {"name": "issue.view", "description": "Show one issue.", "readOnly": true,
             "inputSchema": {"type": "object", "required": ["project", "issue"],
                "properties": {"project": {"type": "string"},
                    "issue": {"type": "integer", "minimum": 1}},
                "additionalProperties": false},
             "resources": {"type": "project", "inputs": ["/project"]}},
            {"name": "issue.create", "description": "Create an issue.",
             "inputSchema": {"type": "object", "required": ["project", "summary"],
                "properties": {"project": {"type": "string"}, "summary": {"type": "string"}},
                "additionalProperties": false},
             "outputSchema": {"type": "object", "required": ["key"]},
             "resources": {"type": "project", "inputs": ["/project"]}},
            {"name": "issue.search", "description": "Search issues.", "readOnly": true,
             "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}},
                "additionalProperties": false},
             "resources": {"type": "project"}},
            {"name": "server.info", "description": "Server information.", "readOnly": true,
             "inputSchema": {"type": "object", "additionalProperties": false}}
        ]
    })
}

fn clock_manifest() -> Value {
    json!({
        "format": "agent-access-command/1",
        "version": "1.0.0",
        "actions": [
            {"name": "time.now", "description": "Current time.", "readOnly": true,
             "inputSchema": {"type": "object", "additionalProperties": false}}
        ]
    })
}

/// One fixture command approved as `tickets`, with further approved names
/// running the same script on their own manifests, and the files the
/// script keeps.
struct Contract {
    fixture: CommandFixture,
    admin: String,
}

impl Contract {
    fn new(manifest: &Value) -> Self {
        let mut fixture = CommandFixture::with_script("tickets", manifest, CONTRACT_COMMAND);
        for directory in ["requests", "responses"] {
            std::fs::create_dir(fixture.path(directory)).unwrap();
        }
        let (runs, responses, hold) = (
            fixture.path("requests"),
            fixture.path("responses"),
            fixture.path("hold"),
        );
        let entry = fixture.config.command_imports.get_mut("tickets").unwrap();
        for (name, path) in [("RUNS", runs), ("RESPONSES", responses), ("HOLD", hold)] {
            entry.env.insert(name.into(), path.display().to_string());
        }
        fixture.config.mcp.enabled = true;
        fixture.config.mcp.public_url = Some("https://broker.example.test/mcp".into());
        let admin = fixture.admin_token();
        Self { fixture, admin }
    }

    /// Approves `name` running the same script on `manifest`.
    fn approve(
        &mut self,
        name: &str,
        manifest: &Value,
        change: impl FnOnce(&mut CommandImportConfig),
    ) {
        let path = self.fixture.path(&format!("{name}.json"));
        std::fs::write(&path, manifest.to_string()).unwrap();
        let mut entry = self.fixture.config.command_imports["tickets"].clone();
        entry
            .env
            .insert("MANIFEST".into(), path.display().to_string());
        change(&mut entry);
        self.fixture
            .config
            .command_imports
            .insert(name.into(), entry);
    }

    fn entry(&mut self, name: &str) -> &mut CommandImportConfig {
        self.fixture.config.command_imports.get_mut(name).unwrap()
    }

    fn hold(&self, on: bool) {
        let path = self.fixture.path("hold");
        if on {
            std::fs::write(path, "").unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
    }

    /// The next `operation` runs answer `response`; `None` restores the
    /// checksum answer.
    fn respond(&self, operation: &str, response: Option<&str>) {
        let path = self.fixture.path(&format!("responses/{operation}.json"));
        match response {
            Some(response) => std::fs::write(path, response).unwrap(),
            None => {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    /// The process IDs of the `operation` runs started so far.
    fn started(&self, operation: &str) -> Vec<i32> {
        self.fixture
            .runs()
            .iter()
            .filter_map(|run| run.strip_prefix(operation)?.trim().parse().ok())
            .collect()
    }

    /// What the last `operation` run read and was started with.
    fn last(&self, operation: &str) -> Run {
        let pid = *self.started(operation).last().expect("a run");
        self.run(operation, pid)
    }

    fn run(&self, operation: &str, pid: i32) -> Run {
        let file = |suffix: &str| {
            std::fs::read_to_string(
                self.fixture
                    .path(&format!("requests/{operation}-{pid}.{suffix}")),
            )
            .unwrap()
        };
        let request = file("request");
        Run {
            document: serde_json::from_str(&request).unwrap(),
            raw: request,
            args: file("args"),
            env: file("env")
                .lines()
                .filter_map(|line| line.split_once('='))
                .filter(|(name, _)| !matches!(*name, "PWD" | "OLDPWD" | "SHLVL" | "_"))
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
        }
    }

    fn audit(&self) -> Vec<Value> {
        read_audit_records(Path::new(&self.fixture.config.audit.as_ref().unwrap().path))
    }

    fn audit_text(&self) -> String {
        read_audit_text(Path::new(&self.fixture.config.audit.as_ref().unwrap().path))
    }

    /// The invocation audit records of the call with agent request ID `id`.
    fn audited(&self, id: &str) -> Vec<Value> {
        self.audit()
            .into_iter()
            .filter(|record| record["agentRequestId"] == id)
            .collect()
    }
}

struct Run {
    document: Value,
    raw: String,
    args: String,
    env: BTreeMap<String, String>,
}

/// The checksum the fixture answers with for what it read.
fn cksum(text: &str) -> String {
    use std::io::Write;
    let mut child = std::process::Command::new("cksum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .to_owned()
}

async fn invoke_as(
    app: &Router,
    token: &str,
    id: &str,
    service: &str,
    action: &str,
    inputs: Value,
) -> (StatusCode, Value) {
    let response = authed_json_request(
        app.clone(),
        Method::POST,
        format!("/v1/invoke/{service}/{action}"),
        id,
        "Authorization",
        format!("Bearer {token}"),
        Some(&json!({"inputs": inputs}).to_string()),
    )
    .await;
    (response.status(), response_json(response).await)
}

async fn admin(app: &Router, token: &str, method: Method, path: &str, body: Value) -> Value {
    let (status, result) = request(app, token, method, path, Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{path}: {result}");
    result
}

/// Creates, discovers and accepts import `service` of command `command` in
/// `modes`, with `issue.create` reviewed as a write and every other action
/// as a read, stores the service credential when service mode is bound, and
/// enables it.
async fn import(app: &Router, token: &str, service: &str, command: &str, modes: &[&str]) -> Value {
    let created = admin(
        app,
        token,
        Method::POST,
        "/v1/admin/imports",
        super::imports_command::definition(service, command, modes),
    )
    .await;
    let discovered = admin(
        app,
        token,
        Method::POST,
        &format!("/v1/admin/imports/{service}/discover"),
        versions(&created["result"]),
    )
    .await;
    let discovered = &discovered["result"];
    let mut accept = versions(discovered);
    accept["manifestHash"] = discovered["preview"]["manifestHash"].clone();
    accept["selections"] = json!(
        discovered["preview"]["manifest"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| json!({"source": tool["definition"]["source"],
                "action": tool["definition"]["action"],
                "readOnly": tool["definition"]["action"] != "issue.create"}))
            .collect::<Vec<_>>()
    );
    let mut current = admin(
        app,
        token,
        Method::POST,
        &format!("/v1/admin/imports/{service}/accept"),
        accept,
    )
    .await["result"]
        .clone();
    if modes.contains(&"service") {
        current = rotate_service_slot(app, token, service, &current, SERVICE_TOKEN).await;
    }
    let mut enable = versions(&current);
    enable["status"] = json!("enabled");
    admin(
        app,
        token,
        Method::POST,
        &format!("/v1/admin/imports/{service}/status"),
        enable,
    )
    .await["result"]
        .clone()
}

async fn rotate_service_slot(
    app: &Router,
    token: &str,
    service: &str,
    current: &Value,
    secret: &str,
) -> Value {
    let mut body = versions(current);
    body["username"] = json!("svc-tickets");
    body["token"] = json!(secret);
    admin(
        app,
        token,
        Method::PUT,
        &format!("/v1/admin/imports/{service}/credentials/execution"),
        body,
    )
    .await["result"]
        .clone()
}

async fn current(app: &Router, token: &str, service: &str) -> Value {
    let (status, current) = request(
        app,
        token,
        Method::GET,
        &format!("/v1/admin/imports/{service}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{current}");
    current["result"].clone()
}

/// The resources `resource_ids` and resource groups `resource_group_ids`.
fn select(resource_ids: &[&str], resource_group_ids: &[&str]) -> ResourceSelection {
    ResourceSelection {
        resource_ids: resource_ids.iter().map(|id| (*id).into()).collect(),
        resource_group_ids: resource_group_ids.iter().map(|id| (*id).into()).collect(),
    }
}

fn grant(
    id: &str,
    subject: &str,
    service: &str,
    action: &str,
    mode: &str,
    priority: i32,
    resources: ResourceSelection,
) -> ManagedPolicyGrantCreateRequest {
    ManagedPolicyGrantCreateRequest {
        grant_id: Some(id.into()),
        subjects: vec![subject.into()],
        execution_contexts: vec!["default".into()],
        service: service.into(),
        actions: vec![action.into()],
        resources,
        credential_mode: mode.into(),
        priority: Some(priority),
        status: None,
        description: None,
        created_by: "admin".into(),
    }
}

/// Avery, in group `engineering`, with display name and email, a personal
/// `username-token` credential for `tickets`, and an agent token labelled
/// `laptop agent` for `services`. Returns the token and its ID.
fn avery(runtime: &BrokerRuntime, config: &BrokerConfig, services: &[&str]) -> (String, String) {
    let store = runtime.managed_store().unwrap();
    store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "avery".into(),
            kind: "user".into(),
            display_name: Some("Avery Example".into()),
            email: Some("avery@example.com".into()),
            external_subject: None,
            created_by: "admin".into(),
        })
        .unwrap();
    store
        .create_group(agent_access_core::GroupWriteRequest {
            group_id: "engineering".into(),
            display_name: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap();
    store.add_group("avery", "engineering", "admin").unwrap();
    personal_credential(runtime, PERSONAL_TOKEN);
    let issued = store
        .issue_broker_token(
            &BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap(),
            BrokerTokenIssueRequest {
                principal_id: "avery".into(),
                name: "laptop agent".into(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: json!({"allowedServices": services,
                    "allowedExecutionContexts": ["default"]}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap();
    (issued.token, issued.record.token_id)
}

fn personal_credential(runtime: &BrokerRuntime, token: &str) {
    runtime
        .managed_store()
        .unwrap()
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            agent_access_core::CredentialWriteRequest {
                owner_principal_id: "avery".into(),
                service: "tickets".into(),
                name: "default".into(),
                profile: "username-token".into(),
                credential_kind: "basic_api_token".into(),
                secret: json!({"username": "avery", "token": token}),
                metadata: json!({}),
                actor: "admin".into(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
}

/// Resources of the imported project type: `ops` with private attributes,
/// `dev` without, `sec`, an `all` entry and the group `wide`, which is every
/// project except `sec`.
async fn projects(app: &Router, token: &str) {
    for (id, selector, name, attributes) in [
        (
            "ops",
            json!({"kind": "exact", "value": "OPS"}),
            Some("Operations"),
            json!({"region": REGION, "webhookSecret": WEBHOOK_SECRET}),
        ),
        (
            "dev",
            json!({"kind": "exact", "value": "DEV"}),
            None,
            json!({}),
        ),
        (
            "sec",
            json!({"kind": "exact", "value": "SEC"}),
            None,
            json!({}),
        ),
        ("all", json!({"kind": "all"}), None, json!({})),
    ] {
        let mut body = json!({"id": id, "resourceType": "tickets_project", "selector": selector,
            "allowedExecutionContexts": ["default"], "attributes": attributes});
        if let Some(name) = name {
            body["displayName"] = json!(name);
        }
        admin(app, token, Method::POST, "/v1/admin/policy/resources", body).await;
    }
    admin(
        app,
        token,
        Method::POST,
        "/v1/admin/policy/resource-groups",
        json!({"id": "wide", "name": "Wide", "includedResourceIds": ["all"],
            "excludedResourceIds": ["sec"]}),
    )
    .await;
}

fn grants(runtime: &BrokerRuntime) {
    for grant in [
        grant(
            "view-user",
            "group:engineering",
            "tickets",
            "issue.view",
            "per_user",
            0,
            select(&["ops", "dev"], &[]),
        ),
        grant(
            "create-user",
            "user:avery",
            "tickets",
            "issue.create",
            "per_user",
            0,
            select(&["ops", "dev"], &[]),
        ),
        grant(
            "create-service",
            "user:bob",
            "tickets",
            "issue.create",
            "service",
            0,
            select(&["all"], &[]),
        ),
        grant(
            "search-user",
            "group:engineering",
            "tickets",
            "issue.search",
            "per_user",
            10,
            select(&[], &["wide"]),
        ),
        grant(
            "search-service",
            "group:engineering",
            "tickets",
            "issue.search",
            "service",
            10,
            select(&["ops"], &[]),
        ),
        // A lower band is never passed.
        grant(
            "search-low",
            "group:engineering",
            "tickets",
            "issue.search",
            "service",
            0,
            select(&["all"], &[]),
        ),
        grant(
            "info-service",
            "group:engineering",
            "tickets",
            "server.info",
            "service",
            0,
            select(&[], &[]),
        ),
        grant(
            "info-user",
            "group:engineering",
            "tickets",
            "server.info",
            "per_user",
            0,
            select(&[], &[]),
        ),
    ] {
        runtime.create_managed_policy_grant(grant).unwrap();
    }
}

fn sorted_grants(authorization: &Value) -> Vec<Value> {
    let mut grants = authorization["grants"].as_array().unwrap().clone();
    grants.sort_by_key(|grant| grant.to_string());
    grants
}

fn no_secret_in(text: &str, what: &str) {
    for secret in [SERVICE_TOKEN, PERSONAL_TOKEN, WEBHOOK_SECRET, REGION] {
        assert!(!text.contains(secret), "{what} contains {secret}: {text}");
    }
}

/// Every environment variable is the command's configured `env`, and with
/// `network = "inherit"` the network variables of the default `system`
/// trust: the proxy and `NO_PROXY` variables when the Broker's process has
/// them.
fn assert_configured_environment(run: &Run, entry: &CommandImportConfig) {
    for (name, value) in &run.env {
        if let Some(configured) = entry.env.get(name) {
            assert_eq!(value, configured, "{name}");
        } else {
            assert!(
                matches!(
                    name.as_str(),
                    "HTTPS_PROXY"
                        | "HTTP_PROXY"
                        | "https_proxy"
                        | "http_proxy"
                        | "NO_PROXY"
                        | "no_proxy"
                ),
                "unexpected variable {name}"
            );
        }
    }
}

/// Whether the Broker's process environment names an HTTPS proxy, which an
/// inheriting command receives instead of the configured one.
fn process_https_proxy() -> bool {
    ["HTTPS_PROXY", "https_proxy"]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
}

/// Criteria 7a, 8, 9, 10, 11, 18 and 20: each authority mode's request,
/// read from the command's stdin, carries the caller, the admitted
/// resources with their identity and private attributes, and exactly the
/// credentials its grants use, in both modes and without credentials; no
/// secret reaches arguments, environment, responses or audit.
#[tokio::test]
async fn requests_carry_the_caller_authority_resources_and_credentials_on_stdin_only() {
    let mut contract = Contract::new(&tickets_manifest(true));
    contract.approve("clock", &clock_manifest(), |_| {});
    let config = contract.fixture.config.clone();
    let broker = import_broker(&config).await;
    let app = broker.app();
    let token = contract.admin.clone();
    import(&app, &token, "tickets", "tickets", &["service", "per_user"]).await;
    import(&app, &token, "clock", "clock", &[]).await;
    projects(&app, &token).await;
    let runtime = broker.runtime();
    let (agent, token_id) = avery(&runtime, &config, &["tickets", "clock"]);
    grants(&runtime);
    runtime
        .create_managed_policy_grant(grant(
            "clock",
            "user:avery",
            "clock",
            "time.now",
            "service",
            0,
            select(&[], &[]),
        ))
        .unwrap();

    // Broker-enforced, personal: the named resource with its identity and
    // attributes, and only the personal credential.
    let (status, viewed) = invoke_as(
        &app,
        &agent,
        "view-ops",
        "tickets",
        "issue.view",
        json!({"project": "OPS", "issue": 42}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{viewed}");
    let run = contract.last("invoke");
    let sent = &run.document;
    assert_eq!(sent["format"], "agent-access-command/1");
    assert_eq!(sent["action"], "issue.view");
    assert_eq!(sent["context"], "default");
    assert_eq!(sent["requestId"], viewed["brokerRequestId"]);
    let deadline = chrono::DateTime::parse_from_rfc3339(sent["deadline"].as_str().unwrap())
        .unwrap()
        .with_timezone(&chrono::Utc);
    let remaining = (deadline - chrono::Utc::now()).num_seconds();
    assert!((0..=10).contains(&remaining), "{remaining}");
    assert_eq!(
        sent["caller"],
        json!({"principal": "avery", "kind": "user", "displayName": "Avery Example",
            "email": "avery@example.com", "token": {"id": token_id, "label": "laptop agent"},
            "groups": ["engineering"]})
    );
    assert_eq!(sent["inputs"], json!({"project": "OPS", "issue": 42}));
    assert_eq!(
        sent["authorization"],
        json!({"mode": "broker", "credential": "user", "resourceType": "project",
            "resources": [{"value": "OPS", "id": "ops", "name": "Operations",
                "attributes": {"region": REGION, "webhookSecret": WEBHOOK_SECRET}}]})
    );
    assert_eq!(
        sent["credentials"],
        json!({"user": {"kind": "username_token", "username": "avery", "token": PERSONAL_TOKEN}})
    );
    if !process_https_proxy() {
        assert_eq!(sent["network"]["proxy"], Value::Null);
    }
    assert_eq!(sent["network"]["trust"], "system");
    assert_eq!(sent["network"]["caCertificate"], Value::Null);
    let keys = sent
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        [
            "action",
            "authorization",
            "caller",
            "context",
            "credentials",
            "deadline",
            "format",
            "inputs",
            "network",
            "requestId"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    // The command answers with a checksum of the request, never the request.
    assert_eq!(
        viewed["result"]["upstreamCommand"],
        json!({"cksum": cksum(&run.raw)})
    );
    assert!(viewed["result"].get("mutationStatus").is_none(), "{viewed}");
    assert_eq!(run.args, "invoke\n");
    assert_configured_environment(&run, &config.command_imports["tickets"]);
    no_secret_in(&format!("{:?}", run.env), "environment");
    no_secret_in(&viewed.to_string(), "response");
    let records = contract.audited("view-ops");
    assert_eq!(records.len(), 1);
    let audit = &records[0]["providerAudit"];
    assert_eq!(audit["command"]["name"], "tickets");
    assert_eq!(audit["command"]["spawned"], true);
    assert_eq!(audit["command"]["exitCode"], 0);
    assert_eq!(audit["command"]["signal"], Value::Null);
    assert!(audit["command"]["durationMs"].is_u64(), "{audit}");
    assert_eq!(audit["command"]["contractViolation"], false);
    assert_eq!(audit["command"]["operationDispatched"], true);
    assert_eq!(audit["commandAuthorization"]["mode"], "broker");
    assert_eq!(audit["commandAuthorization"]["credentialMode"], "per_user");
    assert_eq!(audit["commandAuthorization"]["values"], json!(["OPS"]));
    assert_eq!(
        audit["commandAuthorization"]["grant"]["grantId"],
        "view-user"
    );
    assert!(audit["importedService"]["serviceVersion"].is_i64());
    assert_eq!(records[0]["credentialMode"], "per_user");

    // Broker-enforced write, service mode, a value no exact entry holds:
    // the value alone and only the service credential; the success is an
    // unverified write with the command's locators.
    contract.respond(
        "invoke",
        Some(r#"{"ok": true, "result": {"key": "NEW-1"}, "receipt": {"safeLocators": {"issue": "NEW-1"}}}"#),
    );
    let bob = contract.fixture.issue(
        "bob",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedServices": ["tickets"], "allowedExecutionContexts": ["default"]}),
    );
    let (status, created) = invoke_as(
        &app,
        &bob,
        "create-new",
        "tickets",
        "issue.create",
        json!({"project": "NEW", "summary": "A new project's first issue"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(
        created["result"],
        json!({"upstreamCommand": {"key": "NEW-1"}, "mutationStatus": "applied_unverified",
            "retrySafe": false, "safeLocators": {"issue": "NEW-1"}})
    );
    let sent = contract.last("invoke").document;
    assert_eq!(
        sent["authorization"],
        json!({"mode": "broker", "credential": "service", "resourceType": "project",
            "resources": [{"value": "NEW"}]})
    );
    assert_eq!(
        sent["credentials"],
        json!({"service": {"kind": "username_token", "username": "svc-tickets",
            "token": SERVICE_TOKEN}})
    );
    assert_eq!(sent["caller"]["principal"], "bob");
    assert!(sent["caller"].get("displayName").is_none());
    contract.respond("invoke", None);

    // Command-enforced, typed: the top band's grants with their own
    // credentials, an all-except boundary and a finite one with its
    // resource's attributes; never the lower band.
    let (status, searched) = invoke_as(
        &app,
        &agent,
        "search",
        "tickets",
        "issue.search",
        json!({"query": "status = open"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{searched}");
    let sent = contract.last("invoke").document;
    assert_eq!(sent["authorization"]["mode"], "command");
    assert_eq!(sent["authorization"]["resourceType"], "project");
    assert_eq!(
        sorted_grants(&sent["authorization"]),
        vec![
            json!({"credential": "service", "resources": [{"value": "OPS", "id": "ops",
                "name": "Operations", "attributes": {"region": REGION, "webhookSecret": WEBHOOK_SECRET}}]}),
            json!({"credential": "user", "resources": "any", "except": ["SEC"]}),
        ]
    );
    assert_eq!(
        sent["credentials"],
        json!({
            "service": {"kind": "username_token", "username": "svc-tickets", "token": SERVICE_TOKEN},
            "user": {"kind": "username_token", "username": "avery", "token": PERSONAL_TOKEN}
        })
    );
    let records = contract.audited("search");
    let authorization = &records[0]["providerAudit"]["commandAuthorization"];
    assert_eq!(authorization["mode"], "command");
    let passed = authorization["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|grant| {
            (
                grant["grant"]["grantId"].as_str().unwrap().to_owned(),
                grant["credentialMode"].as_str().unwrap().to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        passed,
        BTreeSet::from([
            ("search-service".to_owned(), "service".to_owned()),
            ("search-user".to_owned(), "per_user".to_owned()),
        ])
    );
    assert_eq!(records[0]["credentialMode"], Value::Null);

    // Command-enforced, untyped: no resource type, only "any" entries.
    let (status, info) = invoke_as(&app, &agent, "info", "tickets", "server.info", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{info}");
    let sent = contract.last("invoke").document;
    assert!(sent["authorization"].get("resourceType").is_none());
    assert_eq!(
        sorted_grants(&sent["authorization"]),
        vec![
            json!({"credential": "service", "resources": "any"}),
            json!({"credential": "user", "resources": "any"}),
        ]
    );

    // Without a credential: no credentials and no credential members.
    let (status, now) = invoke_as(&app, &agent, "clock", "clock", "time.now", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{now}");
    let sent = contract.last("invoke").document;
    assert_eq!(
        sent["authorization"],
        json!({"mode": "command", "grants": [{"resources": "any"}]})
    );
    assert!(sent.get("credentials").is_none(), "{sent}");
    no_secret_in(&sent.to_string(), "credential-free request");

    // No supplied secret reaches the audit store or a response's
    // non-sensitive fields; the payload is marked sensitive on every
    // surface.
    no_secret_in(&contract.audit_text(), "audit");
    for path in [
        "/v1/spec/catalog",
        "/v1/spec/openapi.json",
        "/v1/spec/send-schema.json",
    ] {
        let (status, spec) = request(&app, &agent, Method::GET, path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {spec}");
        let text = spec.to_string();
        assert!(text.contains("/result/upstreamCommand"), "{path}");
    }
    // MCP tool results carry the marker too.
    let session = mcp_session(&app, &agent).await;
    let call = mcp_call(
        &app,
        &agent,
        &session,
        3,
        "issue.view",
        json!({"project": "OPS", "issue": 7}),
    );
    let called = super::mcp::rpc_body(call.await.unwrap()).await;
    assert_eq!(called["result"]["isError"], false, "{called}");
    assert_eq!(
        called["result"]["_meta"]["agent-access/sensitive-output-pointers"],
        json!(["/result/upstreamCommand"])
    );
    no_secret_in(&called.to_string(), "MCP result");
    let (status, catalog) = request(&app, &agent, Method::GET, "/v1/spec/catalog", None).await;
    assert_eq!(status, StatusCode::OK);
    let actions = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|service| service["service"] == "tickets" || service["service"] == "clock")
        .flat_map(|service| service["actions"].as_array().unwrap().clone())
        .collect::<Vec<_>>();
    assert!(!actions.is_empty());
    for action in actions {
        assert_eq!(
            action["sensitiveOutputPointers"],
            json!(["/result/upstreamCommand"]),
            "{action}"
        );
    }
    drop(app);
    let report = broker.stop().await;
    assert!(report.is_clean(), "{report:?}");
}

/// Criteria 16 and 1: error codes map with the command's message and
/// retry wait; write receipts follow the response; a malformed receipt or a
/// locator echoing a supplied secret is a contract violation; a failed or
/// missing executable is an `operation_failed` whose write receipt says
/// whether anything ran.
#[tokio::test]
async fn responses_map_errors_receipts_and_contract_violations() {
    let contract = Contract::new(&tickets_manifest(false));
    let config = contract.fixture.config.clone();
    let broker = import_broker(&config).await;
    let app = broker.app();
    let token = contract.admin.clone();
    import(&app, &token, "tickets", "tickets", &["service", "per_user"]).await;
    projects(&app, &token).await;
    let runtime = broker.runtime();
    let (agent, _) = avery(&runtime, &config, &["tickets"]);
    grants(&runtime);
    let create = |id: &'static str| {
        let (app, agent) = (app.clone(), agent.clone());
        async move {
            invoke_as(
                &app,
                &agent,
                id,
                "tickets",
                "issue.create",
                json!({"project": "OPS", "summary": "Hello"}),
            )
            .await
        }
    };

    for (code, reason, status, receipt, expected) in [
        (
            "input_invalid",
            "input_invalid",
            400,
            Some(r#"{"mutationStatus": "not_applied"}"#),
            json!({"mutationStatus": "not_applied", "retrySafe": true, "operationDispatched": true}),
        ),
        (
            "resource_forbidden",
            "service_action_denied",
            403,
            None,
            json!({"mutationStatus": "unknown", "retrySafe": false, "operationDispatched": true}),
        ),
        (
            "conflict",
            "version_conflict",
            409,
            Some(r#"{"mutationStatus": "unknown"}"#),
            json!({"mutationStatus": "unknown", "retrySafe": false, "operationDispatched": true}),
        ),
        (
            "upstream_failed",
            "upstream_failed",
            424,
            Some(
                r#"{"mutationStatus": "applied_unverified", "verificationStage": "post_write_read", "safeLocators": {"issue": "OPS-7"}}"#,
            ),
            json!({"mutationStatus": "applied_unverified", "retrySafe": false,
                "verificationStage": "post_write_read", "safeLocators": {"issue": "OPS-7"},
                "operationDispatched": true}),
        ),
        (
            "upstream_unreachable",
            "upstream_connection_failed",
            502,
            None,
            json!({"mutationStatus": "unknown", "retrySafe": false, "operationDispatched": true}),
        ),
    ] {
        let receipt = receipt.map_or(String::new(), |receipt| {
            format!(r#", "receipt": {receipt}"#)
        });
        contract.respond(
            "invoke",
            Some(&format!(
                r#"{{"ok": false, "error": {{"code": "{code}", "message": "The command says no."}}{receipt}}}"#
            )),
        );
        let (status_code, body) = create("mapped").await;
        assert_eq!(status_code.as_u16(), status, "{code}: {body}");
        assert_eq!(body["reasonCode"], reason, "{code}: {body}");
        assert_eq!(body["reason"], "The command says no.", "{code}: {body}");
        assert_eq!(body["result"], expected, "{code}: {body}");
    }

    // Rate limiting carries the wait as the upstream rate-limit result.
    contract.respond(
        "invoke",
        Some(r#"{"ok": false, "error": {"code": "upstream_rate_limited", "message": "Slow down.", "retryAfterSeconds": 30}, "receipt": {"mutationStatus": "not_applied"}}"#),
    );
    let (status, body) = create("limited").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["reasonCode"], "upstream_rate_limited");
    assert_eq!(body["result"]["limitScope"], "upstream");
    assert_eq!(body["result"]["service"], "tickets");
    assert_eq!(body["result"]["retryAfterSeconds"], 30);
    assert_eq!(body["result"]["mutationStatus"], "not_applied");

    // Contract violations fail without exposing the document, and audit
    // records them.
    for (response, case) in [
        (r#"{"ok": true, "result": {"no_key": 1}}"#, "output schema"),
        (
            r#"{"ok": false, "error": {"code": "teapot", "message": "x"}}"#,
            "unknown code",
        ),
        (
            r#"{"ok": true, "result": {"key": "K"}, "receipt": {"retrySafe": true}}"#,
            "receipt field",
        ),
        (
            r#"{"ok": true, "result": {"key": "K"}} {"ok": true}"#,
            "trailing document",
        ),
    ] {
        contract.respond("invoke", Some(response));
        let (status, body) = create("violation").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{case}: {body}");
        assert_eq!(body["reasonCode"], "operation_failed", "{case}");
        assert_eq!(body["reason"], "The tool failed.", "{case}");
        assert_eq!(body["result"]["mutationStatus"], "unknown", "{case}");
        assert!(!body.to_string().contains("no_key") && !body.to_string().contains("teapot"));
    }
    // An error message echoing the personal token, and a locator holding
    // the Basic credential built from the username and token.
    let basic = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(format!("avery:{PERSONAL_TOKEN}"))
    };
    for (response, id) in [
        (
            format!(
                r#"{{"ok": false, "error": {{"code": "upstream_unauthorized", "message": "Rejected {PERSONAL_TOKEN}."}}}}"#
            ),
            "echo-message",
        ),
        (
            format!(
                r#"{{"ok": true, "result": {{"key": "K"}}, "receipt": {{"safeLocators": {{"auth": "Basic {basic}"}}}}}}"#
            ),
            "echo-basic",
        ),
    ] {
        contract.respond("invoke", Some(&response));
        let (status, body) = create(id).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{id}: {body}");
        assert_eq!(body["reasonCode"], "operation_failed", "{id}");
        assert_eq!(body["result"]["mutationStatus"], "unknown", "{id}");
        assert!(!body.to_string().contains(&basic), "{id}");
        no_secret_in(&body.to_string(), id);
        assert_eq!(
            contract.audited(id)[0]["providerAudit"]["command"]["contractViolation"],
            true,
            "{id}"
        );
    }
    // A locator echoing the personal token the request supplied.
    contract.respond(
        "invoke",
        Some(&format!(
            r#"{{"ok": true, "result": {{"key": "K"}}, "receipt": {{"safeLocators": {{"note": "token {PERSONAL_TOKEN}"}}}}}}"#
        )),
    );
    let (status, body) = create("echo").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["result"]["mutationStatus"], "unknown");
    no_secret_in(&body.to_string(), "violation response");
    let records = contract.audited("echo");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0]["providerAudit"]["command"]["contractViolation"],
        true
    );
    assert_eq!(records[0]["providerAudit"]["command"]["exitCode"], 0);
    no_secret_in(&contract.audit_text(), "audit");

    // An empty document after a clean exit leaves the write unknown.
    contract.respond("invoke", Some(""));
    let (status, body) = create("empty").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["result"]["mutationStatus"], "unknown");
    contract.respond("invoke", None);

    // A missing executable fails before dispatch: nothing ran or applied.
    let mut moved = config.clone();
    moved.command_imports.get_mut("tickets").unwrap().path = contract
        .fixture
        .path("absent/command")
        .display()
        .to_string();
    broker.reload_config(&moved).await;
    let started = contract.started("invoke").len();
    let (status, body) = create("absent").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["reasonCode"], "operation_failed");
    assert_eq!(body["reason"], "The tool could not be started.");
    assert_eq!(
        body["result"],
        json!({"mutationStatus": "not_applied", "retrySafe": true, "operationDispatched": false})
    );
    assert_eq!(contract.started("invoke").len(), started);
    let records = contract.audited("absent");
    assert_eq!(records.len(), 1);
    let command = &records[0]["providerAudit"]["command"];
    assert_eq!(command["spawned"], false);
    assert_eq!(command["operationDispatched"], false);
    assert_eq!(command["exitCode"], Value::Null);
    assert_eq!(command["durationMs"], Value::Null);
    assert_eq!(
        records[0]["providerAudit"]["commandAuthorization"]["mode"],
        "broker"
    );
    drop(app);
    broker.stop().await;
}

async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// No process, running or zombie, has the ID `pid`.
fn reaped(pid: i32) -> bool {
    // SAFETY: signal 0 only checks whether the process exists.
    let result = unsafe { libc::kill(pid, 0) };
    result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

fn far() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(60)
}

fn assert_not_applied(status: StatusCode, body: &Value, reason: &str) {
    assert_eq!(body["reasonCode"], reason, "{status}: {body}");
    assert_eq!(
        body["result"],
        json!({"mutationStatus": "not_applied", "retrySafe": true, "operationDispatched": false}),
        "{body}"
    );
}

const CREATED: &str = r#"{"ok": true, "result": {"key": "OPS-1"}}"#;

/// Criteria 12 and 12a: a call queued for its command's only permit is
/// checked after it: a replaced resource fails `scope_unresolved`, a rotated
/// service slot and a disabled action fail `service_action_denied`, a
/// removed personal credential fails `credential_not_provisioned`, all
/// without starting a process; a personal credential rotated during the
/// wait is sent with its new value.
#[tokio::test]
async fn queued_calls_recheck_resources_and_credentials_after_their_permit() {
    let mut contract = Contract::new(&tickets_manifest(false));
    contract.entry("tickets").max_concurrent = 1;
    let config = contract.fixture.config.clone();
    let broker = import_broker(&config).await;
    let app = broker.app();
    let token = contract.admin.clone();
    import(&app, &token, "tickets", "tickets", &["service", "per_user"]).await;
    projects(&app, &token).await;
    let runtime = broker.runtime();
    let (agent, _) = avery(&runtime, &config, &["tickets"]);
    grants(&runtime);
    let bob = contract.fixture.issue(
        "bob",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedServices": ["tickets"], "allowedExecutionContexts": ["default"]}),
    );
    contract.respond("invoke", Some(CREATED));
    let registry = runtime.command_registry().clone();
    let queue = |caller: &str, id: &'static str| {
        let (app, caller) = (app.clone(), caller.to_owned());
        tokio::spawn(async move {
            invoke_as(
                &app,
                &caller,
                id,
                "tickets",
                "issue.create",
                json!({"project": "OPS", "summary": "Queued"}),
            )
            .await
        })
    };

    // A personal credential rotated during the wait is sent as it is now.
    let held = registry.acquire("tickets", 1, far()).await.unwrap();
    let queued = queue(&agent, "rotated");
    wait_until("the call queues", || registry.waiting("tickets") == 1).await;
    personal_credential(&runtime, "pat-rotated-77e1");
    drop(held);
    let (status, body) = queued.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        contract.last("invoke").document["credentials"]["user"]["token"],
        "pat-rotated-77e1"
    );
    let started = contract.started("invoke").len();

    // A removed one fails without falling back to the service credential.
    let held = registry.acquire("tickets", 1, far()).await.unwrap();
    let queued = queue(&agent, "removed");
    wait_until("the call queues", || registry.waiting("tickets") == 1).await;
    runtime
        .managed_store()
        .unwrap()
        .delete_user_credential(
            "avery",
            "tickets",
            "default",
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    drop(held);
    let (status, body) = queued.await.unwrap();
    assert_not_applied(status, &body, "credential_not_provisioned");
    personal_credential(&runtime, PERSONAL_TOKEN);

    // A resource replaced during the wait is never refreshed onto the call.
    let held = registry.acquire("tickets", 1, far()).await.unwrap();
    let queued = queue(&agent, "replaced");
    wait_until("the call queues", || registry.waiting("tickets") == 1).await;
    let version = runtime
        .managed_store()
        .unwrap()
        .resource("ops")
        .unwrap()
        .version;
    admin(
        &app,
        &token,
        Method::PATCH,
        "/v1/admin/policy/resources/ops",
        json!({"expectedVersion": version, "attributes": {"region": "eu-west-8"}}),
    )
    .await;
    drop(held);
    let (status, body) = queued.await.unwrap();
    assert_not_applied(status, &body, "scope_unresolved");

    // A service slot rotated during the wait fences the call rather than
    // substituting the new secret; the next call uses it.
    let held = registry.acquire("tickets", 1, far()).await.unwrap();
    let queued = queue(&bob, "slot");
    wait_until("the call queues", || registry.waiting("tickets") == 1).await;
    let record = current(&app, &token, "tickets").await;
    rotate_service_slot(&app, &token, "tickets", &record, "svc-rotated-0b3d").await;
    drop(held);
    let (status, body) = queued.await.unwrap();
    assert_not_applied(status, &body, "service_action_denied");
    assert_eq!(contract.started("invoke").len(), started);
    let (status, body) = queue(&bob, "after-slot").await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        contract.last("invoke").document["credentials"]["service"]["token"],
        "svc-rotated-0b3d"
    );
    let started = contract.started("invoke").len();

    // An action disabled during the wait is fenced too.
    let held = registry.acquire("tickets", 1, far()).await.unwrap();
    let queued = queue(&agent, "disabled");
    wait_until("the call queues", || registry.waiting("tickets") == 1).await;
    let mut disable = versions(&current(&app, &token, "tickets").await);
    disable["status"] = json!("disabled");
    admin(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/tickets/actions/issue.create/status",
        disable,
    )
    .await;
    drop(held);
    let (status, body) = queued.await.unwrap();
    assert_not_applied(status, &body, "service_action_denied");
    assert_eq!(contract.started("invoke").len(), started);
    for id in ["removed", "replaced", "slot", "disabled"] {
        let records = contract.audited(id);
        assert_eq!(records.len(), 1, "{id}");
        assert_eq!(
            records[0]["providerAudit"]["command"]["spawned"], false,
            "{id}"
        );
        assert_eq!(
            records[0]["providerAudit"]["commandAuthorization"]["mode"], "broker",
            "{id}"
        );
    }
    assert_eq!(registry.in_use("tickets"), 0);
    drop(app);
    broker.stop().await;
}

/// Criteria 18 and 19: `verify: true` runs `<path> verify` for a personal
/// `username-token` credential, read exactly as resolved, and shows
/// Verified or Failed with the mapped reason; without `verify` it is
/// unsupported and no process starts.
#[tokio::test]
async fn verification_runs_verify_only_for_commands_that_declare_it() {
    let mut contract = Contract::new(&tickets_manifest(true));
    let mut notes = tickets_manifest(false);
    notes["credential"] = json!({"kind": "username_token", "modes": ["per_user"]});
    contract.approve("notes", &notes, |_| {});
    let config = contract.fixture.config.clone();
    let broker = import_broker(&config).await;
    let app = broker.app();
    let token = contract.admin.clone();
    import(&app, &token, "tickets", "tickets", &["service", "per_user"]).await;
    import(&app, &token, "notes", "notes", &["per_user"]).await;
    let runtime = broker.runtime();
    avery(&runtime, &config, &["tickets"]);
    let verify = |service: &'static str| {
        let (app, token) = (app.clone(), token.clone());
        async move {
            request(
                &app,
                &token,
                Method::POST,
                &format!("/v1/admin/principals/avery/credentials/{service}/default/verify"),
                None,
            )
            .await
        }
    };

    let (status, verified) = verify("tickets").await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    assert_eq!(
        verified["result"]["verificationStatus"],
        "upstream_verified"
    );
    let run = contract.last("verify");
    let sent = &run.document;
    assert_eq!(sent["format"], "agent-access-command/1");
    assert_eq!(sent["requestId"], verified["brokerRequestId"]);
    assert!(sent["deadline"].is_string());
    assert_eq!(
        sent["credential"],
        json!({"mode": "user", "kind": "username_token", "username": "avery",
            "token": PERSONAL_TOKEN})
    );
    assert_eq!(sent["network"]["trust"], "system");
    let keys = sent
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        ["credential", "deadline", "format", "network", "requestId"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    assert_eq!(run.args, "verify\n");
    no_secret_in(&format!("{:?}", run.env), "environment");
    no_secret_in(&verified.to_string(), "response");
    let audited = contract
        .audit()
        .into_iter()
        .filter(|record| record["brokerRequestId"] == verified["brokerRequestId"])
        .collect::<Vec<_>>();
    let verification = audited
        .iter()
        .find_map(|record| record["providerAudit"].get("verification"))
        .expect("the verification's audit");
    assert_eq!(verification["command"]["name"], "tickets");
    assert_eq!(verification["command"]["spawned"], true);
    assert_eq!(verification["command"]["exitCode"], 0);

    contract.respond(
        "verify",
        Some(r#"{"ok": false, "error": {"code": "upstream_unauthorized", "message": "Token rejected."}}"#),
    );
    let (status, failed) = verify("tickets").await;
    assert_ne!(status, StatusCode::OK, "{failed}");
    assert_eq!(failed["reasonCode"], "upstream_unauthorized", "{failed}");
    let credential = runtime
        .managed_store()
        .unwrap()
        .credential_by_tuple("avery", "tickets", "default")
        .unwrap();
    assert_eq!(
        credential.last_verification_error_code.as_deref(),
        Some("upstream_unauthorized")
    );
    contract.respond("verify", None);

    // Without `verify`, verification is unsupported: checked locally only.
    runtime
        .managed_store()
        .unwrap()
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            agent_access_core::CredentialWriteRequest {
                owner_principal_id: "avery".into(),
                service: "notes".into(),
                name: "default".into(),
                profile: "username-token".into(),
                credential_kind: "basic_api_token".into(),
                secret: json!({"username": "avery", "token": "notes-example"}),
                metadata: json!({}),
                actor: "admin".into(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    let runs = contract.started("verify").len();
    let (status, local) = verify("notes").await;
    assert_eq!(status, StatusCode::OK, "{local}");
    assert_eq!(local["result"]["verificationStatus"], "local_verified");
    assert_eq!(contract.started("verify").len(), runs);
    drop(app);
    broker.stop().await;
}

/// Criterion 17: `network = "inherit"` passes the proxy route with its
/// credentials, the trust mode and the configured `caCertificate` path as
/// is, with the convenience variables each trust mode sets; `network =
/// "none"` passes neither fields nor variables. A locator echoing the proxy
/// password is a contract violation.
#[tokio::test]
async fn inherited_network_settings_follow_the_trust_mode() {
    let ca = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../agent-access-core/tests/fixtures/outbound-tls/ca-a.pem"
    );
    let mut contract = Contract::new(&tickets_manifest(false));
    contract.approve("offline", &clock_manifest(), |entry| {
        entry.network = agent_access_core::CommandNetwork::None;
        entry.env.insert(
            "HTTPS_PROXY".into(),
            "http://own-proxy.example.test:3128".into(),
        );
    });
    let secrets = |name: &str, value: &str| {
        let path = contract.fixture.path(name);
        std::fs::write(&path, value).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        format!("file:{}", path.display())
    };
    let egress = agent_access_provider::EgressProxyConfig {
        url: "https://proxy.example.test:8443".into(),
        username_ref: Some(secrets("proxy-user", "proxy-user")),
        password_ref: Some(secrets("proxy-password", "proxy-pass/5e")),
    };
    let mut config = contract.fixture.config.clone();
    config.network.egress_proxy = Some(egress);
    config.network.outbound_tls = OutboundTlsConfig {
        trust: OutboundTlsTrustMode::Custom,
        ca_certificate: Some(ca.into()),
    };
    let broker = import_broker(&config).await;
    let app = broker.app();
    let token = contract.admin.clone();
    import(&app, &token, "tickets", "tickets", &["service", "per_user"]).await;
    import(&app, &token, "offline", "offline", &[]).await;
    projects(&app, &token).await;
    let runtime = broker.runtime();
    let (agent, _) = avery(&runtime, &config, &["tickets", "offline"]);
    grants(&runtime);
    runtime
        .create_managed_policy_grant(grant(
            "offline",
            "user:avery",
            "offline",
            "time.now",
            "service",
            0,
            select(&[], &[]),
        ))
        .unwrap();
    let proxied = !process_https_proxy();
    let credentialed = "https://proxy-user:proxy-pass%2F5e@proxy.example.test:8443";

    for (trust, name, variables) in [
        (
            OutboundTlsTrustMode::Custom,
            "custom",
            &["NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"][..],
        ),
        (
            OutboundTlsTrustMode::SystemPlusCustom,
            "system_plus_custom",
            &["NODE_EXTRA_CA_CERTS"][..],
        ),
        (OutboundTlsTrustMode::System, "system", &[][..]),
    ] {
        let mut generation = config.clone();
        generation.network.outbound_tls = OutboundTlsConfig {
            trust,
            ca_certificate: (trust != OutboundTlsTrustMode::System).then(|| ca.into()),
        };
        broker.reload_config(&generation).await;
        let (status, body) = invoke_as(
            &app,
            &agent,
            name,
            "tickets",
            "issue.view",
            json!({"project": "OPS", "issue": 1}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{name}: {body}");
        let run = contract.last("invoke");
        let network = &run.document["network"];
        assert_eq!(network["trust"], name);
        let path = (trust != OutboundTlsTrustMode::System).then_some(ca);
        assert_eq!(network["caCertificate"], json!(path), "{name}");
        assert!(network["noProxy"].is_array(), "{name}");
        let set = run
            .env
            .iter()
            .filter(|(variable, _)| {
                matches!(
                    variable.as_str(),
                    "SSL_CERT_FILE" | "REQUESTS_CA_BUNDLE" | "NODE_EXTRA_CA_CERTS"
                )
            })
            .map(|(variable, value)| {
                assert_eq!(value, ca, "{name}: {variable}");
                variable.as_str()
            })
            .collect::<Vec<_>>();
        assert_eq!(set, variables, "{name}");
        if proxied {
            assert_eq!(
                network["proxy"],
                json!({"url": "https://proxy.example.test:8443", "username": "proxy-user",
                    "password": "proxy-pass/5e"}),
                "{name}"
            );
            for variable in ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"] {
                assert_eq!(run.env[variable], credentialed, "{name}: {variable}");
            }
        }
    }

    // A locator copied from HTTPS_PROXY, whose password is percent-encoded,
    // is a contract violation.
    contract.respond(
        "invoke",
        Some(&format!(
            r#"{{"ok": true, "result": {{"key": "K"}}, "receipt": {{"safeLocators": {{"proxy": "{credentialed}"}}}}}}"#
        )),
    );
    let (status, body) = invoke_as(
        &app,
        &agent,
        "echo-proxy-url",
        "tickets",
        "issue.create",
        json!({"project": "OPS", "summary": "x"}),
    )
    .await;
    if proxied {
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["reasonCode"], "operation_failed");
        assert!(!body.to_string().contains("proxy-pass"), "{body}");
    }

    // A locator echoing the proxy password is a contract violation.
    contract.respond(
        "invoke",
        Some(r#"{"ok": true, "result": {"key": "K"}, "receipt": {"safeLocators": {"note": "proxy-pass/5e"}}}"#),
    );
    let (status, body) = invoke_as(
        &app,
        &agent,
        "echo-proxy",
        "tickets",
        "issue.create",
        json!({"project": "OPS", "summary": "x"}),
    )
    .await;
    if proxied {
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["reasonCode"], "operation_failed");
        assert!(!body.to_string().contains("proxy-pass"), "{body}");
    }
    contract.respond("invoke", None);

    // `network = "none"`: no network field and only the configured `env`.
    let (status, body) = invoke_as(&app, &agent, "offline", "offline", "time.now", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let run = contract.last("invoke");
    assert!(run.document.get("network").is_none(), "{}", run.document);
    assert_eq!(
        run.env.keys().cloned().collect::<BTreeSet<_>>(),
        config.command_imports["offline"]
            .env
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(run.env["HTTPS_PROXY"], "http://own-proxy.example.test:3128");
    drop(app);
    broker.stop().await;
}

/// A test broker on `config` whose shutdown waits at most `shutdown` for
/// running operations before stopping them.
async fn broker_with_shutdown(config: &BrokerConfig, shutdown: Duration) -> TestBroker {
    TestBroker::start_with(
        TestBroker::config_builder(config)
            .reload_timeout(Duration::from_secs(5))
            .shutdown_timeout(shutdown),
    )
    .await
}

/// An initialized MCP session of `token`.
async fn mcp_session(app: &Router, token: &str) -> String {
    let initialized = tower::ServiceExt::oneshot(
        app.clone(),
        super::mcp::request(
            Method::POST,
            Some(token),
            None,
            Some(
                json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "command-contract", "version": "1"}}}),
            ),
        ),
    )
    .await
    .unwrap();
    assert_eq!(initialized.status(), StatusCode::OK);
    let session = initialized.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    tower::ServiceExt::oneshot(
        app.clone(),
        super::mcp::request(
            Method::POST,
            Some(token),
            Some(&session),
            Some(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})),
        ),
    )
    .await
    .unwrap();
    session
}

/// Calls `action` of `tickets` over MCP as request `id`; the response
/// resolves once its stream starts.
fn mcp_call(
    app: &Router,
    token: &str,
    session: &str,
    id: u64,
    action: &str,
    inputs: Value,
) -> tokio::task::JoinHandle<axum::response::Response> {
    let request = super::mcp::request(
        Method::POST,
        Some(token),
        Some(session),
        Some(
            json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
            "name": agent_access_core::mcp::tool_name("tickets", action),
            "arguments": {"inputs": inputs}}}),
        ),
    );
    let app = app.clone();
    tokio::spawn(async move { tower::ServiceExt::oneshot(app, request).await.unwrap() })
}

/// The invocation audit records of `action` of `tickets`.
fn action_records(contract: &Contract, action: &str) -> Vec<Value> {
    contract
        .audit()
        .into_iter()
        .filter(|record| record["service"] == "tickets" && record["action"] == action)
        .collect()
}

/// Waits until a new `invoke` run has read its request, and returns its
/// process ID.
async fn next_run(contract: &Contract, before: usize) -> i32 {
    wait_until("the command reads its request", || {
        contract.started("invoke").len() > before
            && contract
                .fixture
                .path(&format!(
                    "requests/invoke-{}.env",
                    contract.started("invoke")[before]
                ))
                .exists()
    })
    .await;
    contract.started("invoke")[before]
}

/// Criterion 15: an HTTP disconnect leaves a running command to finish with
/// its result, and the call is audited once.
#[tokio::test]
async fn an_http_disconnect_leaves_the_command_running_to_its_result() {
    let mut contract = Contract::new(&tickets_manifest(false));
    contract.entry("tickets").timeout = "30s".into();
    let config = contract.fixture.config.clone();
    let broker = import_broker(&config).await;
    let app = broker.app();
    let token = contract.admin.clone();
    import(&app, &token, "tickets", "tickets", &["service", "per_user"]).await;
    projects(&app, &token).await;
    let runtime = broker.runtime();
    let (agent, _) = avery(&runtime, &config, &["tickets"]);
    grants(&runtime);
    let registry = runtime.command_registry().clone();
    contract.respond("invoke", Some(CREATED));

    // The client goes away while the command runs.
    contract.hold(true);
    let before = contract.started("invoke").len();
    let call = {
        let (app, agent) = (app.clone(), agent.clone());
        tokio::spawn(async move {
            invoke_as(
                &app,
                &agent,
                "disconnect",
                "tickets",
                "issue.create",
                json!({"project": "OPS", "summary": "Left behind"}),
            )
            .await
        })
    };
    let pid = next_run(&contract, before).await;
    call.abort();
    let _ = call.await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!reaped(pid));
    assert!(contract.audited("disconnect").is_empty());
    contract.hold(false);
    wait_until("the disconnected call is audited", || {
        !contract.audited("disconnect").is_empty()
    })
    .await;
    wait_until("the command is reaped", || reaped(pid)).await;
    let records = contract.audited("disconnect");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["decision"], "allow");
    assert_eq!(records[0]["providerAudit"]["command"]["exitCode"], 0);
    assert_eq!(
        records[0]["providerAudit"]["command"]["contractViolation"],
        false
    );
    wait_until("the permit returns", || registry.in_use("tickets") == 0).await;
    drop(app);
    let report = broker.stop().await;
    assert!(report.is_clean(), "{report:?}");
}

/// Criterion 15: MCP cancellation after dispatch is advisory: the command
/// runs to its result, and the call is audited once.
#[tokio::test]
async fn mcp_cancellation_leaves_the_command_running_to_its_result() {
    let mut contract = Contract::new(&tickets_manifest(false));
    contract.entry("tickets").timeout = "30s".into();
    let config = contract.fixture.config.clone();
    let broker = import_broker(&config).await;
    let app = broker.app();
    let token = contract.admin.clone();
    import(&app, &token, "tickets", "tickets", &["service", "per_user"]).await;
    projects(&app, &token).await;
    let runtime = broker.runtime();
    let (agent, _) = avery(&runtime, &config, &["tickets"]);
    grants(&runtime);
    let registry = runtime.command_registry().clone();
    contract.respond("invoke", Some(CREATED));
    let session = mcp_session(&app, &agent).await;
    let audited = action_records(&contract, "issue.create").len();
    contract.hold(true);
    let before = contract.started("invoke").len();
    let call = mcp_call(
        &app,
        &agent,
        &session,
        7,
        "issue.create",
        json!({"project": "OPS", "summary": "Cancelled"}),
    );
    let pid = next_run(&contract, before).await;
    // The streamed response has started; the client cancels and goes away.
    let response = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .unwrap()
        .unwrap();
    // Every MCP response body holds the broker state it was admitted under,
    // so only the cancellation's status is kept.
    let cancelled = tower::ServiceExt::oneshot(
        app.clone(),
        super::mcp::request(
            Method::POST,
            Some(&agent),
            Some(&session),
            Some(
                json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
                "params": {"requestId": 7, "reason": "test cancellation"}}),
            ),
        ),
    )
    .await
    .unwrap()
    .status();
    assert_eq!(cancelled, StatusCode::ACCEPTED);
    drop(response);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!reaped(pid));
    contract.hold(false);
    wait_until("the cancelled call is audited", || {
        action_records(&contract, "issue.create").len() > audited
    })
    .await;
    wait_until("the command is reaped", || reaped(pid)).await;
    let records = action_records(&contract, "issue.create");
    assert_eq!(records.len(), audited + 1);
    let record = records.last().unwrap();
    assert_eq!(record["decision"], "allow", "{record}");
    assert_eq!(record["providerAudit"]["command"]["exitCode"], 0);
    assert_eq!(contract.started("invoke").len(), before + 1);
    wait_until("the permit returns", || registry.in_use("tickets") == 0).await;
    drop(app);
    let report = broker.stop().await;
    assert!(report.is_clean(), "{report:?}");
}

/// Criteria 15 and 20: the command timeout, the HTTP MCP deadline and a
/// forced shutdown each kill the process group and audit the call once;
/// interrupted command-enforced calls in mixed and single credential modes
/// still record the grants they passed, with unknown process facts `null`.
#[tokio::test]
async fn deadlines_and_shutdown_kill_commands_and_audit_their_authority_once() {
    let mut contract = Contract::new(&tickets_manifest(false));
    contract.entry("tickets").timeout = "1s".into();
    contract.fixture.config.mcp.operation_timeout_ms = 1500;
    let config = contract.fixture.config.clone();
    let broker = broker_with_shutdown(&config, Duration::from_secs(2)).await;
    let app = broker.app();
    let token = contract.admin.clone();
    import(&app, &token, "tickets", "tickets", &["service", "per_user"]).await;
    projects(&app, &token).await;
    let runtime = broker.runtime();
    let (agent, _) = avery(&runtime, &config, &["tickets"]);
    grants(&runtime);
    runtime
        .create_managed_policy_grant(grant(
            "search-bob",
            "user:bob",
            "tickets",
            "issue.search",
            "service",
            0,
            select(&["ops"], &[]),
        ))
        .unwrap();
    let bob = contract.fixture.issue(
        "bob",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedServices": ["tickets"], "allowedExecutionContexts": ["default"]}),
    );
    let registry = runtime.command_registry().clone();
    contract.hold(true);

    // The command timeout kills and reaps the group; the write is unknown.
    let before = contract.started("invoke").len();
    let (status, body) = invoke_as(
        &app,
        &agent,
        "timeout",
        "tickets",
        "issue.create",
        json!({"project": "OPS", "summary": "Slow"}),
    )
    .await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
    assert_eq!(body["reasonCode"], "upstream_timeout");
    assert_eq!(body["reason"], "The tool did not finish in time.");
    assert_eq!(
        body["result"],
        json!({"mutationStatus": "unknown", "retrySafe": false, "operationDispatched": true})
    );
    let pid = contract.started("invoke")[before];
    wait_until("the command is reaped", || reaped(pid)).await;
    let records = contract.audited("timeout");
    assert_eq!(records.len(), 1);
    let command = &records[0]["providerAudit"]["command"];
    assert_eq!(command["spawned"], true);
    assert_eq!(command["exitCode"], Value::Null);
    assert_eq!(command["signal"], libc::SIGKILL);
    // The Broker stopped it before reading a response: no verdict.
    assert_eq!(command["contractViolation"], Value::Null);
    wait_until("the permit returns", || registry.in_use("tickets") == 0).await;

    // The HTTP MCP deadline drops the call, which kills its process; audit
    // keeps the grants the command was passed.
    let mut generation = config.clone();
    generation
        .command_imports
        .get_mut("tickets")
        .unwrap()
        .timeout = "30s".into();
    broker.reload_config(&generation).await;
    for (caller, modes) in [
        (&agent, BTreeSet::from(["per_user", "service"])),
        (&bob, BTreeSet::from(["service"])),
    ] {
        let session = mcp_session(&app, caller).await;
        let audited = action_records(&contract, "issue.search").len();
        let before = contract.started("invoke").len();
        let call = mcp_call(
            &app,
            caller,
            &session,
            9,
            "issue.search",
            json!({"query": "open"}),
        );
        let pid = next_run(&contract, before).await;
        let response = super::mcp::rpc_body(
            tokio::time::timeout(Duration::from_secs(10), call)
                .await
                .unwrap()
                .unwrap(),
        )
        .await;
        assert_eq!(response["result"]["isError"], true, "{response}");
        wait_until("the command is reaped", || reaped(pid)).await;
        wait_until("the call is audited", || {
            action_records(&contract, "issue.search").len() > audited
        })
        .await;
        let records = action_records(&contract, "issue.search");
        assert_eq!(records.len(), audited + 1);
        let record = records.last().unwrap();
        assert_eq!(record["reasonCode"], "operation_timeout", "{record}");
        let audit = &record["providerAudit"];
        assert_eq!(audit["executionState"], "unknown", "{audit}");
        assert_eq!(audit["command"]["spawned"], true, "{audit}");
        assert_eq!(audit["command"]["exitCode"], Value::Null, "{audit}");
        assert_eq!(audit["command"]["operationDispatched"], true, "{audit}");
        assert_eq!(
            audit["command"]["contractViolation"],
            Value::Null,
            "{audit}"
        );
        let authorization = &audit["commandAuthorization"];
        assert_eq!(authorization["mode"], "command", "{audit}");
        let grants = authorization["grants"].as_array().unwrap();
        assert_eq!(
            grants
                .iter()
                .map(|grant| grant["credentialMode"].as_str().unwrap())
                .collect::<BTreeSet<_>>(),
            modes
        );
        for grant in grants {
            assert!(grant["grant"]["grantId"].is_string(), "{grant}");
            assert!(grant["grant"]["grantVersion"].is_i64(), "{grant}");
            assert!(grant["scope"]["type"].is_string(), "{grant}");
        }
        no_secret_in(&record.to_string(), "interrupted audit");
        wait_until("the permit returns", || registry.in_use("tickets") == 0).await;
    }

    // Forced shutdown kills a running command and reports clean only once
    // it is reaped and its permit returned.
    let before = contract.started("invoke").len();
    let call = {
        let (app, agent) = (app.clone(), agent.clone());
        tokio::spawn(async move {
            invoke_as(
                &app,
                &agent,
                "shutdown",
                "tickets",
                "issue.create",
                json!({"project": "OPS", "summary": "Interrupted"}),
            )
            .await
        })
    };
    let pid = next_run(&contract, before).await;
    drop(app);
    let report = broker.stop().await;
    assert_eq!(report.unfinished_command_processes(), 0);
    assert!(reaped(pid));
    assert_eq!(registry.in_use("tickets"), 0);
    let _ = tokio::time::timeout(Duration::from_secs(5), call).await;
    let records = contract.audited("shutdown");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["reasonCode"], "operation_cancelled");
    let audit = &records[0]["providerAudit"];
    assert_eq!(audit["executionState"], "unknown", "{audit}");
    assert_eq!(audit["command"]["spawned"], true, "{audit}");
    assert_eq!(
        audit["command"]["contractViolation"],
        Value::Null,
        "{audit}"
    );
    assert_eq!(audit["commandAuthorization"]["mode"], "broker", "{audit}");
    contract.hold(false);
}

/// Criterion 18: `username_token` credentials execute in both modes, take
/// part in key readiness and the used-key inventory, and arrive unchanged
/// after a rewrap to a new key and a restart that no longer has the old one.
#[tokio::test]
async fn username_token_credentials_execute_in_both_modes_across_rewrap() {
    use base64::Engine;
    let mut contract = Contract::new(&tickets_manifest(false));
    let next = contract.fixture.path("next-key");
    std::fs::write(
        &next,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
    )
    .unwrap();
    std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o600)).unwrap();
    let encryption = contract
        .fixture
        .config
        .credential_encryption
        .as_mut()
        .unwrap();
    encryption
        .keys
        .push(agent_access_core::CredentialEncryptionKeyConfig {
            id: "next".into(),
            provider: "file".into(),
            env: None,
            path: Some(next.display().to_string()),
        });
    let config = contract.fixture.config.clone();
    let broker = import_broker(&config).await;
    let app = broker.app();
    let token = contract.admin.clone();
    import(&app, &token, "tickets", "tickets", &["service", "per_user"]).await;
    projects(&app, &token).await;
    let runtime = broker.runtime();
    let (agent, _) = avery(&runtime, &config, &["tickets"]);
    grants(&runtime);
    let bob = contract.fixture.issue(
        "bob",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedServices": ["tickets"], "allowedExecutionContexts": ["default"]}),
    );
    contract.respond("invoke", Some(CREATED));
    let calls = |app: Router| {
        let (agent, bob) = (agent.clone(), bob.clone());
        async move {
            for (caller, id) in [(&agent, "personal"), (&bob, "service")] {
                let (status, body) = invoke_as(
                    &app,
                    caller,
                    id,
                    "tickets",
                    "issue.create",
                    json!({"project": "OPS", "summary": "Rewrapped"}),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "{id}: {body}");
            }
        }
    };
    let sent = |contract: &Contract| {
        contract
            .started("invoke")
            .iter()
            .rev()
            .take(2)
            .map(|pid| contract.run("invoke", *pid).document["credentials"].clone())
            .collect::<Vec<_>>()
    };
    let expected = vec![
        json!({"service": {"kind": "username_token", "username": "svc-tickets", "token": SERVICE_TOKEN}}),
        json!({"user": {"kind": "username_token", "username": "avery", "token": PERSONAL_TOKEN}}),
    ];
    calls(app.clone()).await;
    assert_eq!(sent(&contract), expected);

    {
        let store = runtime.managed_store().unwrap();
        let ring = runtime.credential_key_ring().unwrap();
        store.check_active_credential_keys(ring).unwrap();
        let summary = store
            .rewrap_credentials(ring, "test", "next", "admin")
            .unwrap();
        assert!(summary.rewrapped >= 2, "{summary:?}");
        assert_eq!(summary.conflicts, 0);
    }
    drop((runtime, app));
    broker.stop().await;

    // Without the old key, readiness passes and both credentials arrive as
    // they were stored.
    let mut rotated = config.clone();
    let encryption = rotated.credential_encryption.as_mut().unwrap();
    encryption.active_key = "next".into();
    encryption.keys.retain(|key| key.id == "next");
    let broker = import_broker(&rotated).await;
    calls(broker.app()).await;
    assert_eq!(sent(&contract), expected);
    broker.stop().await;
}

/// Item: a call whose import changed after its request was built, while it
/// resolved resources, credentials and its caller, is fenced immediately
/// before the command starts: `service_action_denied` with `not_applied`,
/// and no process receives its credentials.
#[tokio::test]
async fn calls_are_fenced_again_immediately_before_the_command_starts() {
    let contract = Contract::new(&tickets_manifest(false));
    let config = contract.fixture.config.clone();
    let broker = import_broker(&config).await;
    let app = broker.app();
    let token = contract.admin.clone();
    // A service name no other test pauses.
    import(&app, &token, "fenced", "tickets", &["service", "per_user"]).await;
    admin(
        &app,
        &token,
        Method::POST,
        "/v1/admin/policy/resources",
        json!({"id": "fenced-all", "resourceType": "fenced_project",
            "selector": {"kind": "all"}, "allowedExecutionContexts": ["default"]}),
    )
    .await;
    broker
        .runtime()
        .create_managed_policy_grant(grant(
            "fenced",
            "user:bob",
            "fenced",
            "issue.create",
            "service",
            0,
            select(&["fenced-all"], &[]),
        ))
        .unwrap();
    let bob = contract.fixture.issue(
        "bob",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedServices": ["fenced"], "allowedExecutionContexts": ["default"]}),
    );
    contract.respond("invoke", Some(CREATED));

    let pause = agent_access_core::test_support::CommandDispatchPause::new("fenced");
    let call = {
        let (app, bob) = (app.clone(), bob.clone());
        tokio::spawn(async move {
            invoke_as(
                &app,
                &bob,
                "fenced-call",
                "fenced",
                "issue.create",
                json!({"project": "OPS", "summary": "Fenced"}),
            )
            .await
        })
    };
    pause.reached().await;
    // The request is built; rotating the slot retires the admitted import.
    let record = current(&app, &token, "fenced").await;
    rotate_service_slot(&app, &token, "fenced", &record, "svc-rotated-5c1e").await;
    pause.release();
    let (status, body) = call.await.unwrap();
    assert_not_applied(status, &body, "service_action_denied");
    assert!(contract.started("invoke").is_empty());
    let records = contract.audited("fenced-call");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["providerAudit"]["command"]["spawned"], false);
    drop(pause);

    // The next call runs with the rotated secret.
    let (status, body) = invoke_as(
        &app,
        &bob,
        "fenced-next",
        "fenced",
        "issue.create",
        json!({"project": "OPS", "summary": "Next"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        contract.last("invoke").document["credentials"]["service"]["token"],
        "svc-rotated-5c1e"
    );
    drop(app);
    broker.stop().await;
}

/// Item: a personal verification queued for the command's only slot is
/// fenced after it: a reload that changed the command entry rejects it
/// without starting `verify` or supplying the credential.
#[tokio::test]
async fn queued_verifications_are_fenced_after_their_slot() {
    let mut contract = Contract::new(&tickets_manifest(true));
    contract.entry("tickets").max_concurrent = 1;
    let config = contract.fixture.config.clone();
    let broker = import_broker(&config).await;
    let app = broker.app();
    let token = contract.admin.clone();
    import(&app, &token, "tickets", "tickets", &["service", "per_user"]).await;
    let runtime = broker.runtime();
    avery(&runtime, &config, &["tickets"]);
    let registry = runtime.command_registry().clone();

    let held = registry.acquire("tickets", 1, far()).await.unwrap();
    let verify = {
        let (app, token) = (app.clone(), token.clone());
        tokio::spawn(async move {
            request(
                &app,
                &token,
                Method::POST,
                "/v1/admin/principals/avery/credentials/tickets/default/verify",
                None,
            )
            .await
        })
    };
    wait_until("the verification queues", || {
        registry.waiting("tickets") == 1
    })
    .await;
    let mut moved = config.clone();
    let entry = moved.command_imports.get_mut("tickets").unwrap();
    let script = std::path::Path::new(&entry.path).to_path_buf();
    entry.path = script
        .parent()
        .unwrap()
        .join(".")
        .join(script.file_name().unwrap())
        .display()
        .to_string();
    broker.reload_config(&moved).await;
    drop(held);
    let (status, body) = verify.await.unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "service_action_denied", "{body}");
    assert!(contract.started("verify").is_empty());
    assert_eq!(registry.in_use("tickets"), 0);

    // The current generation verifies with the new entry.
    let (status, verified) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/principals/avery/credentials/tickets/default/verify",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    assert_eq!(contract.started("verify").len(), 1);
    drop((runtime, app));
    broker.stop().await;
}

/// Item: an exact resource without attributes deleted and recreated while a
/// call waits is a different entry: `scope_unresolved` with `not_applied`.
#[tokio::test]
async fn a_recreated_resource_without_attributes_fails_the_queued_call() {
    let mut contract = Contract::new(&tickets_manifest(false));
    contract.entry("tickets").max_concurrent = 1;
    let config = contract.fixture.config.clone();
    let broker = import_broker(&config).await;
    let app = broker.app();
    let token = contract.admin.clone();
    import(&app, &token, "tickets", "tickets", &["service", "per_user"]).await;
    projects(&app, &token).await;
    let lab = json!({"id": "lab", "resourceType": "tickets_project",
        "selector": {"kind": "exact", "value": "LAB"}, "allowedExecutionContexts": ["default"]});
    admin(
        &app,
        &token,
        Method::POST,
        "/v1/admin/policy/resources",
        lab.clone(),
    )
    .await;
    let runtime = broker.runtime();
    avery(&runtime, &config, &["tickets"]);
    grants(&runtime);
    let bob = contract.fixture.issue(
        "bob",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedServices": ["tickets"], "allowedExecutionContexts": ["default"]}),
    );
    contract.respond("invoke", Some(CREATED));
    let registry = runtime.command_registry().clone();
    let create = |id: &'static str| {
        let (app, bob) = (app.clone(), bob.clone());
        tokio::spawn(async move {
            invoke_as(
                &app,
                &bob,
                id,
                "tickets",
                "issue.create",
                json!({"project": "LAB", "summary": "Queued"}),
            )
            .await
        })
    };
    // Admitted with the entry, the value passes its ID.
    let (status, body) = create("lab-before").await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        contract.last("invoke").document["authorization"]["resources"],
        json!([{"value": "LAB", "id": "lab", "attributes": {}}])
    );
    let started = contract.started("invoke").len();

    let version = || {
        runtime
            .managed_store()
            .unwrap()
            .resource("lab")
            .unwrap()
            .version
    };
    // Deleted and recreated identically in a later second.
    let held = registry.acquire("tickets", 1, far()).await.unwrap();
    let queued = create("lab-recreated");
    wait_until("the call queues", || registry.waiting("tickets") == 1).await;
    runtime
        .delete_managed_resource(agent_access_core::DeleteResourceRequest {
            id: "lab".into(),
            expected_version: version(),
            updated_by: "admin".into(),
        })
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    admin(
        &app,
        &token,
        Method::POST,
        "/v1/admin/policy/resources",
        lab,
    )
    .await;
    assert_eq!(version(), 1);
    drop(held);
    let (status, body) = queued.await.unwrap();
    assert_not_applied(status, &body, "scope_unresolved");
    // Changed: renamed, which advances its version.
    let held = registry.acquire("tickets", 1, far()).await.unwrap();
    let queued = create("lab-renamed");
    wait_until("the call queues", || registry.waiting("tickets") == 1).await;
    admin(
        &app,
        &token,
        Method::PATCH,
        "/v1/admin/policy/resources/lab",
        json!({"expectedVersion": version(), "displayName": "Laboratory"}),
    )
    .await;
    drop(held);
    let (status, body) = queued.await.unwrap();
    assert_not_applied(status, &body, "scope_unresolved");
    assert_eq!(contract.started("invoke").len(), started);
    drop((runtime, app));
    broker.stop().await;
}

/// Items: a failed command verification keeps its process facts in its
/// audit record, for a valid error code, a non-zero exit, a contract
/// violation and a timeout; command verification records no upstream
/// status.
#[tokio::test]
async fn failed_verifications_keep_their_process_facts() {
    let mut contract = Contract::new(&tickets_manifest(true));
    contract.entry("tickets").timeout = "1s".into();
    let config = contract.fixture.config.clone();
    let broker = import_broker(&config).await;
    let app = broker.app();
    let token = contract.admin.clone();
    import(&app, &token, "tickets", "tickets", &["service", "per_user"]).await;
    let runtime = broker.runtime();
    avery(&runtime, &config, &["tickets"]);
    let verify = || {
        let (app, token) = (app.clone(), token.clone());
        async move {
            request(
                &app,
                &token,
                Method::POST,
                "/v1/admin/principals/avery/credentials/tickets/default/verify",
                None,
            )
            .await
        }
    };
    let audited = |contract: &Contract, body: &Value| {
        contract
            .audit()
            .into_iter()
            .find(|record| {
                record["brokerRequestId"] == body["brokerRequestId"]
                    && record["providerAudit"].get("verification").is_some()
            })
            .unwrap_or_else(|| panic!("no verification audit: {body}"))
    };

    let (status, verified) = verify().await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    let record = audited(&contract, &verified);
    assert!(record["upstreamStatus"].is_null(), "{record}");
    assert!(record["upstreamDurationMs"].is_u64(), "{record}");
    let facts = &record["providerAudit"]["verification"]["command"];
    assert_eq!(facts["exitCode"], 0, "{record}");
    assert_eq!(facts["contractViolation"], false, "{record}");

    for (case, setup, reason, exit_code, signal, violation) in [
        (
            "error code",
            Some((
                "verify.json",
                r#"{"ok": false, "error": {"code": "upstream_unauthorized", "message": "Rejected."}}"#,
            )),
            "upstream_unauthorized",
            json!(0),
            Value::Null,
            json!(false),
        ),
        (
            "non-zero exit",
            Some(("verify.exit", "3")),
            "operation_failed",
            json!(3),
            Value::Null,
            json!(false),
        ),
        (
            "contract violation",
            Some(("verify.json", "not json")),
            "operation_failed",
            json!(0),
            Value::Null,
            json!(true),
        ),
        (
            "timeout",
            None,
            "upstream_timeout",
            Value::Null,
            json!(libc::SIGKILL),
            Value::Null,
        ),
    ] {
        match setup {
            Some((file, content)) => {
                std::fs::write(contract.fixture.path(&format!("responses/{file}")), content)
                    .unwrap()
            }
            None => contract.hold(true),
        }
        let (status, failed) = verify().await;
        assert_ne!(status, StatusCode::OK, "{case}: {failed}");
        assert_eq!(failed["reasonCode"], reason, "{case}: {failed}");
        let record = audited(&contract, &failed);
        assert!(record["upstreamStatus"].is_null(), "{case}: {record}");
        let facts = &record["providerAudit"]["verification"]["command"];
        assert_eq!(facts["name"], "tickets", "{case}: {record}");
        assert_eq!(facts["spawned"], true, "{case}: {record}");
        assert_eq!(facts["exitCode"], exit_code, "{case}: {record}");
        assert_eq!(facts["signal"], signal, "{case}: {record}");
        assert_eq!(facts["contractViolation"], violation, "{case}: {record}");
        no_secret_in(&record.to_string(), case);
        match setup {
            Some((file, _)) => {
                std::fs::remove_file(contract.fixture.path(&format!("responses/{file}"))).unwrap()
            }
            None => contract.hold(false),
        }
    }
    drop((runtime, app));
    broker.stop().await;
}
