//! A command import of the reference command, `tests/fixtures/command-imports/ticketing.py`,
//! through the shipped CLI and a real broker: approval, `describe` discovery and
//! acceptance, credentials, invocation in both authorization modes with write
//! receipts, error and receipt mapping and contract violations, mixed-mode
//! command-checked grants against discovery, attribute removal without a
//! reload, personal verification and the HTTP MCP listing. The command runs
//! under Python 3; a missing interpreter fails the test.
use agent_access_broker_host::test_support::{FixtureDir, IsolatedBroker, RunningBroker};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    GroupWriteRequest, ManagedStore, ManagedStoreConfig, ManagedStoreOpenMode,
    PrincipalAccessPatchRequest, PrincipalRole, PrincipalWriteRequest,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const SERVICE_TOKEN: &str = "svc-smoke-service-token";
const PERSONAL_TOKEN: &str = "pat-smoke-personal-token";
const WEBHOOK_SECRET: &str = "s3cr3t-smoke-webhook";
const MCP_VERSION: &str = "2025-11-25";

/// The reference command, run directly through its `#!/usr/bin/env python3`.
fn reference_command() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/command-imports/ticketing.py")
}

/// The directory of the Python 3 interpreter the command's `env` finds.
fn python_directory() -> PathBuf {
    let output = Command::new("python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .expect("the reference command needs python3 on PATH");
    assert!(output.status.success(), "python3 failed to start");
    let executable = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
    executable.parent().unwrap().to_path_buf()
}

/// A TOML basic string holding `value`.
fn toml_string(value: impl Display) -> String {
    serde_json::to_string(&value.to_string()).unwrap()
}

fn cli(config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    // A developer's ambient broker/token configuration must never change the
    // broker or identity this test exercises.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
            command.env_remove(key);
        }
    }
    command.arg("--config").arg(config);
    command
}

fn run(config: &Path, args: &[&str]) -> Value {
    let output = cli(config).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "args={args:?} stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

/// A failing CLI call's JSON envelope.
fn run_failing(config: &Path, args: &[&str]) -> Value {
    let output = cli(config).args(args).output().unwrap();
    assert!(
        !output.status.success(),
        "args={args:?} unexpectedly succeeded"
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn invoke(config: &Path, action: &str, inputs: Value) -> Value {
    run(
        config,
        &[
            "invoke",
            &format!("ticketing.{action}"),
            "--input-json",
            &inputs.to_string(),
        ],
    )
}

fn versions(response: &Value) -> (String, String) {
    (
        response["result"]["service"]["version"].to_string(),
        response["result"]["catalogRevision"].to_string(),
    )
}

fn write_file(directory: &Path, name: &str, contents: impl AsRef<[u8]>) -> String {
    let path = directory.join(name);
    std::fs::write(&path, contents).unwrap();
    path.display().to_string()
}

fn client_config(directory: &Path, name: &str, base: &str, token: &str) -> PathBuf {
    let token_path = write_file(directory, &format!("{name}.token"), token);
    let path = directory.join(format!("{name}.toml"));
    std::fs::write(
        &path,
        format!(
            "[service]\nurl={base:?}\n[identity]\nheader=\"Authorization\"\nscheme=\"Bearer\"\ndisabled=false\ntoken_file={token_path:?}\n"
        ),
    )
    .unwrap();
    path
}

/// Managed identity, policy and store with management, HTTP MCP, JSONL audit,
/// and imports limited to the approved `ticketing` command, which inherits
/// the Broker's network settings and reads its manifest profile from the file
/// `profile`, so the test can upgrade it without a reload.
fn broker_document(directory: &FixtureDir, mcp_public_url: &str) -> String {
    format!(
        r#"
[identity]
mode = "required"
authority = "managed"

[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"

[managed_store]
type = "sqlite"
path = {store}
auto_migrate = true
require_registered_principal_for_invocation = true

[broker_tokens]
hash_key_ref = {hash_key}

[credential_encryption]
active_key = "test"

[[credential_encryption.keys]]
id = "test"
provider = "file"
path = {key}

[management]
enabled = true

[policy]
authority = "managed"
default_decision = "deny"

[imports]
enabled = true
allowed_kinds = ["command"]

[command_imports.ticketing]
path = {command}
timeout = "30s"
network = "inherit"

[command_imports.ticketing.env]
PATH = {path}
LANG = "C.UTF-8"
TICKETING_PROFILE_FILE = {profile}

[audit]
type = "jsonl"
path = {audit}

[mcp]
enabled = true
public_url = {mcp_public_url}

[limits]
upload_spool_dir = {spool}
"#,
        store = toml_string(directory.join("store.sqlite").display()),
        hash_key = toml_string(format_args!("file:{}", directory.join("hash").display())),
        key = toml_string(directory.join("key").display()),
        command = toml_string(reference_command().display()),
        path = toml_string(format_args!(
            "{}:/usr/bin:/bin",
            python_directory().display()
        )),
        profile = toml_string(directory.join("profile").display()),
        audit = toml_string(directory.join("audit.jsonl").display()),
        mcp_public_url = toml_string(mcp_public_url),
        spool = toml_string(directory.join("upload-spool").display()),
    )
}

/// The tokens [`seed`] issues.
struct Seeded {
    admin: String,
    agent: String,
    agent_id: String,
}

/// Seeds the principals, Avery's `engineering` group and the admin and agent
/// tokens, before the broker opens and locks the store.
fn seed(directory: &FixtureDir, hash: &Path) -> Seeded {
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: directory.join("store.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: true,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    for (principal, display_name) in [("admin", None), ("avery", Some("Avery Example"))] {
        store
            .create_principal(PrincipalWriteRequest {
                role: PrincipalRole::User,
                self_service_enabled: None,
                principal_id: principal.into(),
                kind: "user".into(),
                display_name: display_name.map(str::to_owned),
                email: None,
                external_subject: None,
                created_by: "admin".into(),
            })
            .unwrap();
    }
    store
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "admin".into(),
            role: Some(PrincipalRole::Admin),
            self_service_enabled: None,
            actor: "test".into(),
        })
        .unwrap();
    store
        .create_group(GroupWriteRequest {
            group_id: "engineering".into(),
            display_name: None,
            description: None,
            auto_enroll_new_microsoft_users: false,
            created_by: "admin".into(),
        })
        .unwrap();
    store.add_group("avery", "engineering", "admin").unwrap();
    let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash.display()),
        ..Default::default()
    })
    .unwrap();
    let issue = |principal: &str, class, scopes| {
        store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: principal.into(),
                    name: "command smoke".into(),
                    token_class: class,
                    scopes,
                    expires_at: None,
                    created_by: "admin".into(),
                },
            )
            .unwrap()
    };
    let admin = issue("admin", BrokerTokenClass::Admin, json!({})).token;
    let agent = issue(
        "avery",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedExecutionContexts": ["default"]}),
    );
    Seeded {
        admin,
        agent: agent.token,
        agent_id: agent.record.token_id,
    }
}

/// A fresh agent request ID.
fn request_id() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    format!(
        "command-smoke-{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

/// A call of `ticketing.<action>` over HTTP: status, `Retry-After` and body.
async fn http_invoke(
    base: &str,
    token: &str,
    action: &str,
    inputs: Value,
) -> (u16, Option<String>, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/invoke/ticketing/{action}"))
        .bearer_auth(token)
        .header("X-Agent-Access-Request-Id", request_id())
        .json(&json!({"inputs": inputs}))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("retry-after")
        .map(|value| value.to_str().unwrap().to_owned());
    (status, retry_after, response.json().await.unwrap())
}

/// A discovery read with `token`; `None` when the service is hidden.
async fn http_get(base: &str, token: &str, path: &str) -> Option<Value> {
    let response = reqwest::Client::new()
        .get(format!("{base}{path}"))
        .bearer_auth(token)
        .header("X-Agent-Access-Request-Id", request_id())
        .send()
        .await
        .unwrap();
    if response.status() == reqwest::StatusCode::FORBIDDEN {
        return None;
    }
    assert!(response.status().is_success(), "{path}");
    Some(response.json().await.unwrap())
}

/// The actions the caller's service catalog lists.
async fn catalog_actions(base: &str, token: &str) -> Vec<String> {
    let mut actions = http_get(base, token, "/v1/services/ticketing")
        .await
        .map(|service| {
            service["actions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|action| action["action"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    actions.sort();
    actions
}

/// Whether resource discovery offers `action` for project `value`.
async fn offered(base: &str, token: &str, action: &str, value: &str) -> bool {
    http_get(
        base,
        token,
        &format!("/v1/services/ticketing/actions?resource={value}"),
    )
    .await
    .is_some_and(|listed| {
        listed["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|offered| offered == action)
    })
}

/// The audit records of one Broker request, waiting briefly for the audit
/// writer to append them.
fn audited(directory: &Path, broker_request_id: &str) -> Vec<Value> {
    for _ in 0..100 {
        let records = std::fs::read_to_string(directory.join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|record| record["brokerRequestId"] == broker_request_id)
            .collect::<Vec<_>>();
        if !records.is_empty() {
            return records;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Vec::new()
}

/// Whether a request's audit shows that the command process started.
fn spawned(directory: &Path, broker_request_id: &str) -> bool {
    let records = audited(directory, broker_request_id);
    assert!(!records.is_empty(), "no audit for {broker_request_id}");
    records
        .iter()
        .any(|record| record["providerAudit"]["command"]["spawned"] == true)
}

/// The grants a search echoes, sorted by credential mode.
fn passed_grants(search: &Value) -> Vec<Value> {
    let mut grants = search["result"]["upstreamCommand"]["grants"]
        .as_array()
        .unwrap()
        .clone();
    grants.sort_by_key(|grant| grant["credential"].as_str().unwrap().to_owned());
    grants
}

/// One JSON-RPC response from an HTTP MCP answer, JSON or event stream.
async fn rpc_response(response: reqwest::Response) -> Value {
    assert!(response.status().is_success());
    let content_type = response.headers()["content-type"]
        .to_str()
        .unwrap()
        .to_owned();
    let text = tokio::time::timeout(Duration::from_secs(10), response.text())
        .await
        .unwrap()
        .unwrap();
    if content_type.starts_with("application/json") {
        return serde_json::from_str(&text).unwrap();
    }
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .find(|message| message.get("id").is_some())
        .unwrap()
}

/// The `ticketing` tool names an agent's HTTP MCP session lists.
async fn mcp_tool_names(base: &str, token: &str) -> Vec<String> {
    let client = reqwest::Client::new();
    let request = |body: Value| {
        client
            .post(format!("{base}/mcp"))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .json(&body)
    };
    let initialized = request(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": MCP_VERSION, "capabilities": {},
            "clientInfo": {"name": "command-smoke", "version": "1"}}}))
    .send()
    .await
    .unwrap();
    let session = initialized.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        rpc_response(initialized).await["result"]["protocolVersion"],
        MCP_VERSION
    );
    let notified = request(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", MCP_VERSION)
        .send()
        .await
        .unwrap();
    assert!(notified.status().is_success());
    let listed = request(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", MCP_VERSION)
        .send()
        .await
        .unwrap();
    let tools = rpc_response(listed).await;
    let mut names = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .filter(|name| name.starts_with("ticketing_"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    names.sort();
    names
}

async fn stop(broker: RunningBroker) {
    broker.shutdown();
    broker.join().await.unwrap();
}

fn assert_no_secret(text: &str, what: &str) {
    for secret in [SERVICE_TOKEN, PERSONAL_TOKEN, WEBHOOK_SECRET] {
        assert!(!text.contains(secret), "{what} exposes a supplied secret");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reference_command_imports_invokes_in_both_modes_verifies_and_lists_over_mcp() {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let directory = application.directory().clone();
    let base = application.public_url();
    directory
        .secret_file("key", URL_SAFE_NO_PAD.encode([71u8; 32]))
        .unwrap();
    let hash = directory
        .secret_file("hash", URL_SAFE_NO_PAD.encode([72u8; 32]))
        .unwrap();
    let seeded = seed(&directory, &hash);
    let files = directory.path();
    let profile = |name: &str| std::fs::write(files.join("profile"), name).unwrap();
    profile("default");
    let admin = client_config(files, "admin", &base, &seeded.admin);
    let agent = client_config(files, "agent", &base, &seeded.agent);
    let broker = application
        .config_document(broker_document(&directory, &format!("{base}/mcp")))
        .start()
        .await
        .unwrap();

    // Import the approved command by name; discovery runs `describe`.
    let bindings = ["service", "per_user"].map(|mode| {
        json!({"ownerMode": mode, "mechanism": "static_token",
            "delivery": {"kind": "stdin"}, "status": "configured"})
    });
    let created = run(
        &admin,
        &[
            "admin",
            "imports",
            "create",
            "--request-file",
            &write_file(
                files,
                "create.json",
                json!({"service": "ticketing", "displayName": "Ticketing",
                    "adapterKind": "command", "endpoint": "command:ticketing",
                    "executionBindings": bindings,
                    "discovery": {"kind": "anonymous"}})
                .to_string(),
            ),
        ],
    );
    assert_eq!(created["result"]["service"]["status"], "draft");
    let (version, revision) = versions(&created);
    let discovered = run(
        &admin,
        &[
            "admin",
            "imports",
            "discover",
            "ticketing",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    let preview = &discovered["result"]["preview"];
    let manifest = &preview["manifest"];
    assert_eq!(manifest["protocolVersion"], "agent-access-command/1");
    assert_eq!(manifest["serviceMetadata"]["version"], "1.4.0");
    assert_eq!(
        manifest["serviceMetadata"]["credential"],
        json!({"kind": "username_token", "modes": ["service", "per_user"]})
    );
    assert_eq!(
        manifest["serviceMetadata"]["resourceTypes"][0]["brokerType"],
        "ticketing_project"
    );
    let changes = &discovered["result"]["resourceTypeChanges"];
    assert_eq!(changes[0]["change"], "added");
    assert_eq!(changes[0]["editable"], true);
    let tools = manifest["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 5);
    assert!(tools.iter().all(|tool| tool["unsupportedReason"].is_null()));
    let accepted = accept_all(&admin, files, &discovered);
    assert_eq!(accepted["result"]["commandVersion"], "1.4.0");
    let (version, revision) = versions(&accepted);
    let service_secret = write_file(files, "service.token", SERVICE_TOKEN);
    let configured = run(
        &admin,
        &[
            "admin",
            "imports",
            "credentials",
            "put",
            "ticketing",
            "execution",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
            "--secret-file",
            &service_secret,
            "--username",
            "svc-tickets",
        ],
    );
    assert_no_secret(&configured.to_string(), "the credential response");
    let (version, revision) = versions(&configured);
    let enabled = run(
        &admin,
        &[
            "admin",
            "imports",
            "status",
            "ticketing",
            "enabled",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    assert_eq!(enabled["result"]["service"]["status"], "enabled");

    // Resources of the imported type: OPS with private attributes, WEB, SEC,
    // every project, and the group `wide` of every project except SEC.
    let attributes = write_file(
        files,
        "attributes.json",
        json!({"region": "eu-1", "webhookSecret": WEBHOOK_SECRET}).to_string(),
    );
    for (id, value, name) in [
        ("ops", Some("OPS"), Some("Operations")),
        ("web", Some("WEB"), None),
        ("sec", Some("SEC"), None),
        ("all-projects", None, None),
    ] {
        let mut args = vec![
            "admin",
            "policy",
            "resources",
            "create",
            "--id",
            id,
            "--resource-type",
            "ticketing_project",
            "--execution-context",
            "default",
        ];
        match value {
            Some(value) => args.extend(["--selector-kind", "exact", "--selector-value", value]),
            None => args.extend(["--selector-kind", "all"]),
        }
        if let Some(name) = name {
            args.extend(["--display-name", name, "--attributes-file", &attributes]);
        }
        run(&admin, &args);
    }
    run(
        &admin,
        &[
            "admin",
            "policy",
            "resource-groups",
            "create",
            "--id",
            "wide",
            "--name",
            "Every project but SEC",
            "--included-resource-id",
            "all-projects",
            "--excluded-resource-id",
            "sec",
        ],
    );
    let grant = |id: &str, actions: &[&str], mode: &str, resources: &[&str], groups: &[&str]| {
        let mut args = vec![
            "admin",
            "policy",
            "grants",
            "create",
            "--grant-id",
            id,
            "--subject",
            "user:avery",
            "--service",
            "ticketing",
            "--credential-mode",
            mode,
            "--execution-context",
            "default",
        ];
        for action in actions {
            args.extend(["--action", action]);
        }
        for resource in resources {
            args.extend(["--resource-id", resource]);
        }
        for group in groups {
            args.extend(["--resource-group-id", group]);
        }
        run(&admin, &args);
    };
    grant(
        "ticketing-service",
        &["issue.view", "issue.create"],
        "service",
        &["ops"],
        &[],
    );
    grant(
        "ticketing-personal",
        &["issue.search", "issue.close"],
        "per_user",
        &["ops", "web"],
        &[],
    );
    // A mixed-mode pair on the command-checked search: the same subject and
    // priority, personal over OPS and WEB, service over every project but SEC.
    grant(
        "ticketing-search-service",
        &["issue.search"],
        "service",
        &[],
        &["wide"],
    );
    grant("ticketing-whoami", &["whoami"], "per_user", &[], &[]);

    // The personal username-and-token credential, verified by the command.
    let personal_secret = write_file(files, "personal.token", PERSONAL_TOKEN);
    let saved = run(
        &admin,
        &[
            "admin",
            "credentials",
            "put",
            "avery",
            "ticketing",
            "--profile",
            "username-token",
            "--username",
            "avery",
            "--field-file",
            &format!("token={personal_secret}"),
        ],
    );
    assert_no_secret(&saved.to_string(), "the saved credential");
    let verified = run(
        &admin,
        &["admin", "credentials", "verify", "avery", "ticketing"],
    );
    assert_eq!(
        verified["result"]["verificationStatus"], "upstream_verified",
        "{verified}"
    );

    // Broker-checked: the named resource with its private attributes and the
    // service credential; a write reports the command's receipt.
    let view = invoke(&agent, "issue.view", json!({"project": "OPS", "issue": 42}));
    let result = &view["result"]["upstreamCommand"];
    assert_eq!(result["issue"]["key"], "OPS-42");
    assert_eq!(
        result["access"],
        json!({"credential": "service", "account": "svc-tickets",
            "attributes": ["region", "webhookSecret"]})
    );
    let created = invoke(
        &agent,
        "issue.create",
        json!({"project": "OPS", "summary": "Rotate the build keys"}),
    );
    assert_eq!(created["result"]["upstreamCommand"]["key"], "OPS-43");
    assert_eq!(created["result"]["upstreamCommand"]["webhookSigned"], true);
    assert_eq!(created["result"]["mutationStatus"], "applied_unverified");
    assert_eq!(created["result"]["retrySafe"], false);
    assert_eq!(
        created["result"]["safeLocators"],
        json!({"issue": "OPS-43"})
    );
    // An uncovered project is denied before any process starts, for a read
    // and for a write, which nothing applied.
    let denied = run_failing(
        &agent,
        &[
            "invoke",
            "ticketing.issue.view",
            "--input-json",
            &json!({"project": "SEC", "issue": 7}).to_string(),
        ],
    );
    assert_eq!(denied["reasonCode"], "service_action_denied");
    assert!(
        !spawned(files, denied["brokerRequestId"].as_str().unwrap()),
        "{denied}"
    );
    let (status, _, denied_write) = http_invoke(
        &base,
        &seeded.agent,
        "issue.create",
        json!({"project": "SEC", "summary": "x"}),
    )
    .await;
    assert_eq!(status, 403, "{denied_write}");
    assert_eq!(denied_write["reasonCode"], "service_action_denied");
    assert!(
        !spawned(files, denied_write["brokerRequestId"].as_str().unwrap()),
        "{denied_write}"
    );
    // The Broker's own denial, which as a rejection before dispatch carries
    // no write receipt, unlike the command's refusals below.
    for response in [&denied, &denied_write] {
        assert_eq!(
            response["error"]["message"], "policy denied service action for resolved scopes",
            "{response}"
        );
    }
    assert!(denied_write.get("result").is_none(), "{denied_write}");

    // Command-checked: the caller's top-band grants, each with its own
    // credential and boundary; exclusions arrive as `except`.
    let search = invoke(&agent, "issue.search", json!({"query": ""}));
    assert_eq!(
        passed_grants(&search),
        [
            json!({"credential": "service", "resources": "any", "except": ["SEC"]}),
            json!({"credential": "user", "resources": ["OPS", "WEB"]}),
        ],
        "{search}"
    );
    let result = &search["result"]["upstreamCommand"];
    assert_eq!(
        result["issues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|issue| issue["key"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["OPS-41", "OPS-42", "WEB-12", "WEB-13"]
    );
    // The same plan in discovery: the catalog, MCP and resource discovery
    // offer the search exactly where a passed grant covers the project.
    assert!(
        catalog_actions(&base, &seeded.agent)
            .await
            .contains(&"issue.search".to_owned())
    );
    for (value, covered) in [("OPS", true), ("WEB", true), ("NEW", true), ("SEC", false)] {
        assert_eq!(
            offered(&base, &seeded.agent, "issue.search", value).await,
            covered,
            "{value}"
        );
    }
    let closed = invoke(&agent, "issue.close", json!({"key": "WEB-12"}));
    assert_eq!(
        closed["result"]["upstreamCommand"]["access"],
        json!({"credential": "user", "account": "avery"})
    );
    assert_eq!(closed["result"]["mutationStatus"], "applied_unverified");
    assert_eq!(closed["result"]["safeLocators"], json!({"issue": "WEB-12"}));
    // The command, not the Broker, refuses a project outside the passed
    // grants, after starting; nothing was applied.
    let refused = run_failing(
        &agent,
        &[
            "invoke",
            "ticketing.issue.close",
            "--input-json",
            &json!({"key": "SEC-7"}).to_string(),
        ],
    );
    assert_eq!(refused["reasonCode"], "service_action_denied");
    assert_eq!(refused["result"]["mutationStatus"], "not_applied");
    assert_eq!(refused["result"]["operationDispatched"], true);
    assert!(spawned(files, refused["brokerRequestId"].as_str().unwrap()));
    let whoami = invoke(&agent, "whoami", json!({}));
    let caller = &whoami["result"]["upstreamCommand"]["caller"];
    assert_eq!(caller["principal"], "avery");
    assert_eq!(caller["kind"], "user");
    assert_eq!(caller["displayName"], "Avery Example");
    assert_eq!(caller["groups"], json!(["engineering"]));
    assert_eq!(
        caller["token"],
        json!({"id": seeded.agent_id, "label": "command smoke"})
    );
    assert_eq!(whoami["result"]["upstreamCommand"]["context"], "default");
    // `network = "inherit"` without a configured proxy: system trust, no
    // certificate path, and the process's NO_PROXY entries and proxy, if any.
    let network = &whoami["result"]["upstreamCommand"]["network"];
    assert_eq!(network["trust"], "system", "{network}");
    assert_eq!(network["caCertificate"], Value::Null, "{network}");
    assert!(network["noProxy"].is_array(), "{network}");
    let environment = |names: [&str; 2]| {
        names
            .iter()
            .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
    };
    if !environment(["NO_PROXY", "no_proxy"]) {
        assert_eq!(network["noProxy"], json!([]), "{network}");
    }
    if !environment(["HTTPS_PROXY", "https_proxy"]) {
        assert_eq!(network["proxy"], Value::Null, "{network}");
    }
    for response in [&view, &created, &search, &closed, &whoami, &refused] {
        assert_no_secret(&response.to_string(), "an invocation response");
    }

    // Command answers through the error, receipt and contract mapping.
    let (status, _, conflict) = http_invoke(
        &base,
        &seeded.agent,
        "issue.search",
        json!({"query": "trigger:conflict"}),
    )
    .await;
    assert_eq!(
        (status, &conflict["reasonCode"]),
        (409, &json!("version_conflict"))
    );
    assert_eq!(conflict["error"]["message"], "Triggered conflict.");
    let (status, retry_after, limited) = http_invoke(
        &base,
        &seeded.agent,
        "issue.search",
        json!({"query": "trigger:upstream_rate_limited"}),
    )
    .await;
    assert_eq!(status, 429, "{limited}");
    assert_eq!(limited["reasonCode"], "upstream_rate_limited");
    assert_eq!(limited["result"]["retryAfterSeconds"], 30, "{limited}");
    assert_eq!(retry_after.as_deref(), Some("30"));
    let (status, _, unverified) = http_invoke(
        &base,
        &seeded.agent,
        "issue.create",
        json!({"project": "OPS", "summary": "trigger:receipt_applied_unverified"}),
    )
    .await;
    assert_eq!(status, 424, "{unverified}");
    assert_eq!(unverified["reasonCode"], "upstream_failed");
    assert_eq!(unverified["result"]["mutationStatus"], "applied_unverified");
    assert_eq!(unverified["result"]["verificationStage"], "issue_readback");
    assert_eq!(
        unverified["result"]["safeLocators"],
        json!({"issue": "OPS-43"})
    );
    assert_eq!(unverified["result"]["operationDispatched"], true);
    for (action, inputs) in [
        // A receipt with an unknown field, a locator echoing the supplied
        // service credential, and output past `max_output_bytes`.
        (
            "issue.create",
            json!({"project": "OPS", "summary": "trigger:receipt_unknown_field"}),
        ),
        (
            "issue.create",
            json!({"project": "OPS", "summary": "trigger:locator_secret"}),
        ),
        ("issue.search", json!({"query": "trigger:oversized_output"})),
    ] {
        let (status, _, violated) = http_invoke(&base, &seeded.agent, action, inputs.clone()).await;
        assert_eq!(status, 500, "{inputs}: {violated}");
        assert_eq!(violated["reasonCode"], "operation_failed", "{inputs}");
        assert_no_secret(&violated.to_string(), "a contract violation");
        assert!(!violated.to_string().contains("padding"), "{inputs}");
        if action == "issue.create" {
            assert_eq!(violated["result"]["mutationStatus"], "unknown", "{inputs}");
        }
        let records = audited(files, violated["brokerRequestId"].as_str().unwrap());
        assert!(
            records
                .iter()
                .any(|record| record["providerAudit"]["command"]["contractViolation"] == true),
            "{inputs}: {records:?}"
        );
    }

    // A token restricted to OPS narrows every passed grant to OPS, and
    // discovery agrees.
    let restricted = run(
        &admin,
        &[
            "admin",
            "tokens",
            "issue",
            "avery",
            "--name",
            "ops only",
            "--execution-context",
            "default",
            "--service",
            "ticketing",
            "--action",
            "ticketing=issue.search",
            "--resource-id",
            "ticketing=ops",
            "--never",
        ],
    );
    let restricted_token = restricted["result"]["token"].as_str().unwrap().to_owned();
    let restricted_config = client_config(files, "restricted", &base, &restricted_token);
    let narrowed = invoke(&restricted_config, "issue.search", json!({"query": ""}));
    assert_eq!(
        passed_grants(&narrowed),
        [
            json!({"credential": "service", "resources": ["OPS"]}),
            json!({"credential": "user", "resources": ["OPS"]}),
        ],
        "{narrowed}"
    );
    for (value, covered) in [("OPS", true), ("WEB", false), ("NEW", false)] {
        assert_eq!(
            offered(&base, &restricted_token, "issue.search", value).await,
            covered,
            "{value}"
        );
    }

    assert_eq!(
        mcp_tool_names(&base, &seeded.agent).await,
        [
            "ticketing_issue_close",
            "ticketing_issue_create",
            "ticketing_issue_search",
            "ticketing_issue_view",
            "ticketing_whoami"
        ]
    );

    // Upgrading the command to drop one attribute, then the last one: each
    // accepted refresh deletes the removed attributes' values, and the next
    // call, without a reload, carries exactly the remaining attributes.
    for (name, remaining) in [("trimmed", json!(["region"])), ("bare", json!([]))] {
        profile(name);
        let current = run(&admin, &["admin", "imports", "get", "ticketing"]);
        let (version, revision) = versions(&current);
        let refreshed = run(
            &admin,
            &[
                "admin",
                "imports",
                "discover",
                "ticketing",
                "--expected-version",
                &version,
                "--expected-catalog-revision",
                &revision,
            ],
        );
        let change = &refreshed["result"]["resourceTypeChanges"][0];
        assert_eq!(change["details"], json!(["attribute_removed"]), "{name}");
        assert_eq!(change["affectedResources"], json!(["ops"]), "{name}");
        let accepted = accept_all(&admin, files, &refreshed);
        assert_eq!(
            accepted["result"]["resourceTypeEffects"]["deletedAttributeValues"][0]["resourceId"],
            "ops",
            "{name}"
        );
        let view = invoke(&agent, "issue.view", json!({"project": "OPS", "issue": 42}));
        assert_eq!(
            view["result"]["upstreamCommand"]["access"]["attributes"], remaining,
            "{name}"
        );
        let resource = run(&admin, &["admin", "policy", "resources", "get", "ops"]);
        let configured = resource["result"]["configuredAttributes"].clone();
        assert_eq!(
            if configured.is_null() {
                json!([])
            } else {
                configured
            },
            remaining,
            "{name}"
        );
    }

    // Without the personal credential, the personal grant is omitted: the
    // search passes the service grant alone, and personal-only actions leave
    // discovery and the MCP listing.
    run(
        &admin,
        &["admin", "credentials", "delete", "avery", "ticketing"],
    );
    let alone = invoke(&agent, "issue.search", json!({"query": ""}));
    assert_eq!(
        passed_grants(&alone),
        [json!({"credential": "service", "resources": "any", "except": ["SEC"]})],
        "{alone}"
    );
    assert!(offered(&base, &seeded.agent, "issue.search", "WEB").await);
    assert!(!offered(&base, &seeded.agent, "issue.close", "OPS").await);
    assert_eq!(
        mcp_tool_names(&base, &seeded.agent).await,
        [
            "ticketing_issue_create",
            "ticketing_issue_search",
            "ticketing_issue_view"
        ]
    );
    let audit = std::fs::read_to_string(files.join("audit.jsonl")).unwrap();
    assert_no_secret(&audit, "the audit log");
    stop(broker).await;
}

/// Accepts every action of a discovery, the writes as write-capable.
fn accept_all(admin: &Path, files: &Path, discovered: &Value) -> Value {
    let (version, revision) = versions(discovered);
    let selections = discovered["result"]["preview"]["manifest"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| {
            let action = tool["definition"]["action"].as_str().unwrap();
            json!({"source": tool["definition"]["source"], "action": action,
                "readOnly": !matches!(action, "issue.create" | "issue.close")})
        })
        .collect::<Vec<_>>();
    run(
        admin,
        &[
            "admin",
            "imports",
            "accept",
            "ticketing",
            "--request-file",
            &write_file(
                files,
                "accept.json",
                json!({"expectedVersion": version.parse::<u64>().unwrap(),
                    "expectedCatalogRevision": revision.parse::<u64>().unwrap(),
                    "manifestHash": discovered["result"]["preview"]["manifestHash"],
                    "selections": selections})
                .to_string(),
            ),
        ],
    )
}
