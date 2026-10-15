//! A command import of the reference command, `tests/fixtures/command-imports/ticketing.py`,
//! through the shipped CLI and a real broker: approval, `describe` discovery and
//! acceptance, credentials, invocation in both authorization modes with write
//! receipts, personal verification and the HTTP MCP listing. The command runs
//! under Python 3; a missing interpreter fails the test.
use agent_access_broker_host::test_support::{FixtureDir, IsolatedBroker, RunningBroker};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig, ManagedStore,
    ManagedStoreConfig, ManagedStoreOpenMode, PrincipalAccessPatchRequest, PrincipalRole,
    PrincipalWriteRequest,
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

/// Managed identity, policy and store with management, HTTP MCP, and imports
/// limited to the approved `ticketing` command.
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
network = "none"

[command_imports.ticketing.env]
PATH = {path}
LANG = "C.UTF-8"

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
        mcp_public_url = toml_string(mcp_public_url),
        spool = toml_string(directory.join("upload-spool").display()),
    )
}

/// Seeds the principals and returns the admin and agent tokens, before the
/// broker opens and locks the store.
fn seed(directory: &FixtureDir, hash: &Path) -> (String, String) {
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
            .token
    };
    let admin = issue("admin", BrokerTokenClass::Admin, json!({}));
    let agent = issue(
        "avery",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedExecutionContexts": ["default"]}),
    );
    (admin, agent)
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
    let (admin_token, agent_token) = seed(&directory, &hash);
    let files = directory.path();
    let admin = client_config(files, "admin", &base, &admin_token);
    let agent = client_config(files, "agent", &base, &agent_token);
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
    let (version, revision) = versions(&discovered);
    let selections = tools
        .iter()
        .map(|tool| {
            let action = tool["definition"]["action"].as_str().unwrap();
            json!({"source": tool["definition"]["source"], "action": action,
                "readOnly": !matches!(action, "issue.create" | "issue.close")})
        })
        .collect::<Vec<_>>();
    let accepted = run(
        &admin,
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
                    "manifestHash": preview["manifestHash"], "selections": selections})
                .to_string(),
            ),
        ],
    );
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

    // Resources of the imported type and grants in both credential modes.
    let attributes = write_file(
        files,
        "attributes.json",
        json!({"region": "eu-1", "webhookSecret": WEBHOOK_SECRET}).to_string(),
    );
    for (id, value, name) in [("ops", "OPS", Some("Operations")), ("web", "WEB", None)] {
        let mut args = vec![
            "admin",
            "policy",
            "resources",
            "create",
            "--id",
            id,
            "--resource-type",
            "ticketing_project",
            "--selector-kind",
            "exact",
            "--selector-value",
            value,
            "--execution-context",
            "default",
        ];
        if let Some(name) = name {
            args.extend(["--display-name", name, "--attributes-file", &attributes]);
        }
        run(&admin, &args);
    }
    let grant = |id: &str, actions: &[&str], mode: &str, resources: &[&str]| {
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
        run(&admin, &args);
    };
    grant(
        "ticketing-service",
        &["issue.view", "issue.create"],
        "service",
        &["ops"],
    );
    grant(
        "ticketing-personal",
        &["issue.search", "issue.close"],
        "per_user",
        &["ops", "web"],
    );
    grant("ticketing-whoami", &["whoami"], "per_user", &[]);

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
            "default",
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
        &[
            "admin",
            "credentials",
            "verify",
            "avery",
            "ticketing",
            "default",
        ],
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

    // Command-checked: the caller's grants with the personal credential.
    let search = invoke(&agent, "issue.search", json!({"query": ""}));
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
    assert_eq!(result["access"], json!({"accounts": {"user": "avery"}}));
    let closed = invoke(&agent, "issue.close", json!({"key": "WEB-12"}));
    assert_eq!(
        closed["result"]["upstreamCommand"]["access"],
        json!({"credential": "user", "account": "avery"})
    );
    assert_eq!(closed["result"]["mutationStatus"], "applied_unverified");
    assert_eq!(closed["result"]["safeLocators"], json!({"issue": "WEB-12"}));
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
    let whoami = invoke(&agent, "whoami", json!({}));
    let caller = &whoami["result"]["upstreamCommand"]["caller"];
    assert_eq!(caller["principal"], "avery");
    assert_eq!(caller["displayName"], "Avery Example");
    assert_eq!(caller["token"]["label"], "command smoke");
    assert_eq!(whoami["result"]["upstreamCommand"]["context"], "default");
    for response in [&view, &created, &search, &closed, &whoami, &refused] {
        assert_no_secret(&response.to_string(), "an invocation response");
    }

    assert_eq!(
        mcp_tool_names(&base, &agent_token).await,
        [
            "ticketing_issue_close",
            "ticketing_issue_create",
            "ticketing_issue_search",
            "ticketing_issue_view",
            "ticketing_whoami"
        ]
    );
    stop(broker).await;
}
