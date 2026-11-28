//! `agent-access admin usernames`, `admin access-keys`,
//! `admin access-key-types` and the access key types flags against a real
//! Broker: existing accounts named after startup, confirmation, a name set
//! by hand and taken away, the two modes, a rename by an email change, who
//! may hold each access key type, and an access key issued for a service
//! account and for a person, from issue to revocation, resolved as a
//! trusted caller would resolve it.

use agent_access_broker_host::test_support::{FixtureDir, IsolatedBroker};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    ConfiguredExecutionContexts, ManagedStore, ManagedStoreConfig, ManagedStoreOpenMode,
    PrincipalRole, PrincipalWriteRequest,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::path::Path;
use std::process::{Command, Output};

const CALLER_CREDENTIAL: &str = "resolver-caller-credential-0123456789";

fn toml_string(value: impl std::fmt::Display) -> String {
    serde_json::to_string(&value.to_string()).unwrap()
}

/// A managed Broker with two access key types, one of them for administrators
/// only, username settings and a trusted caller that may resolve tokens.
fn document(directory: &FixtureDir, key: &Path, caller: &Path) -> String {
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

[identity.trusted_callers.proxy]
credential_ref = {caller}
context_mode = "fixed"
execution_context = "default"
allow_access_key_resolution = true

[managed_store]
type = "sqlite"
path = {store}
auto_migrate = true

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

[audit]
type = "jsonl"
path = {audit}

[limits]
upload_spool_dir = {spool}

[access_key_types.inference]
display_name = "Model inference"
description = "Point your tool at https://gateway.example.com/v1."
lifetime_options = ["1h", "30d", "never"]
default_lifetime = "30d"
self_service = true

[access_key_types.batch]
display_name = "Batch jobs"
lifetime_options = ["1h", "7d", "never"]
default_lifetime = "7d"

[usernames]
email_domains = ["example.com"]
reserved_names = ["root"]
existing_usernames = ["carol"]
"#,
        caller = toml_string(format_args!("file:{}", caller.display())),
        store = toml_string(directory.join("store.sqlite").display()),
        hash_key = toml_string(format_args!("file:{}", key.display())),
        key = toml_string(key.display()),
        audit = toml_string(directory.join("audit.jsonl").display()),
        spool = toml_string(directory.join("upload-spool").display()),
    )
}

/// An administrator with a token, and three people who hold no username:
/// the store they are written to here has no username settings, as a store
/// that predates them has none.
fn seed(directory: &FixtureDir, key: &Path) -> String {
    let contexts = ConfiguredExecutionContexts::from_config(None).unwrap();
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: directory.join("store.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        },
        &contexts,
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    for (id, role, email) in [
        ("admin", PrincipalRole::Admin, None),
        ("usr-ann", PrincipalRole::User, Some("Ann@example.com")),
        ("usr-carol", PrincipalRole::User, Some("carol@example.com")),
        ("usr-dora", PrincipalRole::User, None),
    ] {
        store
            .create_principal(
                PrincipalWriteRequest {
                    agent_token_issuance: Default::default(),
                    role,
                    self_service_enabled: None,
                    principal_id: id.into(),
                    kind: "user".into(),
                    display_name: None,
                    email: email.map(str::to_string),
                    external_subject: None,
                    created_by: "test".into(),
                },
                &contexts,
            )
            .unwrap();
    }
    let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
        hash_key_ref: format!("file:{}", key.display()),
        ..Default::default()
    })
    .unwrap();
    store
        .issue_broker_token(
            &hasher,
            BrokerTokenIssueRequest {
                principal_id: "admin".into(),
                name: "administrator".into(),
                token_class: BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "test".into(),
            },
        )
        .unwrap()
        .token
}

struct Cli {
    url: String,
    token_path: std::path::PathBuf,
}

impl Cli {
    fn output(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("AGENT_ACCESS_")) {
            command.env_remove(key);
        }
        command
            .env("AGENT_ACCESS_CONFIG", "/dev/null")
            .args(["--url", &self.url, "--token-file"])
            .arg(&self.token_path)
            .args([
                "--identity-header",
                "Authorization",
                "--identity-scheme",
                "Bearer",
                "admin",
            ])
            .args(args)
            .output()
            .unwrap()
    }

    fn run(&self, args: &[&str], expected_success: bool) -> Value {
        let output = self.output(args);
        let response: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{args:?}: invalid JSON {error}; stderr={}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        assert_eq!(
            output.status.success(),
            expected_success,
            "{args:?}: {response}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        response
    }

    /// The `result` of a command that succeeds.
    fn ok(&self, args: &[&str]) -> Value {
        self.run(args, true)["result"].clone()
    }

    /// The reason code and refusal of a command the Broker refuses.
    fn refused(&self, args: &[&str]) -> (String, String) {
        let response = self.run(args, false);
        (
            response["reasonCode"].as_str().unwrap_or_default().into(),
            response["details"]["refusal"]
                .as_str()
                .unwrap_or_default()
                .into(),
        )
    }

    /// A command the CLI itself rejects: nothing is printed or sent.
    fn usage_error(&self, args: &[&str]) {
        let output = self.output(args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}

fn ids(accounts: &Value) -> Vec<&str> {
    accounts
        .as_array()
        .unwrap()
        .iter()
        .map(|account| account["principalId"].as_str().unwrap())
        .collect()
}

/// What a resolving service is answered for `token`.
async fn resolve(url: &str, token: &str) -> Value {
    let response = reqwest::Client::new()
        .post(format!("{url}/v1/access-keys/resolve"))
        .header(
            "X-Agent-Access-Caller-Authorization",
            format!("Bearer {CALLER_CREDENTIAL}"),
        )
        .json(&json!({"key": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response.json().await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn administrator_commands_name_existing_accounts_and_issue_tokens_for_accounts() {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let directory = application.directory().clone();
    let key = directory
        .secret_file("key", URL_SAFE_NO_PAD.encode([41_u8; 32]))
        .unwrap();
    let caller = directory.secret_file("caller", CALLER_CREDENTIAL).unwrap();
    let token = seed(&directory, &key);
    let cli = Cli {
        token_path: directory.secret_file("admin.token", token).unwrap(),
        url: String::new(),
    };
    let broker = application
        .config_document(document(&directory, &key, &caller))
        .start()
        .await
        .unwrap();
    let cli = Cli {
        url: broker.public_url(),
        ..cli
    };

    // The people who existed before the feature was configured are named
    // after startup, without any command: wait for that fill.
    let listed = {
        let mut waited = 0;
        loop {
            let listed = cli.ok(&["usernames", "list"]);
            let named = listed["accountUsernames"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|account| !account["name"].is_null())
                .count();
            if named == 2 {
                break listed;
            }
            waited += 1;
            assert!(
                waited < 100,
                "the startup fill names two accounts: {listed}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    };
    assert_eq!(
        ids(&listed["accountUsernames"]),
        ["admin", "usr-ann", "usr-carol", "usr-dora"]
    );
    let account = |listed: &Value, id: &str| {
        listed["accountUsernames"]
            .as_array()
            .unwrap()
            .iter()
            .find(|account| account["principalId"] == id)
            .unwrap()
            .clone()
    };
    let ann = account(&listed, "usr-ann");
    assert_eq!(ann["mode"], "from_email");
    assert_eq!(ann["state"], "usable");
    assert_eq!(ann["name"]["accountUsername"], "ann");
    assert_eq!(ann["name"]["origin"], "derived");
    assert_eq!(ann["name"]["assignedBy"], "system:startup");
    // A name on the operator's list is allocated and awaits confirmation.
    let carol = account(&listed, "usr-carol");
    assert_eq!(carol["name"]["accountUsername"], "carol");
    assert_eq!(carol["state"], "awaiting_confirmation");
    // No email: no name, and the reason.
    let dora = account(&listed, "usr-dora");
    assert!(dora["name"].is_null());
    assert_eq!(
        (&dora["state"], &dora["reason"]),
        (&json!("none"), &json!("no_email"))
    );

    // A listed name is confirmed for one account, by naming the name; a
    // wrong name confirms nothing.
    assert_eq!(
        cli.refused(&["usernames", "confirm", "usr-carol", "caroline"]),
        (
            "broker_account_username_conflict".into(),
            "name_changed".into()
        )
    );
    assert_eq!(
        cli.refused(&["usernames", "confirm", "usr-ann", "ann"]),
        (
            "broker_account_username_denied".into(),
            "confirmation_not_required".into()
        )
    );
    assert_eq!(
        cli.ok(&["usernames", "inspect", "usr-carol"])["state"],
        "awaiting_confirmation"
    );
    let confirmed = cli.ok(&["usernames", "confirm", "usr-carol", "carol"]);
    assert_eq!(confirmed["state"], "usable");
    assert_eq!(confirmed["name"]["confirmedBy"], "admin");

    // A name set by hand: the person stops following their email.
    let set = cli.ok(&["usernames", "set", "usr-dora", "dora"]);
    assert_eq!(set["mode"], "manual");
    assert_eq!(set["name"]["accountUsername"], "dora");
    assert_eq!(set["name"]["origin"], "administrator");
    assert_eq!(set["accountUsernameChange"]["endedKeys"], 0);
    assert_eq!(set["accountUsernameChange"]["renamed"], true);
    assert_eq!(
        cli.refused(&["usernames", "set", "usr-dora", "ann"]),
        (
            "broker_account_username_conflict".into(),
            "name_taken".into()
        )
    );
    assert_eq!(
        cli.refused(&["usernames", "set", "usr-dora", "root"]),
        (
            "broker_account_username_denied".into(),
            "name_reserved".into()
        )
    );
    // No name, in manual mode.
    let cleared = cli.ok(&["usernames", "clear", "usr-dora"]);
    assert!(cleared["name"].is_null());
    assert_eq!(
        (&cleared["mode"], &cleared["state"], &cleared["reason"]),
        (&json!("manual"), &json!("none"), &json!("not_set"))
    );

    // The two modes: manual keeps the name held; from_email derives at
    // once, here nothing because the account has no email.
    let manual = cli.ok(&["usernames", "mode", "usr-ann", "manual"]);
    assert_eq!(manual["mode"], "manual");
    assert_eq!(manual["name"]["incarnation"], ann["name"]["incarnation"]);
    let followed = cli.ok(&["usernames", "mode", "usr-ann", "from_email"]);
    assert_eq!(followed["mode"], "from_email");
    assert_eq!(followed["name"]["incarnation"], ann["name"]["incarnation"]);
    let followed = cli.ok(&["usernames", "mode", "usr-dora", "from_email"]);
    assert_eq!(
        (&followed["state"], &followed["reason"]),
        (&json!("none"), &json!("no_email"))
    );

    // Changing the email of a person who follows it renames them in the
    // same change; the account's detail shows the name.
    let patched = cli.ok(&[
        "principals",
        "update",
        "usr-dora",
        "--email",
        "Dora@example.com",
    ]);
    assert!(patched["accountUsernameChange"]["before"].is_null());
    assert_eq!(
        patched["accountUsernameChange"]["after"]["accountUsername"],
        "dora"
    );
    let renamed = cli.ok(&[
        "principals",
        "update",
        "usr-dora",
        "--email",
        "dorothy@example.com",
    ]);
    assert_eq!(
        renamed["accountUsernameChange"]["before"]["accountUsername"],
        "dora"
    );
    assert_eq!(
        renamed["accountUsernameChange"]["after"]["accountUsername"],
        "dorothy"
    );
    assert_eq!(renamed["accountUsernameChange"]["endedKeys"], 0);
    let detail = cli.ok(&["principals", "inspect", "usr-dora"]);
    assert_eq!(detail["accountUsername"]["mode"], "from_email");
    assert_eq!(detail["accountUsername"]["state"], "usable");
    assert_eq!(
        detail["accountUsername"]["name"]["accountUsername"],
        "dorothy"
    );

    // The configured types, and a token for a service account.
    let types = cli.ok(&["access-key-types", "list"]);
    assert_eq!(
        types["accessKeyTypes"],
        json!([
            {"id": "batch", "displayName": "Batch jobs", "description": null,
                "lifetimeOptions": ["1h", "7d", "never"], "defaultLifetime": "7d", "selfService": false},
            {"id": "inference", "displayName": "Model inference", "description": "Point your tool at https://gateway.example.com/v1.",
                "lifetimeOptions": ["1h", "30d", "never"], "defaultLifetime": "30d", "selfService": true},
        ])
    );
    cli.ok(&["principals", "create", "robot", "--kind", "service_account"]);

    // A configured type is nobody's until an administrator allows it: the
    // service account's own setting allows one type and a group the other.
    let issue_batch = [
        "access-keys",
        "issue",
        "robot",
        "--name",
        "nightly",
        "--access-key-type",
        "batch",
        "--ttl",
        "1h",
    ];
    assert_eq!(
        cli.refused(&issue_batch),
        (
            "broker_access_key_denied".into(),
            "access_key_type_not_eligible".into()
        )
    );
    let access = cli.ok(&[
        "principals",
        "access",
        "set",
        "robot",
        "--access-key-types",
        "--access-key-type-allow",
        "batch",
    ]);
    assert_eq!(
        access["accessKeyTypes"],
        json!({"allow": ["batch"], "deny": []})
    );
    let group = cli.ok(&[
        "groups",
        "create",
        "automation",
        "--access-key-types",
        "--access-key-type-allow",
        "inference",
    ]);
    assert_eq!(group["accessKeyTypes"], json!({"allow": ["inference"]}));
    cli.ok(&["principals", "groups", "add", "robot", "automation"]);
    assert_eq!(
        cli.ok(&["principals", "inspect", "robot"])["accessKeyTypePolicy"],
        json!({"accessKeyTypes": [
            {"accessKeyType": "batch", "allowed": true, "source": "account", "groupIds": []},
            {"accessKeyType": "inference", "allowed": true, "source": "groups",
                "groupIds": ["automation"]},
        ]})
    );
    assert_eq!(
        cli.refused(&[
            "principals",
            "access",
            "set",
            "robot",
            "--access-key-types",
            "--access-key-type-allow",
            "telemetry",
        ])
        .0,
        "input_invalid"
    );

    assert_eq!(
        cli.refused(&[
            "access-keys",
            "issue",
            "robot",
            "--name",
            "nightly",
            "--access-key-type",
            "batch",
            "--ttl",
            "8d",
        ]),
        (
            "broker_access_key_denied".into(),
            "lifetime_not_offered".into()
        )
    );
    assert_eq!(
        cli.refused(&[
            "access-keys",
            "issue",
            "usr-ann",
            "--name",
            "laptop",
            "--access-key-type",
            "inference",
            "--ttl",
            "1h",
        ]),
        (
            "broker_access_key_denied".into(),
            "access_key_type_not_eligible".into()
        )
    );
    let issued = cli.ok(&[
        "access-keys",
        "issue",
        "robot",
        "--name",
        "nightly",
        "--access-key-type",
        "batch",
        "--access-key-type",
        "inference",
        "--ttl",
        "1h",
    ]);
    let token = issued["key"].as_str().unwrap();
    assert!(agent_access_core::is_access_key(token), "{issued}");
    let key_id = issued["record"]["keyId"].as_str().unwrap();
    assert_eq!(issued["record"]["origin"], "administrator");
    assert_eq!(
        issued["record"]["accessKeyTypes"],
        json!(["batch", "inference"])
    );
    let resolved = resolve(&cli.url, token).await;
    assert_eq!(resolved["active"], true);
    assert_eq!(
        resolved["subject"],
        json!({"kind": "service_account", "id": "robot"})
    );
    assert_eq!(resolved["keyId"], key_id);

    let listed = cli.ok(&["access-keys", "list", "--principal", "robot"]);
    assert_eq!(listed["keys"].as_array().unwrap().len(), 1);
    assert_eq!(listed["keys"][0]["keyId"], key_id);
    assert_eq!(listed["keys"][0]["status"], "active");
    assert!(listed["keys"][0].get("key").is_none());
    assert_eq!(cli.ok(&["access-keys", "list"])["keys"], listed["keys"]);

    // Withdrawn access stops a type of the token that exists, and the
    // listing says what is left; restored access brings it back.
    let usable = |listed: Value| {
        listed["keys"][0]["usableAccessKeyTypes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|access_key_type| access_key_type["name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    let denied = cli.ok(&[
        "principals",
        "access",
        "set",
        "robot",
        "--access-key-types",
        "--access-key-type-allow",
        "batch",
        "--access-key-type-deny",
        "inference",
    ]);
    assert_eq!(
        denied["accessKeyTypes"],
        json!({"allow": ["batch"], "deny": ["inference"]})
    );
    assert_eq!(usable(cli.ok(&["access-keys", "list"])), ["batch"]);
    let narrowed = resolve(&cli.url, token).await;
    assert_eq!(narrowed["types"].as_array().unwrap().len(), 1);
    assert_eq!(narrowed["types"][0]["name"], "batch");
    // The group allows nothing and the account says nothing: no type left.
    let emptied = cli.ok(&["groups", "update", "automation", "--access-key-types"]);
    assert_eq!(emptied["accessKeyTypes"], json!({"allow": []}));
    let cleared = cli.ok(&["principals", "access", "set", "robot", "--access-key-types"]);
    assert_eq!(cleared["accessKeyTypes"], json!({"allow": [], "deny": []}));
    assert_eq!(
        cli.ok(&["access-keys", "list"])["keys"][0]["status"],
        "no_access_key_type"
    );
    assert_eq!(
        resolve(&cli.url, token).await,
        json!({
            "active": false, "keyId": key_id,
            "owner": {"kind": "service_account", "id": "robot"}, "reason": "no_access_key_type"
        })
    );
    cli.ok(&[
        "principals",
        "access",
        "set",
        "robot",
        "--access-key-types",
        "--access-key-type-allow",
        "batch",
        "--access-key-type-allow",
        "inference",
    ]);
    assert_eq!(
        usable(cli.ok(&["access-keys", "list"])),
        ["batch", "inference"]
    );
    assert_eq!(resolve(&cli.url, token).await["active"], true);

    let revoked = cli.ok(&["access-keys", "revoke", key_id]);
    assert_eq!(revoked["newlyRevoked"], true);
    assert_eq!(
        resolve(&cli.url, token).await,
        json!({
            "active": false, "keyId": key_id,
            "owner": {"kind": "service_account", "id": "robot"}, "reason": "revoked"
        })
    );
    assert_eq!(cli.ok(&["access-keys", "list"])["keys"], json!([]));
    let all = cli.ok(&[
        "access-keys",
        "list",
        "--include-revoked",
        "--include-expired",
    ]);
    assert_eq!(all["keys"][0]["status"], "revoked");
    assert_eq!(
        cli.refused(&[
            "access-keys",
            "revoke",
            "ak_00000000000000000000000000000000"
        ])
        .0,
        "broker_access_key_not_found"
    );

    // A token for a person, of a type people cannot create themselves: it
    // needs the person's access to the type and a usable name, not the
    // person.
    let access = cli.ok(&[
        "principals",
        "access",
        "set",
        "usr-ann",
        "--access-key-types",
        "--access-key-type-allow",
        "batch",
    ]);
    assert_eq!(
        access["accessKeyTypes"],
        json!({"allow": ["batch"], "deny": []})
    );
    let for_ann = [
        "access-keys",
        "issue",
        "usr-ann",
        "--name",
        "handed out",
        "--access-key-type",
        "batch",
        "--ttl",
        "1h",
    ];
    let issued = cli.ok(&for_ann);
    let token = issued["key"].as_str().unwrap();
    let key_id = issued["record"]["keyId"].as_str().unwrap();
    assert_eq!(issued["record"]["principalId"], "usr-ann");
    assert_eq!(issued["record"]["origin"], "administrator");
    assert_eq!(issued["record"]["createdBy"], "admin");
    let resolved = resolve(&cli.url, token).await;
    assert_eq!(resolved["active"], true);
    // A person is known to the caller by their name.
    assert_eq!(resolved["subject"], json!({"kind": "user", "id": "ann"}));
    assert_eq!(resolved["origin"], "administrator");
    let listed = cli.ok(&["access-keys", "list", "--principal", "usr-ann"]);
    assert_eq!(listed["keys"].as_array().unwrap().len(), 1);
    assert_eq!(listed["keys"][0]["keyId"], key_id);
    // A person without a usable name is issued nothing.
    cli.ok(&["usernames", "clear", "usr-ann"]);
    assert_eq!(
        resolve(&cli.url, token).await,
        json!({
            "active": false, "keyId": key_id,
            "owner": null, "reason": "no_account_username"
        })
    );
    assert_eq!(
        cli.refused(&for_ann),
        (
            "broker_access_key_denied".into(),
            "no_account_username".into()
        )
    );
    assert_eq!(
        cli.ok(&["access-keys", "revoke", key_id])["newlyRevoked"],
        true
    );

    // What the CLI refuses before sending anything.
    for args in [
        vec!["usernames", "confirm"],
        vec!["usernames", "confirm", "usr-carol"],
        vec!["usernames", "set", "usr-dora"],
        vec!["usernames", "clear"],
        vec!["usernames", "mode", "usr-dora"],
        vec!["usernames", "mode", "usr-dora", "automatic"],
        vec!["usernames", "fill"],
        vec!["usernames", "release", "usr-dora", "dora"],
        vec![
            "access-keys",
            "issue",
            "robot",
            "--name",
            "nightly",
            "--ttl",
            "1h",
        ],
        vec![
            "access-keys",
            "issue",
            "robot",
            "--name",
            "nightly",
            "--access-key-type",
            "batch",
        ],
        vec![
            "principals",
            "access",
            "set",
            "robot",
            "--access-key-type-allow",
            "batch",
        ],
        vec![
            "groups",
            "update",
            "automation",
            "--access-key-types",
            "--access-key-type-deny",
            "batch",
        ],
    ] {
        cli.usage_error(&args);
    }
    assert_eq!(
        cli.refused(&[
            "access-keys",
            "issue",
            "robot",
            "--name",
            "bad-lifetime",
            "--access-key-type",
            "batch",
            "--ttl",
            "forever"
        ])
        .0,
        "input_invalid"
    );
    // `--ttl` sends the chosen string; never remains an explicit null in
    // issuance, listing and resolution. Equivalent finite units also work.
    for ttl in ["never", "60m"] {
        let issued = cli.ok(&[
            "access-keys",
            "issue",
            "robot",
            "--name",
            "lifetime-choice",
            "--access-key-type",
            "batch",
            "--ttl",
            ttl,
        ]);
        assert_eq!(issued["record"]["expiresAt"].is_null(), ttl == "never");
        let answer = resolve(&cli.url, issued["key"].as_str().unwrap()).await;
        assert_eq!(answer["active"], true);
        assert!(answer.as_object().unwrap().contains_key("expiresAt"));
        assert_eq!(answer["expiresAt"], issued["record"]["expiresAt"]);
        assert_eq!(
            answer["types"][0]["validUntil"],
            issued["record"]["expiresAt"]
        );
        let listing = cli.ok(&["access-keys", "list", "--principal", "robot"]);
        assert!(
            listing["keys"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["keyId"] == issued["record"]["keyId"]
                    && item["expiresAt"] == issued["record"]["expiresAt"])
        );
        cli.ok(&[
            "access-keys",
            "revoke",
            issued["record"]["keyId"].as_str().unwrap(),
        ]);
    }
    broker.shutdown();
    broker.join().await.unwrap();
}
