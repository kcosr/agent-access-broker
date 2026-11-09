use agent_access_broker_host::test_support::{FixtureDir, IsolatedBroker};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    ConfiguredExecutionContexts, ManagedStore, ManagedStoreConfig, ManagedStoreOpenMode,
    OidcProviderStateReconcileRequest, PrincipalRole, PrincipalWriteRequest,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ENROLLMENT_ID: &str = "9a430808-cdb6-4cec-ab3b-36e2b5e5b951";
const TENANT_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";

fn command(url: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("AGENT_ACCESS_")) {
        command.env_remove(key);
    }
    command.env("AGENT_ACCESS_CONFIG", "/dev/null").args([
        "--url",
        url,
        "--no-token",
        "admin",
        "principals",
    ]);
    command
}

fn enrollment_command(url: &str) -> Command {
    let mut command = command(url);
    command.args(["login-methods", "oidc", "enrollment"]);
    command
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn microsoft_enrollment_commands_preserve_identity_and_revision_fences() {
    let server = MockServer::start().await;
    let route = "/v1/admin/principals/alice%2Fteam/login-methods/oidc/microsoft/enrollment";
    let cases = [
        (vec!["inspect", "alice/team"], "GET", None, Value::Null),
        (
            vec!["create", "alice/team", "--email", " Alice@example.test "],
            "POST",
            Some(json!({"email":" Alice@example.test "})),
            json!({"enrollmentId":ENROLLMENT_ID,"revision":1}),
        ),
        (
            vec![
                "update",
                "alice/team",
                "--enrollment-id",
                ENROLLMENT_ID,
                "--expected-revision",
                "7",
                "--email",
                "new@example.test",
            ],
            "PATCH",
            Some(
                json!({"enrollmentId":ENROLLMENT_ID,"expectedRevision":7,"email":"new@example.test"}),
            ),
            json!({"enrollmentId":ENROLLMENT_ID,"revision":8}),
        ),
        (
            vec![
                "cancel",
                "alice/team",
                "--enrollment-id",
                ENROLLMENT_ID,
                "--expected-revision",
                "8",
            ],
            "DELETE",
            Some(json!({"enrollmentId":ENROLLMENT_ID,"expectedRevision":8})),
            json!({"cancelled":true}),
        ),
    ];
    for (args, verb, body, result) in cases {
        let mut mock = Mock::given(method(verb)).and(path(route));
        if let Some(body) = body {
            mock = mock.and(body_json(body));
        }
        mock.respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok":true,"result":result,
        })))
        .expect(1)
        .mount(&server)
        .await;
        let output = enrollment_command(&server.uri())
            .args(&args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["result"], result);
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].body.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn principal_creation_keeps_profile_email_and_microsoft_enrollment_explicit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/admin/principals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok":true,"result":{}})))
        .expect(2)
        .mount(&server)
        .await;
    let output = command(&server.uri())
        .args([
            "create",
            "alice",
            "--email",
            "profile@example.test",
            "--microsoft-enrollment-email",
            "sign-in@example.test",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = command(&server.uri())
        .args(["create", "bob", "--email", "profile@example.test"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = server.received_requests().await.unwrap();
    let enrolled: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(enrolled["email"], "profile@example.test");
    assert_eq!(
        enrolled["microsoftEnrollment"],
        json!({"email":"sign-in@example.test"})
    );
    let ordinary: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(ordinary["email"], "profile@example.test");
    assert!(ordinary.get("microsoftEnrollment").is_none());
}

#[test]
fn microsoft_enrollment_mutations_require_valid_explicit_fences() {
    for action in ["update", "cancel"] {
        let mut base = vec![action, "alice"];
        if action == "update" {
            base.extend(["--email", "alice@example.test"]);
        }
        for extra in [
            vec![],
            vec!["--enrollment-id", ENROLLMENT_ID],
            vec!["--expected-revision", "1"],
            vec!["--enrollment-id", "invalid", "--expected-revision", "1"],
            vec!["--enrollment-id", ENROLLMENT_ID, "--expected-revision", "0"],
        ] {
            let output = enrollment_command("http://127.0.0.1:1")
                .args(&base)
                .args(&extra)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(2),
                "{base:?} {extra:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_enrollment_mutation_surfaces_conflict_without_retrying() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path(
            "/v1/admin/principals/alice/login-methods/oidc/microsoft/enrollment",
        ))
        .and(body_json(
            json!({"enrollmentId":ENROLLMENT_ID,"expectedRevision":3}),
        ))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "ok":false,"decision":"deny","reasonCode":"oidc_login_method_conflict",
            "requestId":"enrollment-conflict","brokerRequestId":"enrollment-conflict",
            "error":{"message":"Microsoft login method conflict"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let output = enrollment_command(&server.uri())
        .args([
            "cancel",
            "alice",
            "--enrollment-id",
            ENROLLMENT_ID,
            "--expected-revision",
            "3",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["reasonCode"], "oidc_login_method_conflict");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

fn toml_string(value: impl std::fmt::Display) -> String {
    serde_json::to_string(&value.to_string()).unwrap()
}

fn managed_document(directory: &FixtureDir, key: &Path) -> String {
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
"#,
        store = toml_string(directory.join("store.sqlite").display()),
        hash_key = toml_string(format_args!("file:{}", key.display())),
        key = toml_string(key.display()),
        audit = toml_string(directory.join("audit.jsonl").display()),
        spool = toml_string(directory.join("upload-spool").display()),
    )
}

fn seed_paused_provider_and_admin(directory: &FixtureDir, key: &Path) -> String {
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
    store
        .reconcile_oidc_provider_state(OidcProviderStateReconcileRequest {
            tenant_id: TENANT_ID.into(),
            client_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2".into(),
            enabled: false,
            config_fingerprint: "sha256:synthetic-paused-provider".into(),
            external_membership_ttl_seconds: 8 * 60 * 60,
            membership_renewal: false,
            invalidate_existing_evidence: false,
            actor: "test".into(),
        })
        .unwrap();
    store
        .create_principal(
            PrincipalWriteRequest {
                agent_token_issuance: Default::default(),
                role: PrincipalRole::Admin,
                self_service_enabled: None,
                principal_id: "admin".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            },
            &contexts,
        )
        .unwrap();
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
                name: "enrollment admin".into(),
                token_class: BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "test".into(),
            },
        )
        .unwrap()
        .token
}

/// The real binary and HTTP contract agree about optional enrollment, canonical
/// matching, revisions, cancellation and Object-ID linking, including preparation
/// while the reconciled provider is paused. No Microsoft requests are made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrollment_commands_drive_a_real_broker_with_a_paused_provider() {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let directory = application.directory().clone();
    let key = directory
        .secret_file("key", URL_SAFE_NO_PAD.encode([31_u8; 32]))
        .unwrap();
    let document = managed_document(&directory, &key);
    let token = seed_paused_provider_and_admin(&directory, &key);
    let token_path = directory.secret_file("admin.token", token).unwrap();
    let broker = application.config_document(document).start().await.unwrap();
    let url = broker.public_url();
    let run = |args: &[&str], expected_success: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("AGENT_ACCESS_")) {
            command.env_remove(key);
        }
        let output = command
            .env("AGENT_ACCESS_CONFIG", "/dev/null")
            .args(["--url", &url, "--token-file"])
            .arg(&token_path)
            .args([
                "--identity-header",
                "Authorization",
                "--identity-scheme",
                "Bearer",
                "admin",
                "principals",
            ])
            .args(args)
            .output()
            .unwrap();
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
    };
    let ok = |args: &[&str]| run(args, true)["result"].clone();
    let enrollment = |args: &[&str], success| {
        let mut command = vec!["login-methods", "oidc", "enrollment"];
        command.extend_from_slice(args);
        run(&command, success)
    };
    let conflict = |args: &[&str]| {
        assert_eq!(run(args, false)["reasonCode"], "oidc_login_method_conflict");
    };

    let created = ok(&[
        "create",
        "alice",
        "--email",
        "profile@example.test",
        "--microsoft-enrollment-email",
        " Alice@Example.Test ",
        "--role",
        "auditor",
        "--agent-token-issuance",
        "disabled",
    ]);
    assert_eq!(created["principalId"], "alice");
    assert_eq!(created["email"], "profile@example.test");
    assert_eq!(created["role"], "auditor");
    assert_eq!(created["microsoftEnrollment"]["tenantId"], TENANT_ID);
    assert_eq!(
        created["microsoftEnrollment"]["matchEmail"],
        "alice@example.test"
    );
    assert_eq!(created["microsoftEnrollment"]["revision"], 1);
    let id = created["microsoftEnrollment"]["enrollmentId"]
        .as_str()
        .unwrap();
    assert_eq!(
        enrollment(&["inspect", "alice"], true)["result"],
        created["microsoftEnrollment"]
    );

    ok(&["update", "alice", "--email", "new-profile@example.test"]);
    ok(&["disable", "alice"]);
    conflict(&[
        "create",
        "collision",
        "--microsoft-enrollment-email",
        "alice@example.test",
    ]);
    assert!(
        !ok(&["list"])
            .as_array()
            .unwrap()
            .iter()
            .any(|principal| principal["principalId"] == "collision")
    );
    ok(&["enable", "alice"]);
    let no_op = enrollment(
        &[
            "update",
            "alice",
            "--enrollment-id",
            id,
            "--expected-revision",
            "1",
            "--email",
            "ALICE@example.test",
        ],
        true,
    );
    assert_eq!(no_op["result"]["revision"], 1);
    let changed = enrollment(
        &[
            "update",
            "alice",
            "--enrollment-id",
            id,
            "--expected-revision",
            "1",
            "--email",
            "sign-in@example.test",
        ],
        true,
    );
    assert_eq!(changed["result"]["revision"], 2);
    assert_eq!(
        enrollment(
            &[
                "cancel",
                "alice",
                "--enrollment-id",
                id,
                "--expected-revision",
                "1",
            ],
            false
        )["reasonCode"],
        "oidc_login_method_conflict"
    );
    conflict(&[
        "login-methods",
        "oidc",
        "link",
        "alice",
        "--user-object-id",
        "cccccccc-cccc-4ccc-8ccc-ccccccccccc3",
    ]);
    assert_eq!(
        enrollment(
            &[
                "cancel",
                "alice",
                "--enrollment-id",
                id,
                "--expected-revision",
                "2",
            ],
            true
        )["result"],
        json!({"cancelled":true})
    );
    assert!(enrollment(&["inspect", "alice"], true)["result"].is_null());
    let retained = ok(&["inspect", "alice"]);
    assert_eq!(retained["email"], "new-profile@example.test");
    assert_eq!(retained["role"], "auditor");
    assert_eq!(retained["agentTokenIssuance"]["mode"], "disabled");
    assert!(retained["microsoftEnrollment"].is_null());

    let replacement = enrollment(&["create", "alice", "--email", "alice@example.test"], true);
    assert_ne!(replacement["result"]["enrollmentId"], id);
    assert_eq!(
        enrollment(
            &[
                "cancel",
                "alice",
                "--enrollment-id",
                id,
                "--expected-revision",
                "1",
            ],
            false
        )["reasonCode"],
        "oidc_login_method_conflict"
    );
    let ordinary = ok(&["create", "bob", "--email", "alice@example.test"]);
    assert!(ordinary["microsoftEnrollment"].is_null());
    assert!(enrollment(&["inspect", "bob"], true)["result"].is_null());

    broker.shutdown();
    broker.join().await.unwrap();
}
