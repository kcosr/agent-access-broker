use super::*;
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig, ManagedStore,
    ManagedStoreConfig, ManagedStoreOpenMode, PrincipalAgentTokenIssuance, PrincipalRole,
    PrincipalWriteRequest,
};
use serde_json::{Value, json};
use std::path::Path;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_issuance_policy_and_inherited_read_only_tokens_drive_a_real_broker() {
    let application = fake_application();
    let files = application.directory().clone();
    let document = fake_document(&files, FakeAccess::Managed);
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: files.join("resource-policy.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            principal_id: "admin".into(),
            kind: "user".into(),
            role: PrincipalRole::Admin,
            self_service_enabled: None,
            agent_token_issuance: PrincipalAgentTokenIssuance::Inherit,
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".into(),
        })
        .unwrap();
    let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
        hash_key_ref: format!("file:{}", files.join("hash-key").display()),
        ..Default::default()
    })
    .unwrap();
    let admin = store
        .issue_broker_token(
            &hasher,
            BrokerTokenIssueRequest {
                principal_id: "admin".into(),
                name: "bootstrap".into(),
                token_class: BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "test".into(),
            },
        )
        .unwrap();
    let admin_path = files.secret_file("admin.token", admin.token).unwrap();
    drop(store);
    let broker = application.config_document(document).start().await.unwrap();
    let url = broker.public_url();
    let run = |token: &Path, args: &[&str], success: bool| -> Value {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("AGENT_ACCESS_")) {
            command.env_remove(key);
        }
        let output = command
            .env("AGENT_ACCESS_CONFIG", "/dev/null")
            .args(["--url", &url, "--token-file"])
            .arg(token)
            .args([
                "--identity-header",
                "Authorization",
                "--identity-scheme",
                "Bearer",
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
            success,
            "{args:?}: reason={} error={} stderr={}",
            response["reasonCode"],
            response["error"],
            String::from_utf8_lossy(&output.stderr)
        );
        response
    };
    let admin = |args: &[&str]| run(&admin_path, args, true)["result"].clone();
    let created = admin(&[
        "admin",
        "principals",
        "create",
        "alice",
        "--agent-token-issuance",
        "disabled",
    ]);
    assert_eq!(created["agentTokenIssuance"], "disabled");
    let group = admin(&[
        "admin",
        "groups",
        "create",
        "readers",
        "--agent-token-issuance",
        "read_only",
    ]);
    assert_eq!(group["agentTokenIssuance"], "read_only");
    admin(&["admin", "groups", "members", "add", "readers", "alice"]);
    for project in ["TEST", "LATER"] {
        admin(&[
            "admin",
            "policy",
            "resources",
            "create",
            "--id",
            project,
            "--resource-type",
            "fake_project",
            "--selector-kind",
            "exact",
            "--selector-value",
            project,
            "--execution-context",
            "default",
        ]);
    }
    let grant = |id: &str, project: &str| {
        admin(&[
            "admin",
            "policy",
            "grants",
            "create",
            "--grant-id",
            id,
            "--subject",
            "user:alice",
            "--service",
            "fake",
            "--action",
            "echo",
            "--credential-mode",
            "service",
            "--execution-context",
            "default",
            "--resource-id",
            project,
        ])
    };
    grant("initial-read", "TEST");
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let setup = admin(&[
        "admin",
        "tokens",
        "issue",
        "alice",
        "--name",
        "setup",
        "--token-class",
        "user_manage",
        "--expires-at",
        &expires_at,
    ]);
    let setup_path = files
        .secret_file("setup.token", setup["token"].as_str().unwrap())
        .unwrap();
    let issue = |read_only: &str, success: bool| {
        run(
            &setup_path,
            &[
                "tokens",
                "issue",
                "--name",
                "follow-grants",
                "--execution-context",
                "default",
                "--ttl",
                "8h",
                "--read-only",
                read_only,
            ],
            success,
        )
    };
    let denied = issue("true", false);
    assert_eq!(
        denied["reasonCode"], "token_issuance_denied",
        "error={}",
        denied["error"]
    );
    // The new field alone satisfies PATCH, and the explicit override beats its group.
    admin(&[
        "admin",
        "principals",
        "access",
        "set",
        "alice",
        "--agent-token-issuance",
        "inherit",
    ]);
    let detail = admin(&["admin", "principals", "inspect", "alice"]);
    assert_eq!(
        detail["agentTokenIssuancePolicy"],
        json!({"mode":"read_only", "source":"groups", "groupIds":["readers"]})
    );
    let denied = issue("false", false);
    assert_eq!(
        denied["reasonCode"], "token_issuance_denied",
        "error={}",
        denied["error"]
    );
    let issued = issue("true", true);
    assert_eq!(
        issued["result"]["record"]["scopes"],
        json!({"allowedExecutionContexts":["default"], "readOnly":true})
    );
    let reader_path = files
        .secret_file("reader.token", issued["result"]["token"].as_str().unwrap())
        .unwrap();
    let status = run(&reader_path, &["auth", "status"], true);
    assert_eq!(status["principal"], "alice");
    assert_eq!(status["brokerToken"], json!({"readOnly":true}));
    assert!(status.get("readOnlyAccess").is_none());
    let setup_status = run(&setup_path, &["auth", "status"], true);
    assert_eq!(setup_status["principal"], "alice");
    assert!(setup_status.get("brokerToken").is_none());
    let echo = |project: &str, success: bool| {
        let input = json!({"project":project,"message":"inherited read"}).to_string();
        run(
            &reader_path,
            &["invoke", "fake.echo", "--input-json", &input],
            success,
        )
    };
    echo("TEST", true);
    echo("LATER", false);
    grant("later-read", "LATER");
    echo("LATER", true);
    admin(&[
        "admin",
        "policy",
        "grants",
        "delete",
        "later-read",
        "--expected-version",
        "1",
    ]);
    echo("LATER", false);
    // Group-only PATCH updates policy; disabling future issuance preserves the issued token.
    let group = admin(&[
        "admin",
        "groups",
        "update",
        "readers",
        "--agent-token-issuance",
        "disabled",
    ]);
    assert_eq!(group["agentTokenIssuance"], "disabled");
    let denied = issue("true", false);
    assert_eq!(
        denied["reasonCode"], "token_issuance_denied",
        "error={}",
        denied["error"]
    );
    echo("TEST", true);
    // Administrative issuance has separate authority even for this disabled owner.
    let writable = admin(&[
        "admin",
        "tokens",
        "issue",
        "alice",
        "--name",
        "administrative",
        "--execution-context",
        "default",
        "--expires-at",
        &expires_at,
        "--read-only",
        "false",
    ]);
    assert_eq!(writable["record"]["scopes"]["readOnly"], false);
    let writable_path = files
        .secret_file("writable.token", writable["token"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        run(&writable_path, &["auth", "status"], true)["brokerToken"],
        json!({"readOnly":false})
    );
    // A policy-only user override permits false explicitly; repeating create cannot reset it.
    admin(&[
        "admin",
        "principals",
        "access",
        "set",
        "alice",
        "--agent-token-issuance",
        "write_capable",
    ]);
    let repeated = run(
        &admin_path,
        &[
            "admin",
            "principals",
            "create",
            "alice",
            "--agent-token-issuance",
            "disabled",
        ],
        false,
    );
    assert_eq!(
        repeated["reasonCode"], "version_conflict",
        "error={}",
        repeated["error"]
    );
    let detail = admin(&["admin", "principals", "inspect", "alice"]);
    assert_eq!(detail["agentTokenIssuance"], "write_capable");
    assert_eq!(
        issue("false", true)["result"]["record"]["scopes"]["readOnly"],
        false
    );
    stop(broker).await;
}
