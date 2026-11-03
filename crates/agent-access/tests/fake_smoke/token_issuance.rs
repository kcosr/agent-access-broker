use super::*;
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig, ManagedStore,
    ManagedStoreConfig, ManagedStoreOpenMode, PrincipalRole, PrincipalWriteRequest,
};
use serde_json::{Value, json};
use std::path::Path;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_issuance_policy_and_inherited_read_only_tokens_drive_a_real_broker() {
    let application = fake_application();
    let files = application.directory().clone();
    let document = fake_document(&files, FakeAccess::Managed).replace(
        "allowed_values = [\"default\", \"internal\"]",
        "allowed_values = [\"default\", \"internal\", \"external\"]",
    );
    let issuance_contexts = agent_access_core::ConfiguredExecutionContexts::from_config(Some(
        &agent_access_core::ExecutionContextConfig {
            allowed_values: vec!["default".into(), "internal".into(), "external".into()],
            default_context: Some("default".into()),
        },
    ))
    .unwrap();
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: files.join("resource-policy.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        },
        &issuance_contexts,
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(
            PrincipalWriteRequest {
                principal_id: "admin".into(),
                kind: "user".into(),
                role: PrincipalRole::Admin,
                self_service_enabled: None,
                agent_token_issuance: Default::default(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            },
            &issuance_contexts,
        )
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
    assert_eq!(
        admin(&["admin", "principals", "create", "default-account"])["agentTokenIssuance"],
        json!({"mode":"inherit", "allowedExecutionContexts":[]})
    );
    assert_eq!(
        admin(&["admin", "groups", "create", "default-group"])["agentTokenIssuance"],
        json!({"mode":"disabled", "allowedExecutionContexts":[]})
    );
    let created = admin(&[
        "admin",
        "principals",
        "create",
        "alice",
        "--agent-token-issuance",
        "disabled",
    ]);
    assert_eq!(
        created["agentTokenIssuance"],
        json!({"mode":"disabled", "allowedExecutionContexts":[]})
    );
    let group = admin(&[
        "admin",
        "groups",
        "create",
        "readers",
        "--agent-token-issuance",
        "read_only",
        "--agent-token-issuance-context",
        "default",
    ]);
    assert_eq!(
        group["agentTokenIssuance"],
        json!({"mode":"read_only", "allowedExecutionContexts":["default"]})
    );
    assert_eq!(
        admin(&[
            "admin",
            "groups",
            "update",
            "readers",
            "--description",
            "Read access"
        ])["agentTokenIssuance"],
        json!({"mode":"read_only", "allowedExecutionContexts":["default"]})
    );
    admin(&[
        "admin",
        "principals",
        "access",
        "set",
        "alice",
        "--self-service-enabled",
        "true",
    ]);
    assert_eq!(
        admin(&["admin", "principals", "inspect", "alice"])["agentTokenIssuance"],
        json!({"mode":"disabled", "allowedExecutionContexts":[]})
    );
    admin(&[
        "admin",
        "groups",
        "create",
        "writers",
        "--agent-token-issuance",
        "write_capable",
        "--agent-token-issuance-context",
        "internal",
    ]);
    admin(&["admin", "groups", "members", "add", "writers", "alice"]);
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
            "--execution-context",
            "internal",
            "--execution-context",
            "external",
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
            "--execution-context",
            "internal",
            "--execution-context",
            "external",
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
    let issue_contexts = |read_only: &str, contexts: &[&str], success: bool| {
        let mut args = vec![
            "tokens",
            "issue",
            "--name",
            "follow-grants",
            "--ttl",
            "8h",
            "--read-only",
            read_only,
        ];
        for context in contexts {
            args.extend(["--execution-context", context]);
        }
        run(&setup_path, &args, success)
    };
    let issue = |read_only: &str, success: bool| issue_contexts(read_only, &["default"], success);
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
        json!({"source":"groups", "contexts":[
            {"executionContext":"default", "mode":"read_only", "groupIds":["readers"]},
            {"executionContext":"internal", "mode":"write_capable", "groupIds":["writers"]},
        ]})
    );
    let denied = issue("false", false);
    assert_eq!(
        denied["reasonCode"], "token_issuance_denied",
        "error={}",
        denied["error"]
    );
    // A read-only context elsewhere cannot lower this internal-only request.
    assert_eq!(
        issue_contexts("false", &["internal"], true)["result"]["record"]["scopes"],
        json!({"allowedExecutionContexts":["internal"], "readOnly":false})
    );
    assert_eq!(
        issue_contexts("false", &["default", "internal"], false)["reasonCode"],
        "token_issuance_denied"
    );
    assert_eq!(
        issue_contexts("true", &["default", "internal"], true)["result"]["record"]["scopes"],
        json!({"allowedExecutionContexts":["default", "internal"], "readOnly":true})
    );
    for contexts in [vec!["external"], vec!["default", "external"]] {
        let denied = issue_contexts("true", &contexts, false);
        assert_eq!(denied["reasonCode"], "token_issuance_denied");
        assert_eq!(
            denied["error"]["message"],
            "Personal agent tokens are not allowed in every requested execution context"
        );
    }
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
    assert_eq!(
        group["agentTokenIssuance"],
        json!({"mode":"disabled", "allowedExecutionContexts":[]})
    );
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
        "--agent-token-issuance-context",
        "default",
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
    assert_eq!(
        detail["agentTokenIssuance"],
        json!({"mode":"write_capable", "allowedExecutionContexts":["default"]})
    );
    assert_eq!(
        issue_contexts("true", &["internal"], false)["reasonCode"],
        "token_issuance_denied"
    );
    assert_eq!(
        issue("false", true)["result"]["record"]["scopes"]["readOnly"],
        false
    );
    // JSON send follows the same complete-object and per-context issuance contracts.
    let send = |token: &Path,
                method: &str,
                route: &str,
                path_params: Value,
                body: Value,
                success: bool| {
        let request = json!({"version":agent_access_core::SEND_SCHEMA_VERSION,
            "kind":"http", "method":method, "route":route, "pathParams":path_params, "body":body})
        .to_string();
        run(token, &["send", "--request-json", &request], success)
    };
    send(
        &admin_path,
        "PATCH",
        "/v1/admin/principals/{principal}/access",
        json!({"principal":"alice"}),
        json!({"agentTokenIssuance":{"mode":"read_only", "allowedExecutionContexts":["internal"]}}),
        true,
    );
    let denied = send(
        &setup_path,
        "POST",
        "/v1/tokens",
        json!({}),
        json!({"name":"send-denied", "ttl":"8h", "allowedExecutionContexts":["external"], "readOnly":true}),
        false,
    );
    assert_eq!(
        denied["reasonCode"], "token_issuance_denied",
        "error={}",
        denied["error"]
    );
    assert_eq!(
        denied["error"]["message"],
        "Personal agent tokens are not allowed in every requested execution context"
    );
    assert_eq!(
        send(
            &setup_path,
            "POST",
            "/v1/tokens",
            json!({}),
            json!({"name":"send-read", "ttl":"8h", "allowedExecutionContexts":["internal"], "readOnly":true}),
            true
        )["result"]["record"]["scopes"],
        json!({"allowedExecutionContexts":["internal"], "readOnly":true})
    );
    let bypass = send(
        &admin_path,
        "POST",
        "/v1/admin/principals/{principal}/agent-tokens",
        json!({"principal":"alice"}),
        json!({"name":"send-admin", "ttl":"8h", "allowedExecutionContexts":["external"], "readOnly":false}),
        true,
    );
    assert_eq!(
        bypass["result"]["record"]["scopes"],
        json!({"allowedExecutionContexts":["external"], "readOnly":false})
    );
    echo("TEST", true);
    stop(broker).await;
}

#[test]
fn invalid_issuance_policy_flag_combinations_fail_before_contacting_the_broker() {
    for command in [
        vec!["admin", "principals", "create", "alice"],
        vec!["admin", "principals", "access", "set", "alice"],
        vec!["admin", "groups", "create", "readers"],
        vec!["admin", "groups", "update", "readers"],
    ] {
        let mut invalid = vec![
            (
                vec![
                    "--agent-token-issuance",
                    "disabled",
                    "--agent-token-issuance-context",
                    "internal",
                ],
                "inherit and disabled reject",
            ),
            (
                vec![
                    "--agent-token-issuance",
                    "read_only",
                    "--agent-token-issuance-context",
                    "internal",
                    "--agent-token-issuance-context",
                    "internal",
                ],
                "issuance contexts must be unique",
            ),
        ];
        if command[1] == "principals" {
            invalid.push((
                vec![
                    "--agent-token-issuance",
                    "inherit",
                    "--agent-token-issuance-context",
                    "internal",
                ],
                "inherit and disabled reject",
            ));
        }
        for (flags, expected_error) in invalid {
            let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
                .env("AGENT_ACCESS_CONFIG", "/dev/null")
                .args(["--url", "http://127.0.0.1:9", "--no-token"])
                .args(&command)
                .args(&flags)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(3), "{command:?} {flags:?}");
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(error.contains(expected_error), "{error}");
            assert!(output.stdout.is_empty());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_issuance_policy_command_sends_one_complete_request_without_read_merge() {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

    let commands = [
        (
            vec!["admin", "principals", "create", "alice"],
            "POST",
            "/v1/admin/principals",
            json!({"principalId":"alice", "kind":"user", "displayName":null,
                "email":null, "externalSubject":null, "role":"user", "selfServiceEnabled":true}),
        ),
        (
            vec![
                "admin",
                "principals",
                "access",
                "set",
                "alice",
                "--self-service-enabled",
                "true",
            ],
            "PATCH",
            "/v1/admin/principals/alice/access",
            json!({"selfServiceEnabled":true}),
        ),
        (
            vec!["admin", "groups", "create", "readers"],
            "POST",
            "/v1/admin/groups",
            json!({"groupId":"readers", "displayName":null, "description":null,
                "autoEnrollNewMicrosoftUsers":false}),
        ),
        (
            vec![
                "admin",
                "groups",
                "update",
                "readers",
                "--description",
                "example",
            ],
            "PATCH",
            "/v1/admin/groups/readers",
            json!({"description":"example"}),
        ),
    ];
    for (command, verb, route, base) in commands {
        for mode in [
            None,
            Some("inherit"),
            Some("disabled"),
            Some("read_only"),
            Some("write_capable"),
        ] {
            if mode == Some("inherit") && command[1] == "groups" {
                continue;
            }
            let server = MockServer::start().await;
            let mut args = Vec::new();
            args.extend(command.iter().copied());
            let mut expected = base.clone();
            if let Some(mode) = mode {
                args.extend(["--agent-token-issuance", mode]);
                let enabled = matches!(mode, "read_only" | "write_capable");
                if enabled {
                    args.extend([
                        "--agent-token-issuance-context",
                        "internal",
                        "--agent-token-issuance-context",
                        "external",
                    ]);
                }
                expected["agentTokenIssuance"] = json!({"mode":mode,
                    "allowedExecutionContexts":if enabled { vec!["external", "internal"] } else { vec![] }});
            }
            Mock::given(method(verb))
                .and(path(route))
                .and(body_json(expected))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "ok":true, "decision":"allow", "result":{},
                })))
                .expect(1)
                .mount(&server)
                .await;
            let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
                .env("AGENT_ACCESS_CONFIG", "/dev/null")
                .args(["--url", &server.uri(), "--no-token"])
                .args(&args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }
}
