use super::*;
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISSUED: &str = "new-bot-credential-secret-sentinel";
const ACTIONS: &[&str] = &[
    "project.member.view",
    "project.access_token.list",
    "project.access_token.view",
    "project.access_token.create",
    "project.access_token.rotate",
    "project.access_token.revoke",
    "service_account.list",
    "service_account.view",
    "service_account.create",
    "service_account.delete",
    "service_account.member.set",
    "service_account.token.list",
    "service_account.token.create",
    "service_account.token.rotate",
    "service_account.token.revoke",
];
fn expiry() -> String {
    (chrono::Utc::now().date_naive() + chrono::Duration::days(7)).to_string()
}
fn token(id: u64) -> Value {
    json!({"id":id,"user_id":70,"name":"reviewer","scopes":["api"],"access_level":30,"expires_at":expiry(),"active":true,"revoked":false,"token":ISSUED})
}
fn account() -> Value {
    json!({"id":70,"name":"reviewer","username":"review-bot","token":"must-not-export-account-extra-fields"})
}

struct Fixture {
    upstream: MockServer,
    base_url: String,
    broker: RunningBroker,
    /// A private directory for the CLI's token output files.
    dir: tempfile::TempDir,
}
impl Fixture {
    async fn new(enabled: bool, actions: &[&str]) -> Self {
        let upstream = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut document = gitlab_per_user_document();
        let provider = &mut document.provider;
        provider.provisioning.enabled = enabled;
        provider.api_base_url = format!("{}/api/v4", upstream.uri());
        provider.web_base_url = upstream.uri();
        provider.allowed_upstream_hosts = vec![format!("{}/api/v4/**", upstream.uri())];
        document.default_invocation_limit = Some((1000, "1m"));
        for grant in &mut document.grants {
            grant.actions = actions.iter().map(|s| s.to_string()).collect();
        }
        Mock::given(method("GET"))
            .and(path("/api/v4/projects/sip%2Fservice"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"id":42,"path_with_namespace":"sip/service","name":"service"}),
            ))
            .mount(&upstream)
            .await;
        // These regressions exercise deliberately exported tokens and private
        // local file delivery. Reference-mode workflows use managed fixtures.
        let broker = start_registered_broker(&document).await;
        let base_url = broker.public_url();
        Self {
            upstream,
            base_url,
            broker,
            dir,
        }
    }
    async fn stop(self) {
        stop(self.broker).await;
    }
    async fn mock(&self, method_name: &str, url: &str, body: Value, status: u16) {
        Mock::given(method(method_name))
            .and(path(url))
            .and(header("authorization", "Bearer gitlab-per-user-token"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&self.upstream)
            .await;
    }
    async fn invoke(&self, action: &str, inputs: Value) -> (reqwest::StatusCode, Value) {
        invoke_gitlab_outcome(
            &reqwest::Client::new(),
            &self.base_url,
            action,
            &uuid::Uuid::new_v4().to_string(),
            json!({"inputs":inputs}),
        )
        .await
    }
    async fn ok(&self, action: &str, inputs: Value) -> Value {
        let (status, value) = self.invoke(action, inputs).await;
        assert_eq!(status, reqwest::StatusCode::OK, "{action}: {value}");
        assert_eq!(value["decision"], "allow", "{value}");
        value
    }
    /// Requires the records of the GitLab `audited` actions, then checks
    /// that no credential or private account field reached the audit.
    fn assert_audit_safe(&self, audited: &[&str]) {
        let audit = self.broker.audit().unwrap();
        for action in audited {
            audit.require_action("gitlab", action);
        }
        let audit = audit.text();
        for secret in [
            ISSUED,
            "gitlab-per-user-token",
            "gitlab-lookup-token",
            "gitlab-service-token",
            "must-not-export-account-extra-fields",
        ] {
            assert!(!audit.contains(secret), "audit leaked credential");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_project_token_cli_http_send_lifecycle_and_private_delivery() {
    let fixture = Fixture::new(true, ACTIONS).await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/access_tokens"))
        .and(header("authorization", "Bearer gitlab-per-user-token"))
        .and(body_json(
            json!({"name":"reviewer","scopes":["api"],"access_level":30,"expires_at":expiry()}),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(token(10)))
        .expect(3)
        .mount(&fixture.upstream)
        .await;
    fixture
        .mock(
            "GET",
            "/api/v4/projects/42/access_tokens/10",
            token(10),
            200,
        )
        .await;
    fixture
        .mock(
            "POST",
            "/api/v4/projects/42/access_tokens/10/rotate",
            token(11),
            200,
        )
        .await;
    fixture
        .mock(
            "GET",
            "/api/v4/projects/42/access_tokens",
            json!([token(10)]),
            200,
        )
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/v4/projects/42/access_tokens/11"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&fixture.upstream)
        .await;
    let output_path = fixture.dir.path().join("reviewer.token");
    let output = gitlab_cli(&fixture.base_url)
        .args([
            "gitlab",
            "project",
            "access-token",
            "create",
            "sip/service",
            "--name",
            "reviewer",
            "--scopes",
            "api",
            "--access-level",
            "30",
            "--expires-at",
            &expiry(),
            "--token-output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("token file issuance", &output);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(ISSUED));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(ISSUED));
    assert_eq!(
        std::fs::read_to_string(&output_path).unwrap(),
        format!("{ISSUED}\n")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&output_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    // A pre-existing path is rejected before a second issuance.
    let refused = gitlab_cli(&fixture.base_url)
        .args([
            "gitlab",
            "project",
            "access-token",
            "create",
            "sip/service",
            "--name",
            "reviewer",
            "--scopes",
            "api",
            "--access-level",
            "30",
            "--expires-at",
            &expiry(),
            "--token-output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    #[cfg(unix)]
    {
        let link = fixture.dir.path().join("symlink.token");
        std::os::unix::fs::symlink(&output_path, &link).unwrap();
        let refused = gitlab_cli(&fixture.base_url)
            .args([
                "gitlab",
                "project",
                "access-token",
                "create",
                "sip/service",
                "--name",
                "reviewer",
                "--scopes",
                "api",
                "--access-level",
                "30",
                "--expires-at",
                &expiry(),
                "--token-output",
                link.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!refused.status.success());
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(
            std::fs::read_to_string(&output_path).unwrap(),
            format!("{ISSUED}\n")
        );
    }
    let response = reqwest::Client::new().post(format!("{}/v1/invoke/gitlab/project.access_token.create",fixture.base_url))
        .header("X-Agent-Access-Identity-Token","agent-token")
        .header("X-Agent-Access-Request-Id",uuid::Uuid::new_v4().to_string())
        .json(&json!({"inputs":{"project":"sip/service","name":"reviewer","scopes":["api"],"accessLevel":30,"expiresAt":expiry()}})).send().await.unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.json::<Value>().await.unwrap()["result"]["issuedToken"],
        ISSUED
    );
    let send_path = fixture.dir.path().join("request.json");
    std::fs::write(&send_path, json!({"version":"agent-access.send.v1","kind":"invoke","service":"gitlab","action":"project.access_token.create","inputs":{"project":"sip/service","name":"reviewer","scopes":["api"],"accessLevel":30,"expiresAt":expiry()}}).to_string()).unwrap();
    let send = gitlab_cli(&fixture.base_url)
        .args(["send", "--request-file", send_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_success("send token issuance", &send);
    assert_eq!(
        serde_json::from_slice::<Value>(&send.stdout).unwrap()["result"]["issuedToken"],
        ISSUED
    );
    for (action, inputs) in [
        (
            "project.access_token.list",
            json!({"project":"sip/service"}),
        ),
        (
            "project.access_token.view",
            json!({"project":"sip/service","tokenId":10}),
        ),
    ] {
        let value = fixture.ok(action, inputs).await;
        assert!(!value.to_string().contains(ISSUED));
    }
    let rotated = fixture
        .ok(
            "project.access_token.rotate",
            json!({"project":"sip/service","tokenId":10,"expiresAt":expiry()}),
        )
        .await;
    assert_eq!(rotated["result"]["accessToken"]["id"], 11);
    assert_eq!(rotated["result"]["issuedToken"], ISSUED);
    fixture
        .ok(
            "project.access_token.revoke",
            json!({"project":"sip/service","tokenId":11}),
        )
        .await;
    fixture.assert_audit_safe(&["project.access_token.create", "project.access_token.rotate"]);
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_service_account_create_membership_tokens_rotation_and_revocation() {
    let fixture = Fixture::new(true, ACTIONS).await;
    fixture
        .mock(
            "POST",
            "/api/v4/projects/42/service_accounts",
            account(),
            201,
        )
        .await;
    fixture
        .mock(
            "GET",
            "/api/v4/projects/42/service_accounts/70",
            account(),
            200,
        )
        .await;
    fixture
        .mock(
            "GET",
            "/api/v4/projects/42/service_accounts",
            json!([account()]),
            200,
        )
        .await;
    fixture
        .mock(
            "GET",
            "/api/v4/projects/42/members/70",
            json!({"id":70,"access_level":30}),
            200,
        )
        .await;
    fixture
        .mock(
            "PUT",
            "/api/v4/projects/42/members/70",
            json!({"id":70,"access_level":30}),
            200,
        )
        .await;
    fixture
        .mock(
            "POST",
            "/api/v4/projects/42/service_accounts/70/personal_access_tokens",
            token(10),
            201,
        )
        .await;
    fixture
        .mock(
            "GET",
            "/api/v4/projects/42/service_accounts/70/personal_access_tokens",
            json!([token(10)]),
            200,
        )
        .await;
    fixture
        .mock(
            "POST",
            "/api/v4/projects/42/service_accounts/70/personal_access_tokens/10/rotate",
            token(11),
            200,
        )
        .await;
    for path_value in [
        "/api/v4/projects/42/service_accounts/70/personal_access_tokens/11",
        "/api/v4/projects/42/service_accounts/70",
    ] {
        Mock::given(method("DELETE"))
            .and(path(path_value))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&fixture.upstream)
            .await;
    }
    let created = gitlab_cli(&fixture.base_url)
        .args([
            "gitlab",
            "service-account",
            "create",
            "sip/service",
            "--name",
            "reviewer",
            "--username",
            "review-bot",
        ])
        .output()
        .unwrap();
    assert_success("service account creation", &created);
    assert!(!String::from_utf8_lossy(&created.stdout).contains("must-not-export"));
    let member = gitlab_cli(&fixture.base_url)
        .args([
            "gitlab",
            "service-account",
            "member-set",
            "sip/service",
            "70",
            "--access-level",
            "30",
        ])
        .output()
        .unwrap();
    assert_success("service account role", &member);
    let output = fixture.dir.path().join("service-account.token");
    let issued = gitlab_cli(&fixture.base_url)
        .args([
            "gitlab",
            "service-account",
            "token",
            "create",
            "sip/service",
            "70",
            "--name",
            "reviewer",
            "--scopes",
            "api",
            "--expires-at",
            &expiry(),
            "--token-output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("service account token", &issued);
    assert_eq!(std::fs::read_to_string(output).unwrap().trim(), ISSUED);
    let listed = fixture
        .ok(
            "service_account.token.list",
            json!({"project":"sip/service","userId":70}),
        )
        .await;
    assert!(!listed.to_string().contains(ISSUED));
    fixture
        .ok(
            "service_account.view",
            json!({"project":"sip/service","userId":70}),
        )
        .await;
    fixture
        .ok("service_account.list", json!({"project":"sip/service"}))
        .await;
    fixture
        .ok(
            "service_account.token.rotate",
            json!({"project":"sip/service","userId":70,"tokenId":10,"expiresAt":expiry()}),
        )
        .await;
    fixture
        .ok(
            "service_account.token.revoke",
            json!({"project":"sip/service","userId":70,"tokenId":11}),
        )
        .await;
    fixture
        .ok(
            "service_account.delete",
            json!({"project":"sip/service","userId":70}),
        )
        .await;
    fixture.assert_audit_safe(&[
        "service_account.create",
        "service_account.token.create",
        "service_account.token.rotate",
    ]);
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_limits_project_ownership_and_exact_grants_prevent_upstream_writes() {
    let fixture = Fixture::new(true, ACTIONS).await;
    let valid = json!({"project":"sip/service","name":"reviewer","scopes":["api"],"accessLevel":30,"expiresAt":expiry()});
    for (field, value) in [
        ("accessLevel", json!(40)),
        ("scopes", json!(["sudo"])),
        ("scopes", json!(["api", "api"])),
        ("expiresAt", json!("2099-01-01")),
        ("expiresAt", json!("2000-01-01")),
        ("expiresAt", json!("2026-02-30")),
        ("unrecognized", json!(true)),
        ("project", json!("other/repo")),
    ] {
        let mut inputs = valid.clone();
        inputs[field] = value;
        let (status, _) = fixture.invoke("project.access_token.create", inputs).await;
        assert!(!status.is_success());
    }
    // An ID that is not a project-owned service account cannot gain membership or receive a token.
    for action in ["service_account.member.set", "service_account.token.create"] {
        let inputs = if action.ends_with("set") {
            json!({"project":"sip/service","userId":99,"accessLevel":30})
        } else {
            json!({"project":"sip/service","userId":99,"name":"reviewer","scopes":["api"],"expiresAt":expiry()})
        };
        let (status, _) = fixture.invoke(action, inputs).await;
        assert!(!status.is_success());
    }
    assert!(
        fixture
            .upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
    let disabled = Fixture::new(false, ACTIONS).await;
    let (status, _) = disabled
        .invoke("project.access_token.create", valid.clone())
        .await;
    assert!(!status.is_success());
    let read_only = Fixture::new(true, &["project.access_token.list"]).await;
    let (status, _) = read_only.invoke("project.access_token.create", valid).await;
    assert!(!status.is_success());
    assert!(
        disabled
            .upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
    assert!(
        read_only
            .upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
    fixture.stop().await;
    disabled.stop().await;
    read_only.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_catalog_openapi_send_and_pagination_bindings() {
    let fixture = Fixture::new(true, ACTIONS).await;
    let client = reqwest::Client::new();
    let mut docs = vec![];
    for path in ["catalog", "openapi.json", "send-schema.json"] {
        docs.push(
            client
                .get(format!("{}/v1/spec/{path}", fixture.base_url))
                .header("X-Agent-Access-Identity-Token", "agent-token")
                .header(
                    "X-Agent-Access-Request-Id",
                    uuid::Uuid::new_v4().to_string(),
                )
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap(),
        );
    }
    let catalog = &docs[0];
    let service = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["service"] == "gitlab")
        .unwrap();
    for action in ACTIONS {
        let item = service["actions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["action"] == *action)
            .unwrap();
        let path = format!("/v1/invoke/gitlab/{action}");
        assert_eq!(
            item["inputSchema"],
            docs[1]["paths"][&path]["post"]["requestBody"]["content"]["application/json"]["schema"]
                ["properties"]["inputs"]
        );
        let secret =
            action.contains("token") && (action.ends_with("create") || action.ends_with("rotate"));
        if secret {
            assert_eq!(
                item["sensitiveOutputPointers"],
                json!(["/result/issuedToken"])
            );
            assert_eq!(
                docs[1]["paths"][&path]["post"]["x-agent-access-sensitive-output-pointers"],
                json!(["/result/issuedToken"])
            );
        }
        assert!(docs[2].to_string().contains(action));
    }
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/access_tokens"))
        .and(query_param("page", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-next-page", "2")
                .set_body_json(json!([token(10)])),
        )
        .mount(&fixture.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/access_tokens"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([token(11)])))
        .mount(&fixture.upstream)
        .await;
    let first = fixture
        .ok(
            "project.access_token.list",
            json!({"project":"sip/service","maxResults":1}),
        )
        .await;
    let next = &first["result"]["nextPageToken"];
    assert!(next.is_string());
    let second = fixture
        .ok(
            "project.access_token.list",
            json!({"project":"sip/service","maxResults":1,"pageToken":next}),
        )
        .await;
    assert_eq!(second["result"]["items"][0]["id"], 11);
    let (status, _) = fixture
        .invoke(
            "project.access_token.list",
            json!({"project":"sip/service","maxResults":2,"pageToken":next}),
        )
        .await;
    assert!(!status.is_success());
    let (status, _) = fixture
        .invoke(
            "service_account.list",
            json!({"project":"sip/service","maxResults":1,"pageToken":next}),
        )
        .await;
    assert!(!status.is_success());
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_unknown_mutations_and_malformed_token_responses_never_export_secrets() {
    let fixture = Fixture::new(true, ACTIONS).await;
    let mut bad = token(10);
    bad["scopes"] = json!(["sudo"]);
    fixture
        .mock("POST", "/api/v4/projects/42/access_tokens", bad, 201)
        .await;
    let inputs = json!({"project":"sip/service","name":"reviewer","scopes":["api"],"accessLevel":30,"expiresAt":expiry()});
    let (status, result) = fixture
        .invoke("project.access_token.create", inputs.clone())
        .await;
    assert!(!status.is_success());
    assert_eq!(result["result"]["mutationStatus"], "applied_unverified");
    assert_eq!(result["result"]["retrySafe"], false);
    assert_eq!(status, reqwest::StatusCode::CONFLICT);
    assert_eq!(result["reasonCode"], "mutation_verification_failed");
    assert_eq!(result["decision"], "error");
    assert_eq!(result["result"]["verificationStage"], "mutation_response");
    assert_eq!(result["result"]["safeLocators"]["tokenId"], 10);
    let record = fixture.broker.audit().unwrap().records().pop().unwrap();
    assert_eq!(record["objectIds"]["tokenId"], 10);
    assert_eq!(record["objectIds"]["userId"], 70);
    assert_eq!(record["upstreamStatus"], 201);
    assert!(record["upstreamDurationMs"].is_number());
    assert!(!result.to_string().contains(ISSUED));
    fixture.upstream.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/sip%2Fservice"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id":42,"path_with_namespace":"sip/service"})),
        )
        .mount(&fixture.upstream)
        .await;
    fixture
        .mock(
            "POST",
            "/api/v4/projects/42/access_tokens",
            json!({"token":ISSUED,"message":ISSUED}),
            500,
        )
        .await;
    let (_, result) = fixture
        .invoke("project.access_token.create", inputs.clone())
        .await;
    assert_eq!(result["reasonCode"], "mutation_verification_failed");
    assert_eq!(result["result"]["mutationStatus"], "applied_unverified");
    assert_eq!(result["result"]["retrySafe"], false);
    assert!(!result.to_string().contains(ISSUED));
    fixture.upstream.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/sip%2Fservice"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id":42,"path_with_namespace":"sip/service"})),
        )
        .mount(&fixture.upstream)
        .await;
    fixture
        .mock(
            "POST",
            "/api/v4/projects/42/access_tokens",
            json!({"message":{"name":ISSUED}}),
            422,
        )
        .await;
    let (_, result) = fixture.invoke("project.access_token.create", inputs).await;
    assert_eq!(result["decision"], "deny");
    assert_eq!(result["reasonCode"], "input_invalid");
    assert!(result["result"].get("mutationStatus").is_none());
    assert!(!result.to_string().contains(ISSUED));
    let record = fixture.broker.audit().unwrap().records().pop().unwrap();
    assert_eq!(record["upstreamStatus"], 422);
    fixture.assert_audit_safe(&["project.access_token.create"]);
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_rotation_rejects_inactive_overprivileged_and_wrong_owner_tokens() {
    for (field, value) in [
        ("active", json!(false)),
        ("revoked", json!(true)),
        ("access_level", json!(40)),
        ("scopes", json!(["sudo"])),
        ("id", json!(99)),
    ] {
        let fixture = Fixture::new(true, ACTIONS).await;
        let mut old = token(10);
        old[field] = value;
        fixture
            .mock("GET", "/api/v4/projects/42/access_tokens/10", old, 200)
            .await;
        let (status, _) = fixture
            .invoke(
                "project.access_token.rotate",
                json!({"project":"sip/service","tokenId":10,"expiresAt":expiry()}),
            )
            .await;
        assert!(!status.is_success(), "{field}");
        assert!(
            fixture
                .upstream
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method.as_str() == "GET")
        );
        fixture.stop().await;
    }
    let fixture = Fixture::new(true, ACTIONS).await;
    fixture
        .mock(
            "GET",
            "/api/v4/projects/42/service_accounts/70",
            account(),
            200,
        )
        .await;
    fixture
        .mock(
            "GET",
            "/api/v4/projects/42/members/70",
            json!({"id":70,"access_level":40}),
            200,
        )
        .await;
    let (status, _) = fixture.invoke("service_account.token.create", json!({"project":"sip/service","userId":70,"name":"reviewer","scopes":["api"],"expiresAt":expiry()})).await;
    assert!(!status.is_success());
    assert!(
        fixture
            .upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET")
    );
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_member_set_adds_only_a_proven_project_service_account() {
    let fixture = Fixture::new(true, ACTIONS).await;
    fixture
        .mock(
            "GET",
            "/api/v4/projects/42/service_accounts/70",
            account(),
            200,
        )
        .await;
    fixture
        .mock(
            "GET",
            "/api/v4/projects/42/members/70",
            json!({"message":"404"}),
            404,
        )
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/members"))
        .and(header("authorization", "Bearer gitlab-per-user-token"))
        .and(body_json(json!({"user_id":70,"access_level":30})))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id":70,"access_level":30})))
        .expect(1)
        .mount(&fixture.upstream)
        .await;
    let result = fixture
        .ok(
            "service_account.member.set",
            json!({"project":"sip/service","userId":70,"accessLevel":30}),
        )
        .await;
    assert_eq!(result["result"]["member"]["userId"], 70);
    fixture.assert_audit_safe(&["service_account.member.set"]);
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_token_file_denials_cleanup_but_uncertain_writes_preserve_reservation() {
    for case in [
        "invalid",
        "disabled",
        "policy",
        "validation",
        "uncertain",
        "malformed",
    ] {
        let fixture = Fixture::new(
            case != "disabled",
            if case == "policy" {
                &["project.access_token.list"]
            } else {
                ACTIONS
            },
        )
        .await;
        if matches!(case, "validation" | "uncertain" | "malformed") {
            fixture
                .mock(
                    "POST",
                    "/api/v4/projects/42/access_tokens",
                    json!({"message":ISSUED}),
                    match case {
                        "validation" => 400,
                        "uncertain" => 500,
                        _ => 201,
                    },
                )
                .await;
        }
        let output_path = fixture.dir.path().join("denied.token");
        let valid_expiry = expiry();
        let output = gitlab_cli(&fixture.base_url)
            .args([
                "gitlab",
                "project",
                "access-token",
                "create",
                "sip/service",
                "--name",
                "reviewer",
                "--scopes",
                "api",
                "--access-level",
                "30",
                "--expires-at",
                if case == "invalid" {
                    "invalid-date"
                } else {
                    &valid_expiry
                },
                "--token-output",
                output_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{case}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains(ISSUED));
        let uncertain = matches!(case, "uncertain" | "malformed");
        assert_eq!(output_path.exists(), uncertain, "{case}");
        if uncertain {
            assert!(output.stdout.is_empty(), "{case}");
            let error: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(error["reasonCode"], "mutation_verification_failed");
            assert!(error["result"]["safeLocators"].is_object());
            assert_eq!(output.status.code(), Some(2), "{case}");
            assert_eq!(std::fs::metadata(&output_path).unwrap().len(), 0);
        }
        if matches!(case, "invalid" | "disabled" | "policy") {
            assert!(
                fixture
                    .upstream
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .all(|r| r.method.as_str() == "GET")
            );
        }
        // Missing authority is now refused by token-output's catalog preflight;
        // it never reaches invoke or produces an invocation audit record.
        fixture.assert_audit_safe(if case == "policy" {
            &[]
        } else {
            &["project.access_token.create"]
        });
        fixture.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_service_account_rotation_lookup_pagination_is_bounded_before_write() {
    for case in ["found", "absent", "nonadvancing", "bound"] {
        let fixture = Fixture::new(true, ACTIONS).await;
        fixture
            .mock(
                "GET",
                "/api/v4/projects/42/service_accounts/70",
                account(),
                200,
            )
            .await;
        fixture
            .mock(
                "GET",
                "/api/v4/projects/42/members/70",
                json!({"id":70,"access_level":30}),
                200,
            )
            .await;
        let pages = if case == "bound" { 100 } else { 2 };
        for page in 1..=pages {
            let mut response =
                ResponseTemplate::new(200).set_body_json(if case == "found" && page == 2 {
                    json!([token(10)])
                } else {
                    json!([token(99)])
                });
            if page < pages || case == "bound" {
                response = response.insert_header("x-next-page", (page + 1).to_string());
            } else if case == "nonadvancing" {
                response = response.insert_header("x-next-page", page.to_string());
            }
            Mock::given(method("GET"))
                .and(path(
                    "/api/v4/projects/42/service_accounts/70/personal_access_tokens",
                ))
                .and(query_param("page", page.to_string()))
                .and(query_param("per_page", "100"))
                .respond_with(response)
                .expect(1)
                .mount(&fixture.upstream)
                .await;
        }
        Mock::given(method("POST"))
            .and(path(
                "/api/v4/projects/42/service_accounts/70/personal_access_tokens/10/rotate",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(token(11)))
            .expect(if case == "found" { 1 } else { 0 })
            .mount(&fixture.upstream)
            .await;
        let (status, result) = fixture
            .invoke(
                "service_account.token.rotate",
                json!({"project":"sip/service","userId":70,"tokenId":10,"expiresAt":expiry()}),
            )
            .await;
        if case == "found" {
            assert!(status.is_success(), "{result}");
            assert_eq!(result["result"]["accessToken"]["id"], 11);
        } else {
            assert!(!status.is_success());
            assert_eq!(
                result["reasonCode"],
                if case == "absent" {
                    "scope_unresolved"
                } else {
                    "upstream_protocol_failed"
                }
            );
            assert!(result["result"].get("mutationStatus").is_none());
        }
        fixture.upstream.verify().await;
        fixture.assert_audit_safe(&["service_account.token.rotate"]);
        fixture.stop().await;
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_token_file_cleanup_failure_preserves_denial_and_exit_code() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new(true, ACTIONS).await;
    let output_dir = fixture.dir.path().join("delivery");
    std::fs::create_dir(&output_dir).unwrap();
    let readonly_dir = output_dir.clone();
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/access_tokens"))
        .respond_with(move |_: &wiremock::Request| {
            // The file has already been reserved. Make unlink fail deterministically at response time.
            std::fs::set_permissions(&readonly_dir, std::fs::Permissions::from_mode(0o500))
                .unwrap();
            ResponseTemplate::new(400).set_body_json(json!({"message":ISSUED}))
        })
        .expect(1)
        .mount(&fixture.upstream)
        .await;
    let output_path = output_dir.join("denied.token");
    let output = gitlab_cli(&fixture.base_url)
        .args([
            "gitlab",
            "project",
            "access-token",
            "create",
            "sip/service",
            "--name",
            "reviewer",
            "--scopes",
            "api",
            "--access-level",
            "30",
            "--expires-at",
            &expiry(),
            "--token-output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    std::fs::set_permissions(&output_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(output.status.code(), Some(3));
    let denial: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(denial["decision"], "deny");
    assert_eq!(denial["reasonCode"], "input_invalid");
    let warning = String::from_utf8_lossy(&output.stderr);
    assert!(warning.contains("Cannot remove unused token output reservation"));
    assert!(warning.contains(output_path.to_str().unwrap()));
    assert!(!warning.contains(ISSUED));
    assert_eq!(std::fs::metadata(&output_path).unwrap().len(), 0);
    fixture.assert_audit_safe(&["project.access_token.create"]);
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_project_member_cli_lookup_is_separately_authorized_and_project_scoped() {
    let fixture = Fixture::new(true, &["project.member.view"]).await;
    fixture
        .mock(
            "GET",
            "/api/v4/projects/42/members/70",
            json!({
                "id":70,"username":"project_42_bot_example","name":"reviewer","access_level":30,
                "email":"private@example.test","token":ISSUED,
            }),
            200,
        )
        .await;
    let output = gitlab_cli(&fixture.base_url)
        .args(["gitlab", "project", "member", "view", "sip/service", "70"])
        .output()
        .unwrap();
    assert_success("project member username lookup", &output);
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["action"], "project.member.view");
    assert_eq!(
        response["result"],
        json!({"member":{
            "id":70,"username":"project_42_bot_example","name":"reviewer","accessLevel":30,
        }})
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(ISSUED));
    let denied = gitlab_cli(&fixture.base_url)
        .args(["gitlab", "project", "member", "view", "fork/service", "70"])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    let calls = fixture.upstream.received_requests().await.unwrap();
    assert_eq!(
        calls
            .iter()
            .filter(|r| r.url.path() == "/api/v4/projects/42/members/70")
            .count(),
        1
    );
    assert!(calls.iter().all(|r| r.method == "GET"));
    assert!(
        !calls
            .iter()
            .any(|r| r.url.path().starts_with("/api/v4/users/"))
    );
    fixture.assert_audit_safe(&["project.member.view"]);
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_token_output_preflight_rejects_references_and_preserves_a_changed_mode_result()
 {
    let fixture = Fixture::new(true, &["project.access_token.create"]).await;
    let response = reqwest::Client::new()
        .get(format!("{}/v1/spec/catalog", fixture.base_url))
        .header("X-Agent-Access-Request-Id", "gitlab-token-output-catalog")
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let catalog = response.json::<Value>().await.unwrap();
    for (mode, invoke_count) in [("reference", 0), ("raw", 1)] {
        // The mock Broker models a catalog/result policy change. No GitLab
        // write occurs; the real CLI must preserve the returned safe outcome.
        let broker = MockServer::start().await;
        let mut projected = catalog.clone();
        let action = projected["services"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|service| service["service"] == "gitlab")
            .unwrap()["actions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|action| action["action"] == "project.access_token.create")
            .unwrap();
        action["secretOutputMode"] = json!(mode);
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(projected))
            .expect(1)
            .mount(&broker)
            .await;
        let reference =
            json!({"secretRef":"synthetic-secret-reference","expiresAt":"2099-01-01T00:00:00Z"});
        let outcome = json!({
            "agentRequestId":"test-reference-delivery", "brokerRequestId":"test-reference-delivery",
            "service":"gitlab", "action":"project.access_token.create", "decision":"allow",
            "resourceScopes":{"repository":["sip/service"]}, "reasonCode":null, "reason":null, "error":null,
            "result":{"accessToken":{"id":10,"userId":70},"issuedToken":reference,
                "mutationStatus":"applied","retrySafe":false},
        });
        Mock::given(method("POST"))
            .and(path("/v1/invoke/gitlab/project.access_token.create"))
            .respond_with(ResponseTemplate::new(200).set_body_json(outcome))
            .expect(invoke_count)
            .mount(&broker)
            .await;
        let path = fixture.dir.path().join(format!("{mode}.token"));
        let output = gitlab_cli(&broker.uri())
            .args([
                "gitlab",
                "project",
                "access-token",
                "create",
                "sip/service",
                "--name",
                "reviewer",
                "--scopes",
                "api",
                "--access-level",
                "30",
                "--expires-at",
                &expiry(),
                "--token-output",
                path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!path.exists(), "{mode}");
        let message = String::from_utf8_lossy(&output.stderr);
        if mode == "reference" {
            assert!(!output.status.success());
            assert!(message.contains("requires Broker raw secret delivery mode"));
        } else {
            assert_success("changed policy retains issuance reference", &output);
            let value: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["result"]["issuedToken"], reference);
            assert_eq!(value["result"]["accessToken"]["id"], 10);
            assert_eq!(value["result"]["mutationStatus"], "applied");
            assert_eq!(value["result"]["retrySafe"], false);
            assert!(message.contains("do not repeat issuance"));
        }
        broker.verify().await;
    }
    assert!(
        fixture
            .upstream
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
    fixture.stop().await;
}
