//! Application access against a real broker: a registered application takes
//! a person through the authorization-code flow with PKCE over HTTP, invokes a
//! service with the minted agent token through the real `agent-access`
//! binary, and an administrator narrows and removes the access with the
//! `admin principals application-access` commands.
use agent_access_broker_host::test_support::{FixtureDir, IsolatedBroker};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    LocalPasswordHasher, LocalPasswordWriteRequest, ManagedStore, ManagedStoreConfig,
    ManagedStoreOpenMode, PrincipalAccessPatchRequest, PrincipalRole, PrincipalWriteRequest,
};
use agent_access_provider::REQUEST_ID_HEADER;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::process::Command;

const HOST: &str = "127.0.0.1";
const ORIGIN: &str = "http://127.0.0.1";
const APP: &str = "example-runner";
const REDIRECT: &str = "https://runner.example.test/auth/broker/callback";
const SECRET: &str = "example-runner-client-secret-0123456789";
const VERIFIER: &str = "verifier-verifier-verifier-verifier-verifier-0123";

fn toml_string(value: impl std::fmt::Display) -> String {
    serde_json::to_string(&value.to_string()).unwrap()
}

/// Managed identity with browser sign-in, the fake service granted to alice
/// by TOML policy, and one registered application.
fn document(directory: &FixtureDir) -> String {
    let secret_ref =
        |name: &str| toml_string(format_args!("file:{}", directory.join(name).display()));
    format!(
        r#"
[deployment]
enable_fake_service = true

[providers.fake]

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

[management]
enabled = true

[broker_tokens]
hash_key_ref = {hash_key}

[credential_encryption]
active_key = "k1"

[[credential_encryption.keys]]
id = "k1"
provider = "file"
path = {encryption_key}

[browser_auth]
enabled = true
public_origin = "{ORIGIN}"
csrf_key_ref = {csrf_key}

[browser_auth.local_password]
enabled = true
pepper_ref = {pepper}

[applications.{APP}]
display_name = "Example Runner"
client_secret_ref = {client_secret}
redirect_uris = ["{REDIRECT}"]
connect = "read_write"
allowed_execution_contexts = ["default"]
allowed_services = ["fake"]

[credentials.service.fake]
type = "bearer_token"
token_ref = {fake_token}

[policy]
authority = "toml"
default_decision = "deny"

[[policy.resources]]
id = "fake-test"
resource_type = "fake_project"
selector = {{ kind = "exact", value = "TEST" }}
allowed_execution_contexts = ["default"]
enabled = true

[[policy.grants]]
subjects = ["user:alice"]
service = "fake"
actions = ["echo"]
resources = {{ resource_ids = ["fake-test"] }}
credential_mode = "service"

[audit]
type = "jsonl"
path = {audit}

[limits]
upload_spool_dir = {spool}
"#,
        store = toml_string(directory.join("store.sqlite").display()),
        hash_key = secret_ref("hash-key"),
        encryption_key = toml_string(directory.join("encryption-key").display()),
        csrf_key = secret_ref("csrf-key"),
        pepper = secret_ref("pepper"),
        client_secret = secret_ref("client-secret"),
        fake_token = secret_ref("fake-token"),
        audit = toml_string(directory.join("audit.jsonl").display()),
        spool = toml_string(directory.join("upload-spool").display()),
    )
}

/// Seeds the administrator and alice, who signs in with a local password,
/// and returns the administrator's token.
fn seed(directory: &FixtureDir) -> String {
    let contexts = agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap();
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
    for (principal, display_name) in [("admin", None), ("alice", Some("Alex Example"))] {
        store
            .create_principal(
                PrincipalWriteRequest {
                    agent_token_issuance: Default::default(),
                    role: PrincipalRole::User,
                    // Connecting needs neither self-service nor token issuance.
                    self_service_enabled: Some(false),
                    principal_id: principal.into(),
                    kind: "user".into(),
                    display_name: display_name.map(str::to_string),
                    email: None,
                    external_subject: None,
                    created_by: "test".into(),
                },
                &contexts,
            )
            .unwrap();
    }
    store
        .patch_principal_access(
            PrincipalAccessPatchRequest {
                agent_token_issuance: None,
                principal_id: "admin".into(),
                role: Some(PrincipalRole::Admin),
                self_service_enabled: None,
                actor: "test".into(),
            },
            &contexts,
        )
        .unwrap();
    let pepper = format!("file:{}", directory.join("pepper").display());
    store
        .enable_local_password(
            &LocalPasswordHasher::load("browser_auth.local_password.pepper_ref", &pepper).unwrap(),
            LocalPasswordWriteRequest {
                principal_id: "alice".into(),
                password: "alice-password".into(),
                min_password_length: 8,
                password_change_required: false,
                actor: "test".into(),
            },
        )
        .unwrap();
    let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
        hash_key_ref: format!("file:{}", directory.join("hash-key").display()),
        ..Default::default()
    })
    .unwrap();
    store
        .issue_broker_token(
            &hasher,
            BrokerTokenIssueRequest {
                principal_id: "admin".into(),
                name: "application access admin".into(),
                token_class: BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "test".into(),
            },
        )
        .unwrap()
        .token
}

fn query(url: &str) -> BTreeMap<String, String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_application_connects_a_person_invokes_and_is_administered() {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let directory = application.directory().clone();
    for (name, value) in [
        ("hash-key", URL_SAFE_NO_PAD.encode([31_u8; 32])),
        ("encryption-key", URL_SAFE_NO_PAD.encode([32_u8; 32])),
        ("csrf-key", URL_SAFE_NO_PAD.encode([33_u8; 32])),
        ("pepper", URL_SAFE_NO_PAD.encode([34_u8; 32])),
        ("client-secret", SECRET.to_string()),
        ("fake-token", "synthetic-fake-service-token".to_string()),
    ] {
        directory.secret_file(name, value).unwrap();
    }
    let admin_token = directory
        .secret_file("admin.token", seed(&directory))
        .unwrap();
    let broker = application
        .config_document(document(&directory))
        .start()
        .await
        .unwrap();
    let url = broker.public_url();
    // Responses are observed as sent: redirects are never followed.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();

    // The application discovers its endpoints; it never hard-codes them.
    let metadata: Value = client
        .get(format!("{url}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(metadata["issuer"], ORIGIN);
    let endpoint = |name: &str| {
        let endpoint = metadata[name].as_str().unwrap();
        // Every endpoint shares the issuer's origin; the test reaches it at
        // the listener's address.
        format!("{url}{}", endpoint.strip_prefix(ORIGIN).unwrap())
    };
    let basic = format!("Basic {}", STANDARD.encode(format!("{APP}:{SECRET}")));

    // The browser is sent to the authorization endpoint.
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let authorize = client
        .get(endpoint("authorization_endpoint"))
        .query(&[
            ("response_type", "code"),
            ("client_id", APP),
            ("redirect_uri", REDIRECT),
            ("state", "client-state-1"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(authorize.status(), StatusCode::SEE_OTHER);
    let consent = authorize.headers()["location"]
        .to_str()
        .unwrap()
        .to_string();
    let request = consent.strip_prefix("/ui/authorize/").unwrap().to_string();

    // The person signs in and approves on the consent page.
    let login = client
        .post(format!("{url}/v1/auth/local/login"))
        .header(REQUEST_ID_HEADER, "application-login")
        .header("Host", HOST)
        .header("Origin", ORIGIN)
        .json(&json!({"principalId": "alice", "password": "alice-password", "returnTo": consent}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let session: Value = login.json().await.unwrap();
    // The sign-in return rule carries the person back to the consent page.
    assert_eq!(session["result"]["returnTo"], consent.as_str());
    assert_eq!(session["result"]["selfServiceEnabled"], false);
    let csrf = session["result"]["csrfToken"].as_str().unwrap().to_string();
    let browser = |method: reqwest::Method, path: String| {
        client
            .request(method, format!("{url}{path}"))
            .header(REQUEST_ID_HEADER, "application-consent")
            .header("Host", HOST)
            .header("Origin", ORIGIN)
            .header("Cookie", &cookie)
            .header("X-Agent-Access-CSRF", &csrf)
    };
    let pending: Value = browser(
        reqwest::Method::GET,
        format!("/v1/applications/authorizations/{request}"),
    )
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(pending["result"]["applicationName"], "Example Runner");
    assert_eq!(pending["result"]["canConnect"], true, "{pending}");
    assert_eq!(pending["result"]["readOnly"], false);
    let decided: Value = browser(
        reqwest::Method::POST,
        format!("/v1/applications/authorizations/{request}/decision"),
    )
    .json(&json!({"decision": "approve"}))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(decided["ok"], true, "{decided}");
    let redirect_to = decided["result"]["redirectTo"].as_str().unwrap();
    assert!(redirect_to.starts_with(REDIRECT));
    let returned = query(redirect_to);
    assert_eq!(returned["state"], "client-state-1");

    // The application exchanges the code.
    let token = |form: Vec<(&'static str, String)>| {
        let request = client
            .post(endpoint("token_endpoint"))
            .header("Authorization", &basic)
            .form(&form);
        async move {
            let response = request.send().await.unwrap();
            let status = response.status();
            assert_eq!(response.headers()["cache-control"], "no-store");
            (status, response.json::<Value>().await.unwrap())
        }
    };
    let (status, minted) = token(vec![
        ("grant_type", "authorization_code".into()),
        ("code", returned["code"].clone()),
        ("redirect_uri", REDIRECT.into()),
        ("code_verifier", VERIFIER.into()),
    ])
    .await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    assert_eq!(minted["token_type"], "Bearer");
    assert_eq!(minted["expires_in"], 28800);
    assert_eq!(minted["principal_id"], "alice");
    assert_eq!(minted["principal_name"], "Alex Example");
    assert_eq!(minted["read_only"], false);
    let refresh_token = minted["refresh_token"].as_str().unwrap().to_string();

    // The minted token is an ordinary agent token for the existing CLI.
    let invoke = |access_token: &str, name: &str| {
        let file = directory.secret_file(name, access_token).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("AGENT_ACCESS_")) {
            command.env_remove(key);
        }
        let output = command
            .env("AGENT_ACCESS_CONFIG", "/dev/null")
            .args(["--url", &url, "--token-file"])
            .arg(&file)
            .args([
                "--identity-header",
                "Authorization",
                "--identity-scheme",
                "Bearer",
                "invoke",
                "fake.echo",
                "--input-json",
                r#"{"project":"TEST","message":"from the application"}"#,
            ])
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned()
                + &String::from_utf8_lossy(&output.stderr),
        )
    };
    let (invoked, output) = invoke(minted["access_token"].as_str().unwrap(), "access-1.token");
    assert!(invoked, "{output}");
    assert!(output.contains("from the application"), "{output}");

    // The administrator sees the access, not its individual tokens.
    let cli = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("AGENT_ACCESS_")) {
            command.env_remove(key);
        }
        let output = command
            .env("AGENT_ACCESS_CONFIG", "/dev/null")
            .args(["--url", &url, "--token-file"])
            .arg(&admin_token)
            .args([
                "--identity-header",
                "Authorization",
                "--identity-scheme",
                "Bearer",
                "admin",
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
        (output.status.success(), response)
    };
    let ok = |args: &[&str]| {
        let (success, response) = cli(args);
        assert!(success, "{args:?}: {response}");
        response["result"].clone()
    };
    let listed = ok(&["principals", "application-access", "list", "alice"]);
    let access = &listed["access"][0];
    assert_eq!(access["applicationId"], APP);
    assert_eq!(access["applicationName"], "Example Runner");
    assert_eq!(access["liveTokenCount"], 1);
    assert_eq!(
        (&access["enabled"], &access["readOnly"], &access["version"]),
        (&json!(true), &json!(false), &json!(1))
    );
    let access_id = access["accessId"].as_str().unwrap().to_string();
    let tokens = ok(&["tokens", "list"]);
    assert!(
        tokens
            .as_array()
            .unwrap()
            .iter()
            .all(|token| token["tokenClass"] != "agent_invoke"),
        "application tokens are not listed individually: {tokens}"
    );

    // Read-only ends the live token; the refreshed one is read-only.
    let narrowed = ok(&[
        "principals",
        "application-access",
        "update",
        "alice",
        &access_id,
        "--read-only",
        "true",
        "--expected-version",
        "1",
    ]);
    assert_eq!(
        (&narrowed["readOnly"], &narrowed["version"]),
        (&json!(true), &json!(2))
    );
    assert_eq!(narrowed["liveTokenCount"], 0);
    let (invoked, output) = invoke(minted["access_token"].as_str().unwrap(), "access-1.token");
    assert!(!invoked, "{output}");
    let (status, refreshed) = token(vec![
        ("grant_type", "refresh_token".into()),
        ("refresh_token", refresh_token.clone()),
    ])
    .await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    assert_eq!(refreshed["read_only"], true);
    assert!(refreshed.get("refresh_token").is_none());
    // The fixture's action is a read, which a read-only token may invoke.
    let (invoked, output) = invoke(
        refreshed["access_token"].as_str().unwrap(),
        "access-2.token",
    );
    assert!(invoked, "{output}");

    // A stale fence is refused; disabling refuses the refresh token.
    let (success, stale) = cli(&[
        "principals",
        "application-access",
        "update",
        "alice",
        &access_id,
        "--enabled",
        "false",
        "--expected-version",
        "1",
    ]);
    assert!(!success, "{stale}");
    assert_eq!(stale["reasonCode"], "version_conflict");
    ok(&[
        "principals",
        "application-access",
        "update",
        "alice",
        &access_id,
        "--enabled",
        "false",
        "--expected-version",
        "2",
    ]);
    let (status, refused) = token(vec![
        ("grant_type", "refresh_token".into()),
        ("refresh_token", refresh_token.clone()),
    ])
    .await;
    assert_eq!(
        (status, &refused),
        (StatusCode::BAD_REQUEST, &json!({"error": "invalid_grant"}))
    );

    // Removal is version-checked and final for this refresh token.
    let removed = ok(&[
        "principals",
        "application-access",
        "delete",
        "alice",
        &access_id,
        "--expected-version",
        "3",
    ]);
    assert_eq!(removed, json!({"removed": true}));
    assert_eq!(
        ok(&["principals", "application-access", "list", "alice"]),
        json!({"access": []})
    );
    let revoke = client
        .post(endpoint("revocation_endpoint"))
        .header("Authorization", &basic)
        .form(&[("token", refresh_token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(
        revoke.status(),
        StatusCode::OK,
        "unknown tokens are accepted"
    );

    // Audit names the application, the decisions and each change, never a secret.
    let audit = broker.audit().unwrap();
    for action in [
        "applications.authorizations.decide",
        "applications.token.issued",
        "applications.token.refused",
        "admin.principals.application_access.patch",
        "admin.principals.application_access.delete",
    ] {
        audit.require_action("broker", action);
    }
    let text = audit.text();
    for secret in [
        SECRET,
        VERIFIER,
        refresh_token.as_str(),
        returned["code"].as_str(),
        minted["access_token"].as_str().unwrap(),
        refreshed["access_token"].as_str().unwrap(),
        request.as_str(),
    ] {
        assert!(!text.contains(secret), "a secret reached the audit log");
    }
    broker.shutdown();
    assert!(broker.join().await.unwrap().is_clean());
}
