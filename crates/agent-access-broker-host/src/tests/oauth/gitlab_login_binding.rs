//! GitLab OAuth with `login_binding`: a GitLab account connects only when
//! GitLab reports it linked, through its Microsoft Entra sign-in, to the
//! owner's Broker Microsoft sign-in, whatever sign-in the browser session
//! used. The fixture's alice signs in with her local password.
use super::*;
use agent_access_core::{MicrosoftOidcConfig, OidcLoginMethodLinkRequest};
use agent_access_provider::{OAuthLoginBinding, OAuthLoginProvider};

const TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const MICROSOFT_CLIENT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2";
const OBJECT_ID: &str = "cccccccc-cccc-4ccc-8ccc-ccccccccccc3";
const OTHER_OBJECT_ID: &str = "dddddddd-dddd-4ddd-8ddd-ddddddddddd4";
/// GitLab's OmniAuth name for its Entra ID sign-in.
const ENTRA: &str = "azure_activedirectory_v2";

fn login_binding() -> OAuthLoginBinding {
    OAuthLoginBinding {
        provider: OAuthLoginProvider::Microsoft,
        upstream_identity_provider: ENTRA.into(),
        upstream_tenant_id: TENANT.into(),
    }
}

/// The GitLab fixture with the Broker's Microsoft sign-in in `TENANT`, and
/// the `gitlab` registration bound to it.
async fn bound_fixture(gitlab: &MockServer, consumer: &Arc<InstanceConsumer>) -> OAuthFixture {
    gitlab_fixture_with(gitlab, consumer, |directory, config| {
        let secret = directory.join("microsoft-client-secret");
        std::fs::write(&secret, "microsoft-client-secret").unwrap();
        let flow_key = directory.join("microsoft-flow-key");
        std::fs::write(&flow_key, URL_SAFE_NO_PAD.encode([25_u8; 32])).unwrap();
        config.browser_auth.oidc.microsoft = MicrosoftOidcConfig {
            enabled: true,
            tenant_id: Some(TENANT.into()),
            client_id: Some(MICROSOFT_CLIENT.into()),
            client_secret_ref: Some(format!("file:{}", secret.display())),
            flow_key_ref: Some(format!("file:{}", flow_key.display())),
            ..MicrosoftOidcConfig::default()
        };
        config
            .oauth
            .registrations
            .get_mut("gitlab")
            .unwrap()
            .login_binding = Some(login_binding());
    })
    .await
}

/// The code exchange, token info and `/api/v4/user` reporting
/// `identities`.
async fn mount_account(gitlab: &MockServer, identities: Value) {
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "gitlab-access-1",
            "refresh_token": "gitlab-refresh-1",
            "token_type": "Bearer",
            "expires_in": 7200
        })))
        .mount(gitlab)
        .await;
    Mock::given(method("GET"))
        .and(path("/oauth/token/info"))
        .respond_with(token_info_scopes())
        .mount(gitlab)
        .await;
    let mut user = json!({"id": 42, "username": "alice", "name": "Alice Example"});
    if !identities.is_null() {
        user["identities"] = identities;
    }
    Mock::given(method("GET"))
        .and(path("/api/v4/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user))
        .mount(gitlab)
        .await;
}

fn entra_identity(extern_uid: &str) -> Value {
    json!({"provider": ENTRA, "extern_uid": extern_uid, "saml_provider_id": null})
}

impl OAuthFixture {
    /// Links alice's Broker account to the Microsoft sign-in `object_id`.
    fn link_microsoft(&self, object_id: &str) {
        self.runtime
            .managed_store()
            .unwrap()
            .link_oidc_login_method(OidcLoginMethodLinkRequest {
                principal_id: "alice".into(),
                user_object_id: object_id.into(),
                actor: "test".into(),
            })
            .unwrap();
    }

    /// Alice's `gitlab` row of the OAuth connections listing.
    async fn gitlab_row(&self) -> Value {
        let response = self
            .browser(
                Method::GET,
                "/v1/oauth/connections",
                "gitlab-binding-list",
                None,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        response_json(response).await["result"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["registration"] == "gitlab")
            .unwrap()
            .clone()
    }
}

#[tokio::test]
async fn a_gitlab_account_linked_to_the_owners_microsoft_sign_in_connects() {
    let gitlab = MockServer::start().await;
    let consumer = InstanceConsumer::new(&gitlab.uri());
    let fixture = bound_fixture(&gitlab, &consumer).await;
    fixture.link_microsoft(OBJECT_ID);
    mount_account(
        &gitlab,
        json!([
            {"provider": "ldapmain", "extern_uid": "uid=alice,ou=people,dc=example,dc=com"},
            entra_identity(OBJECT_ID)
        ]),
    )
    .await;
    let row = fixture.gitlab_row().await;
    assert_eq!(row["canConnect"], true, "{row}");
    assert_eq!(row["connectUnavailableReason"], Value::Null);

    let (state, callback) = fixture.gitlab_consent().await;
    assert_completion_page(callback, "Authorized", &[&state, "one-use-code"]).await;
    let status = fixture.gitlab_status();
    assert_eq!(status.subject_id.as_deref(), Some("42"));
    let (code, body) = fixture
        .invoke("account.view", "gitlab-bound", json!({}))
        .await;
    assert_eq!(code, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_gitlab_account_not_linked_to_the_owners_sign_in_is_not_installed() {
    let gitlab = MockServer::start().await;
    let consumer = InstanceConsumer::new(&gitlab.uri());
    let fixture = bound_fixture(&gitlab, &consumer).await;
    fixture.link_microsoft(OBJECT_ID);
    for identities in [
        // Another person's Entra sign-in.
        json!([entra_identity(OTHER_OBJECT_ID)]),
        // The owner's object ID under another GitLab provider name.
        json!([{"provider": "openid_connect", "extern_uid": OBJECT_ID}]),
        // No linked sign-in, or none reported.
        json!([]),
        Value::Null,
    ] {
        gitlab.reset().await;
        mount_account(&gitlab, identities.clone()).await;
        let (_, callback) = fixture.gitlab_consent().await;
        let status = callback.status();
        let body = response_json(callback).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{identities}: {body}");
        assert_eq!(body["reasonCode"], "credential_invalid");
        assert_eq!(body["error"]["message"], "oauth_login_binding_mismatch");
        // The response names neither person's identity.
        for identity in [OBJECT_ID, OTHER_OBJECT_ID, TENANT] {
            assert!(!body.to_string().contains(identity), "{body}");
        }
        assert_eq!(
            routes(&gitlab).await,
            [
                "POST /oauth/token",
                "GET /oauth/token/info",
                "GET /api/v4/user"
            ]
        );
        assert!(fixture.gitlab_status().connection_id.is_none());
        let (code, body) = fixture
            .invoke("account.view", "gitlab-unbound", json!({}))
            .await;
        assert_ne!(code, StatusCode::OK, "{body}");
    }
    assert!(consumer.versions().is_empty());
    // Each refused callback is audited, without either identity.
    let records = read_audit_records(&fixture.audit_path);
    let refused = records
        .iter()
        .filter(|record| {
            record["agentRequestId"] == "gitlab-callback"
                && record["reasonCode"] == "credential_invalid"
        })
        .count();
    assert_eq!(refused, 4, "{records:?}");
    let audit = serde_json::to_string(&records).unwrap();
    assert!(!audit.contains(OBJECT_ID) && !audit.contains(OTHER_OBJECT_ID));
}

#[tokio::test]
async fn without_a_microsoft_sign_in_gitlab_cannot_connect() {
    let gitlab = MockServer::start().await;
    let consumer = InstanceConsumer::new(&gitlab.uri());
    let fixture = bound_fixture(&gitlab, &consumer).await;
    mount_account(&gitlab, json!([entra_identity(OBJECT_ID)])).await;
    let row = fixture.gitlab_row().await;
    assert_eq!(row["canConnect"], false, "{row}");
    assert_eq!(row["connectUnavailableReason"], "login_binding_required");
    assert!(!row["consumers"].as_array().unwrap().is_empty());

    let connect = fixture
        .browser(
            Method::POST,
            "/v1/oauth/connect",
            "gitlab-unlinked-connect",
            Some(json!({"registration": "gitlab", "intent": "connect"})),
        )
        .await;
    let status = connect.status();
    let body = response_json(connect).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["message"], "oauth_login_binding_required");
    assert!(gitlab.received_requests().await.unwrap().is_empty());

    // Linking alice's Microsoft sign-in is all it takes.
    fixture.link_microsoft(OBJECT_ID);
    assert_eq!(fixture.gitlab_row().await["canConnect"], true);
    let (state, callback) = fixture.gitlab_consent().await;
    assert_completion_page(callback, "Authorized", &[&state, "one-use-code"]).await;
}

#[tokio::test]
async fn unlinking_the_microsoft_sign_in_during_consent_prevents_the_install() {
    let gitlab = MockServer::start().await;
    let consumer = InstanceConsumer::new(&gitlab.uri());
    let fixture = bound_fixture(&gitlab, &consumer).await;
    fixture.link_microsoft(OBJECT_ID);
    mount_account(&gitlab, json!([entra_identity(OBJECT_ID)])).await;
    let connect = fixture
        .browser(
            Method::POST,
            "/v1/oauth/connect",
            "gitlab-binding-connect",
            Some(json!({"registration": "gitlab", "intent": "connect"})),
        )
        .await;
    assert_eq!(connect.status(), StatusCode::OK);
    let authorization_url = url::Url::parse(
        response_json(connect).await["result"]["authorizationUrl"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let state = authorization_url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    // An administrator unlinks it while alice is at GitLab. Her session
    // signed in with her password, so it stays valid.
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .unlink_oidc_login_method("alice", "admin")
        .unwrap();
    let callback = fixture
        .browser(
            Method::GET,
            &format!(
                "/v1/oauth/callback/gitlab?{}",
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("state", &state)
                    .append_pair("code", "one-use-code")
                    .finish()
            ),
            "gitlab-binding-callback",
            None,
        )
        .await;
    let status = callback.status();
    let body = response_json(callback).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["message"], "oauth_login_binding_required");
    assert!(fixture.gitlab_status().connection_id.is_none());
}

/// The bound production sample's offline validation errors about
/// `login_binding`, after `extra` TOML.
fn binding_errors(extra: &str) -> Vec<String> {
    let base = "https://gitlab.example.com";
    validation_errors(&format!(
        "{}{extra}",
        gitlab_oauth_config(base, base, "rotate_both", base)
    ))
    .into_iter()
    .filter(|error| error.contains("login_binding"))
    .collect()
}

const MICROSOFT_SIGN_IN: &str = r#"
[browser_auth.oidc.microsoft]
enabled = true
tenant_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
client_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2"
client_secret_ref = "env:AGENT_ACCESS_MICROSOFT_OIDC_CLIENT_SECRET"
flow_key_ref = "env:AGENT_ACCESS_MICROSOFT_OIDC_FLOW_KEY"
"#;

fn gitlab_binding(provider: &str, tenant: &str) -> String {
    format!(
        r#"
[oauth.registrations.gitlab.login_binding]
provider = "microsoft"
upstream_identity_provider = "{provider}"
upstream_tenant_id = "{tenant}"
"#
    )
}

#[test]
fn login_binding_validates_offline_against_the_brokers_microsoft_sign_in() {
    let label = "oauth.registrations.gitlab.login_binding";
    // GitLab with the Broker's own tenant.
    assert_eq!(
        binding_errors(&format!(
            "{MICROSOFT_SIGN_IN}{}",
            gitlab_binding(ENTRA, TENANT)
        )),
        Vec::<String>::new()
    );
    // Without the Broker's Microsoft sign-in.
    assert_eq!(
        binding_errors(&gitlab_binding(ENTRA, TENANT)),
        [format!(
            "{label} with provider = \"microsoft\" requires browser_auth.oidc.microsoft.enabled"
        )]
    );
    // GitLab's provider attested to another tenant.
    assert_eq!(
        binding_errors(&format!(
            "{MICROSOFT_SIGN_IN}{}",
            gitlab_binding(ENTRA, OTHER_OBJECT_ID)
        )),
        [format!(
            "{label}.upstream_tenant_id must be browser_auth.oidc.microsoft.tenant_id: the upstream must sign people in through the Broker's own Microsoft tenant"
        )]
    );
    // Malformed values.
    assert_eq!(
        binding_errors(&format!(
            "{MICROSOFT_SIGN_IN}{}",
            gitlab_binding("azure ad", &TENANT.to_uppercase())
        )),
        [
            format!(
                "{label}.upstream_identity_provider must be the upstream's identity provider name: 1-128 bytes without whitespace or control characters"
            ),
            format!("{label}.upstream_tenant_id must be a canonical lowercase UUID"),
            format!(
                "{label}.upstream_tenant_id must be browser_auth.oidc.microsoft.tenant_id: the upstream must sign people in through the Broker's own Microsoft tenant"
            ),
        ]
    );
    // An unknown key or provider is a parse error, never ignored.
    for extra in [
        format!(
            "{}upstream_uid_field = \"oid\"\n",
            gitlab_binding(ENTRA, TENANT)
        ),
        gitlab_binding(ENTRA, TENANT).replace("\"microsoft\"", "\"google\""),
    ] {
        let base = "https://gitlab.example.com";
        let raw = format!(
            "{}{MICROSOFT_SIGN_IN}{extra}",
            gitlab_oauth_config(base, base, "rotate_both", base)
        );
        assert!(
            agent_access_core::parse_broker_config_raw(
                "gitlab-oauth.toml",
                &raw,
                &Arc::new(crate::test_composition::backend_registry()),
            )
            .is_err(),
            "{extra}"
        );
    }
}

#[test]
fn dialects_without_linked_identities_reject_login_binding() {
    let google = format!(
        r#"{MICROSOFT_SIGN_IN}
[oauth.registrations.google]
adapter = "google"
base_url = "https://accounts.google.com"
redirect_uri = "https://broker.example.com/v1/oauth/callback/google"
client_id = "broker.apps.googleusercontent.com"
client_secret_ref = "env:GOOGLE_CLIENT_SECRET"
rotation = "preserve_old"

[oauth.registrations.google.permission_profiles.mail]
scopes = ["openid", "https://www.googleapis.com/auth/gmail.modify"]
audience = "https://gmail.googleapis.com/"
target = "me"

[oauth.registrations.google.login_binding]
provider = "microsoft"
upstream_identity_provider = "{ENTRA}"
upstream_tenant_id = "{TENANT}"
"#
    );
    assert_eq!(
        binding_errors(&google),
        [
            "oauth.registrations.google.login_binding is not supported by the google dialect, which reports no linked identities to check"
        ]
    );
}
