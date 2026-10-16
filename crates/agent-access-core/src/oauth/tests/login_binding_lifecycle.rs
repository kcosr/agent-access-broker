//! `login_binding` through the manager's consent lifecycle, with a fixture
//! dialect that reports the stub account's linked identities: the owner
//! check at consent start, the account check after the identity request and
//! again inside the install transaction, and the registration fingerprint.
use super::*;
use agent_access_provider::{LinkedIdentity, OAuthLoginBinding, OAuthLoginProvider};
use wiremock::{Request, Respond};

const TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const OTHER_TENANT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2";
const OBJECT_ID: &str = "cccccccc-cccc-4ccc-8ccc-ccccccccccc3";
const OTHER_OBJECT_ID: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee5";
const UPSTREAM_PROVIDER: &str = "azure_activedirectory_v2";

/// The `stub` dialect's wire, with an identity that also reports `/me`'s
/// `identities`, as a dialect supporting `login_binding` does.
struct LinkedIdentityDialect;
pub(in crate::oauth::tests) static LINKED_IDENTITY_DIALECT:
    agent_access_provider::OAuthDialectRegistration =
    agent_access_provider::OAuthDialectRegistration::new(
        agent_access_provider::module_metadata!(),
        "linked_identity_fixture",
        &LinkedIdentityDialect,
    )
    .development_only();

fn stub() -> &'static dyn OAuthDialect {
    STUB_OAUTH_DIALECT.dialect()
}

#[async_trait::async_trait]
impl OAuthDialect for LinkedIdentityDialect {
    fn supports_login_binding(&self) -> bool {
        true
    }
    fn validate_registration(&self, _config: &OAuthRegistrationConfig) -> Result<(), String> {
        Ok(())
    }
    fn upstream_allowlist(&self, config: &OAuthRegistrationConfig) -> Vec<String> {
        stub().upstream_allowlist(config)
    }
    fn authorization_url(
        &self,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        request: AuthorizationRequest<'_>,
    ) -> Result<Url, OAuthDialectError> {
        stub().authorization_url(client, profile, request)
    }
    fn callback_issuer(&self, config: &OAuthRegistrationConfig) -> OAuthCallbackIssuer {
        stub().callback_issuer(config)
    }
    fn refresh_replay(&self, config: &OAuthRegistrationConfig) -> RefreshReplay {
        stub().refresh_replay(config)
    }
    async fn exchange_code(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        exchange: CodeExchange<'_>,
    ) -> Result<TokenGrant, OAuthDialectError> {
        stub().exchange_code(http, client, exchange).await
    }
    async fn refresh(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        refresh_token: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<TokenGrant, OAuthDialectError> {
        stub()
            .refresh(http, client, profile, refresh_token, granted_scopes)
            .await
    }
    async fn identity(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        access_token: &str,
    ) -> Result<agent_access_provider::ConnectedIdentity, OAuthDialectError> {
        let url = Url::parse(&client.config.base_url)
            .and_then(|base| base.join("me"))
            .map_err(|_| OAuthDialectError::Configuration)?;
        let me = http
            .send(
                http.request(reqwest::Method::GET, url)
                    .bearer_auth(access_token),
                "oauth.identity",
            )
            .await?
            .json()
            .await?;
        let text = |value: &serde_json::Value, key: &str| value[key].as_str().map(str::to_owned);
        let linked = me["identities"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|identity| {
                Some(LinkedIdentity::new(
                    text(identity, "provider")?,
                    text(identity, "extern_uid")?,
                ))
            })
            .collect::<Vec<_>>();
        Ok(agent_access_provider::ConnectedIdentity::new(
            text(&me, "name").ok_or(OAuthDialectError::InvalidResponse)?,
        )
        .with_subject(text(&me, "id").ok_or(OAuthDialectError::InvalidResponse)?)
        .with_linked_identities(linked))
    }
    async fn discover_targets(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        access_token: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<Vec<OAuthTarget>, OAuthDialectError> {
        stub()
            .discover_targets(http, client, access_token, granted_scopes)
            .await
    }
}

fn login() -> OAuthLoginBinding {
    OAuthLoginBinding {
        provider: OAuthLoginProvider::Microsoft,
        upstream_identity_provider: UPSTREAM_PROVIDER.into(),
        upstream_tenant_id: TENANT.into(),
    }
}

/// The lifecycle tests' `stub` registration, speaking the linked-identity
/// fixture dialect with `login`.
fn linked_config(
    server: &MockServer,
    secret_file: &std::path::Path,
    login: Option<OAuthLoginBinding>,
) -> OAuthConfig {
    let mut config = config(server, secret_file);
    let registration = config.registrations.get_mut("stub").unwrap();
    registration.adapter = OAuthAdapter::new("linked_identity_fixture");
    registration.login_binding = login;
    config
}

async fn linked_fixture(
    login: Option<OAuthLoginBinding>,
) -> (
    tempfile::TempDir,
    ManagedStore,
    CredentialKeyRing,
    OAuthManager,
    MockServer,
) {
    let (dir, store, ring) = test_fixture();
    let server = MockServer::start().await;
    let secret_file = dir.path().join("client-secret");
    std::fs::write(&secret_file, "application-secret").unwrap();
    let manager = stub_manager(
        store.clone(),
        ring.clone(),
        linked_config(&server, &secret_file, login),
    )
    .unwrap();
    manager.activate().unwrap();
    (dir, store, ring, manager, server)
}

/// Links `user` to the Microsoft sign-in `subject` with `status`.
fn link(store: &ManagedStore, subject: &str, status: &str) {
    test_sql(
        store,
        &format!(
            "DELETE FROM principal_login_methods WHERE login_method_id='microsoft';
             INSERT INTO principal_login_methods(login_method_id,principal_id,method,external_provider,external_subject,status,created_at,updated_at,created_by,updated_by)
             VALUES('microsoft','user','oidc','microsoft','{subject}','{status}','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','admin','admin');"
        ),
    );
}

fn entra(tenant: &str, object_id: &str) -> String {
    format!("entra:v1:{tenant}:{object_id}")
}

fn targets() -> serde_json::Value {
    serde_json::json!({"targets":[{"id":"workspace-one","name":"One","audience":"records-api","scopes":["records.read"]}]})
}

/// The stub authorization server answering the code exchange, and `/me`
/// reporting `identities`.
async fn mount_account(server: &MockServer, identities: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token(0)))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"id":"alice","name":"Alice","identities":identities}),
        ))
        .mount(server)
        .await;
}

/// Answers target discovery after running `between`, which lands between
/// the check after the identity request and the install transaction.
struct DiscoverAfter<F>(F);
impl<F: Fn() + Send + Sync + 'static> Respond for DiscoverAfter<F> {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        (self.0)();
        ResponseTemplate::new(200).set_body_json(targets())
    }
}

async fn complete(manager: &OAuthManager, state: &str) -> Result<OAuthConnection, OAuthError> {
    manager
        .complete(
            "user",
            "session",
            "stub",
            state,
            "one-use-code",
            runtime(manager),
        )
        .await
}

async fn requested(server: &MockServer, route: &str) -> bool {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .any(|request| request.url.path() == route)
}

/// Whether `user` has neither a pending consent nor a connection.
fn nothing_pending(manager: &OAuthManager) -> bool {
    match manager.read("user", "stub") {
        Ok(slot) => slot.flows.is_empty() && slot.connection.is_none(),
        Err(OAuthError::ReconnectRequired) => true,
        Err(error) => panic!("{error:?}"),
    }
}

fn matching() -> serde_json::Value {
    serde_json::json!([{"provider":UPSTREAM_PROVIDER,"extern_uid":OBJECT_ID}])
}

#[tokio::test]
async fn consent_needs_an_active_microsoft_sign_in_in_the_bound_tenant() {
    let (_dir, store, _ring, manager, server) = linked_fixture(Some(login())).await;
    let binding = binding();
    let attempt = || {
        manager.connect(
            "user",
            "session",
            &binding,
            OAuthConnectIntent::Connect,
            admission(),
            runtime(&manager),
        )
    };
    // No Microsoft sign-in, one in another tenant, and a disabled one.
    for linked in [
        None,
        Some((entra(OTHER_TENANT, OBJECT_ID), "active")),
        Some((entra(TENANT, OBJECT_ID), "disabled")),
    ] {
        if let Some((subject, status)) = &linked {
            link(&store, subject, status);
        }
        assert_eq!(
            manager.check_login_binding("user", "stub"),
            Err(OAuthError::LoginBindingRequired),
            "{linked:?}"
        );
        assert_eq!(
            attempt().await.err(),
            Some(OAuthError::LoginBindingRequired),
            "{linked:?}"
        );
        assert!(nothing_pending(&manager));
    }
    // The local-password session does not matter: the linked sign-in does.
    link(&store, &entra(TENANT, OBJECT_ID), "active");
    assert_eq!(manager.check_login_binding("user", "stub"), Ok(()));
    attempt().await.unwrap();
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn only_an_account_linked_to_the_owners_sign_in_is_installed() {
    let (_dir, store, _ring, manager, server) = linked_fixture(Some(login())).await;
    link(&store, &entra(TENANT, OBJECT_ID), "active");
    for identities in [
        serde_json::json!([]),
        serde_json::json!([{"provider":UPSTREAM_PROVIDER,"extern_uid":OTHER_OBJECT_ID}]),
        serde_json::json!([{"provider":"openid_connect","extern_uid":OBJECT_ID}]),
    ] {
        server.reset().await;
        mount_account(&server, identities.clone()).await;
        Mock::given(method("GET"))
            .and(path("/targets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(targets()))
            .mount(&server)
            .await;
        let state = start(&manager, OAuthConnectIntent::Connect).await;
        assert_eq!(
            complete(&manager, &state).await.unwrap_err(),
            OAuthError::LoginBindingMismatch,
            "{identities}"
        );
        // Rejected before target discovery, and nothing is installed.
        assert!(!requested(&server, "/targets").await);
        assert!(nothing_pending(&manager));
    }
    server.reset().await;
    mount_account(&server, matching()).await;
    Mock::given(method("GET"))
        .and(path("/targets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(targets()))
        .mount(&server)
        .await;
    let state = start(&manager, OAuthConnectIntent::Connect).await;
    let connection = complete(&manager, &state).await.unwrap();
    assert_eq!(connection.subject_id.as_deref(), Some("alice"));
    assert_eq!(connection.status, OAuthConnectionStatus::Ready);
}

#[tokio::test]
async fn the_install_transaction_rechecks_the_owners_sign_in() {
    // The sign-in is unlinked, or relinked to another person, after the
    // check that follows the identity request.
    for (between, expected) in [
        (None, OAuthError::LoginBindingRequired),
        (
            Some(entra(TENANT, OTHER_OBJECT_ID)),
            OAuthError::LoginBindingMismatch,
        ),
    ] {
        let (_dir, store, _ring, manager, server) = linked_fixture(Some(login())).await;
        link(&store, &entra(TENANT, OBJECT_ID), "active");
        mount_account(&server, matching()).await;
        let changed = store.clone();
        Mock::given(method("GET"))
            .and(path("/targets"))
            .respond_with(DiscoverAfter(move || match &between {
                None => test_sql(
                    &changed,
                    "DELETE FROM principal_login_methods WHERE login_method_id='microsoft'",
                ),
                Some(subject) => link(&changed, subject, "active"),
            }))
            .mount(&server)
            .await;
        let state = start(&manager, OAuthConnectIntent::Connect).await;
        assert_eq!(complete(&manager, &state).await.unwrap_err(), expected);
        // The first check passed: discovery ran.
        assert!(requested(&server, "/targets").await);
        assert!(nothing_pending(&manager));
    }
}

#[tokio::test]
async fn enabling_login_binding_changes_the_fingerprint_and_drops_connections() {
    // Off by default: nothing is checked, and the owner needs no sign-in.
    let (dir, store, ring, unbound, server) = linked_fixture(None).await;
    assert_eq!(unbound.check_login_binding("user", "stub"), Ok(()));
    mount_account(&server, serde_json::json!([])).await;
    Mock::given(method("GET"))
        .and(path("/targets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(targets()))
        .mount(&server)
        .await;
    let state = start(&unbound, OAuthConnectIntent::Connect).await;
    complete(&unbound, &state).await.unwrap();
    assert!(
        unbound
            .status("user", "stub")
            .unwrap()
            .connection_id
            .is_some()
    );

    let secret_file = dir.path().join("client-secret");
    let unbound_config = linked_config(&server, &secret_file, None);
    let bound_config = linked_config(&server, &secret_file, Some(login()));
    let fingerprint =
        |config: &OAuthConfig| registration_fingerprint(&config.registrations["stub"]);
    assert_ne!(fingerprint(&unbound_config), fingerprint(&bound_config));
    let bound = stub_manager(store.clone(), ring.clone(), bound_config).unwrap();
    bound.activate().unwrap();
    let status = bound.status("user", "stub").unwrap();
    assert_eq!(status.status, OAuthConnectionStatus::Disconnected);
    assert!(status.connection_id.is_none());

    // So does a changed binding, such as another upstream provider name.
    let mut changed = login();
    changed.upstream_identity_provider = "openid_connect".into();
    assert_ne!(
        fingerprint(&bound.inner.config),
        fingerprint(&linked_config(&server, &secret_file, Some(changed)))
    );
}

#[tokio::test]
async fn login_binding_needs_a_dialect_that_reports_linked_identities() {
    let (dir, store, ring) = test_fixture();
    let server = MockServer::start().await;
    let secret_file = dir.path().join("client-secret");
    std::fs::write(&secret_file, "application-secret").unwrap();
    // The stub dialect reports no linked identities.
    let mut stub_bound = config(&server, &secret_file);
    stub_bound
        .registrations
        .get_mut("stub")
        .unwrap()
        .login_binding = Some(login());
    assert_eq!(
        stub_manager(store.clone(), ring.clone(), stub_bound).err(),
        Some(OAuthError::Configuration)
    );
    // Malformed binding values.
    for change in [
        |binding: &mut OAuthLoginBinding| binding.upstream_identity_provider.clear(),
        |binding: &mut OAuthLoginBinding| binding.upstream_tenant_id = TENANT.to_uppercase(),
    ] {
        let mut binding = login();
        change(&mut binding);
        let config = linked_config(&server, &secret_file, Some(binding));
        assert_eq!(config.validate(), Err(OAuthError::Configuration));
    }
    assert!(
        linked_config(&server, &secret_file, Some(login()))
            .validate()
            .is_ok()
    );
}
