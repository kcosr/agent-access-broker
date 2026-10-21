//! Microsoft membership renewal end to end (design §8 and §9.3), against the
//! fake Microsoft provider's refresh-token grant: every entry point that
//! resolves a person's identity renews expired evidence once and succeeds
//! through a group-derived grant; evidence inside the renewal window renews
//! speculatively; concurrent requests share one redemption; attempts keep
//! their durable interval and the provider throttle; every classification
//! writes its row state and audit record; waiters check their identity
//! again; shutdown drains or reports renewals; and neither logs nor audit
//! records carry tokens, raw bodies or `error_description`.
use super::mcp::{rpc_body, structured};
use super::microsoft_oidc::{
    CLIENT_SECRET, FakeBody, FakeGroupClaims, FakeMicrosoftOidcProvider, FakeRefresh,
    FakeTokenClaims, GROUP_ID, TENANT_ID, TestClock, session_cookie,
};
use super::*;
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    ExternalGroupBindingCreateRequest, GroupWriteRequest, ManagedStore, ManagedStoreConfig,
    ManagedStoreOpenMode, MicrosoftOidcConfig, OidcMembershipRenewalEndedReason,
    OidcMembershipRenewalFailureCode, OidcMembershipRenewalRecord, OidcMembershipRenewalState,
    TrustedCallerConfig, TrustedCallerContextMode, TrustedCallerCredentialTransport,
};
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

const RELAY: &str = "synthetic-renewal-relay-0123456789";
const CALLER: &str = "x-agent-access-caller-authorization";
const FINGERPRINT: &str = "x-aw-identity-token-sha256";
const UPLOAD_PACK_REFS: &str = "/sip/service.git/info/refs?service=git-upload-pack";
const RENEWED: &str = "oidc.membership.renewed";
const RENEWAL_FAILED: &str = "oidc.membership.renewal_failed";
const LONG_AGO: &str = "2000-01-01T00:00:00Z";
const LONG_AGO_START: &str = "1999-12-31T16:00:00Z";
const OTHER_USER_OBJECT_ID: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee5";

fn real_now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// One person signed in with renewal, with an agent token, a browser session
/// and an identity token, and group-derived grants on the fake service and
/// a Git repository.
struct Fixture {
    broker: TestBroker,
    app: Router,
    gateway: Router,
    provider: FakeMicrosoftOidcProvider,
    clock: TestClock,
    store: ManagedStore,
    store_path: PathBuf,
    audit_path: PathBuf,
    config: BrokerConfig,
    hasher: BrokerTokenHasher,
    person: Person,
}

/// A signed-in person's credentials.
struct Person {
    principal: String,
    method: String,
    agent_token: String,
    agent_token_id: String,
    cookie: String,
    fingerprint: String,
}

async fn fixture() -> Fixture {
    fixture_with(Duration::from_secs(30)).await
}

async fn fixture_with(shutdown_timeout: Duration) -> Fixture {
    fixture_configured(shutdown_timeout, |_| {}).await
}

/// The fixture, with `edit` applied to its configuration and the person's
/// evidence expired. The provider's clock starts at the Broker's and only
/// moves forward; a renewal's token is issued at the provider's clock.
async fn fixture_configured(
    shutdown_timeout: Duration,
    edit: impl FnOnce(&mut BrokerConfig),
) -> Fixture {
    let store_path = temp_path("membership-renewal.sqlite");
    let audit_path = temp_path("membership-renewal.audit.jsonl");
    let secret = |name: &str, value: String| {
        let path = temp_path(name);
        std::fs::write(&path, value).unwrap();
        format!("file:{}", path.display())
    };
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity = IdentityConfig {
        trusted_callers: BTreeMap::from([(
            "relay".to_string(),
            TrustedCallerConfig {
                credential_ref: secret("renewal-relay", RELAY.to_string()),
                credential_transport: TrustedCallerCredentialTransport::CallerAuthorization,
                username_namespace: None,
                context_mode: TrustedCallerContextMode::Fixed,
                execution_context: Some("default".into()),
                allowed_execution_contexts: None,
                allow_forwarded_identity: true,
            },
        )]),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: true,
        auto_migrate: true,
    });
    config.management.enabled = true;
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: secret(
            "renewal-broker-hash-key",
            URL_SAFE_NO_PAD.encode([31_u8; 32]),
        ),
        ..BrokerTokensConfig::default()
    });
    config.browser_auth.enabled = true;
    config.browser_auth.public_origin = Some("https://broker.example.test".to_string());
    config.browser_auth.session_cookie_name = "aab_session".to_string();
    config.browser_auth.session_ttl = "24h".to_string();
    config.browser_auth.csrf_key_ref = Some(secret(
        "renewal-csrf-key",
        URL_SAFE_NO_PAD.encode([32_u8; 32]),
    ));
    config.browser_auth.allowed_return_paths = vec!["/ui".to_string()];
    config.browser_auth.local_password.enabled = true;
    config.browser_auth.local_password.pepper_ref = Some(secret(
        "renewal-password-pepper",
        URL_SAFE_NO_PAD.encode([34_u8; 32]),
    ));
    config.browser_auth.oidc.microsoft = MicrosoftOidcConfig {
        enabled: true,
        tenant_id: Some(TENANT_ID.to_string()),
        client_id: Some(super::microsoft_oidc::CLIENT_ID.to_string()),
        client_secret_ref: Some(secret("renewal-client-secret", CLIENT_SECRET.to_string())),
        flow_key_ref: Some(secret(
            "renewal-flow-key",
            URL_SAFE_NO_PAD.encode([33_u8; 32]),
        )),
        flow_ttl: "10m".to_string(),
        max_pending_flows: 100,
        jit_provisioning: true,
        external_membership_ttl: "8h".to_string(),
        membership_renewal: true,
    };
    // Twenty concurrent requests of one person must be admitted.
    config.limits.max_concurrent_requests_per_principal = 64;
    // Reloads check credential readiness: the fake's token is a file.
    config
        .credentials
        .service
        .get_mut("fake")
        .unwrap()
        .token_ref = Some(secret(
        "renewal-fake-service-token",
        "synthetic-fake-service-token".to_string(),
    ));
    config.mcp.enabled = true;
    config.mcp.public_url = Some("https://broker.example.test/mcp".into());
    config.mcp.max_sessions_per_principal = 64;
    config.policy.grants = vec![
        PolicyGrantConfig {
            subjects: vec!["group:microsoft-users".to_string()],
            execution_contexts: None,
            service: "fake".to_string(),
            actions: vec!["echo".to_string()],
            resources: selected_resources(&[("project", &["TEST"])]),
            credential_mode: "service".to_string(),
            priority: None,
        },
        PolicyGrantConfig {
            subjects: vec!["group:microsoft-users".to_string()],
            execution_contexts: None,
            service: "gitlab_git".to_string(),
            actions: vec!["repo.fetch".to_string()],
            resources: selected_resources(&[("repository", &["sip/service"])]),
            credential_mode: "service".to_string(),
            priority: None,
        },
    ];
    let mut gateway = test_git_gateway_config();
    gateway.allow_forwarded_identity = true;
    config.gateways.insert("gitlab_git".into(), gateway);
    config.credentials.service.insert(
        "gitlab_git".into(),
        CredentialConfig {
            kind: "bearer_token".into(),
            token_ref: Some(secret(
                "renewal-git-upstream-token",
                "synthetic-git-upstream-token".to_string(),
            )),
            username_ref: None,
            provider: None,
            path: None,
            read_only: None,
            connection: None,
        },
    );
    edit(&mut config);

    let store = ManagedStore::open(
        config.managed_store.as_ref().unwrap(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_group(GroupWriteRequest {
            group_id: "microsoft-users".to_string(),
            display_name: None,
            description: None,
            auto_enroll_new_microsoft_users: false,
            created_by: "test".to_string(),
        })
        .unwrap();
    store
        .create_external_group_binding(ExternalGroupBindingCreateRequest {
            external_group_id: GROUP_ID.to_string(),
            group_id: "microsoft-users".to_string(),
            actor: "test".to_string(),
        })
        .unwrap();

    let clock = TestClock::new(real_now());
    let provider = FakeMicrosoftOidcProvider::new(clock.clone());
    let broker = TestBroker::start_with(
        TestBroker::config_builder(&config)
            .gateway_listener()
            .unwrap()
            .shutdown_timeout(shutdown_timeout)
            .microsoft_oidc_components(Arc::new(provider.clone()), Arc::new(clock.clone())),
    )
    .await;
    let hasher = BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let mut fixture = Fixture {
        app: broker.app(),
        gateway: broker.gateway_app(),
        broker,
        provider,
        clock,
        store,
        store_path,
        audit_path,
        config,
        hasher,
        person: Person {
            principal: String::new(),
            method: String::new(),
            agent_token: String::new(),
            agent_token_id: String::new(),
            cookie: String::new(),
            fingerprint: String::new(),
        },
    };
    fixture.person = fixture
        .sign_in_person(FakeTokenClaims::valid(fixture.clock.now_timestamp()))
        .await;
    fixture.expire(&fixture.person.method);
    fixture
}

impl Fixture {
    /// Signs in a person with `claims`, and issues them an agent token.
    async fn sign_in_person(&self, claims: FakeTokenClaims) -> Person {
        let external_subject = format!("entra:v1:{TENANT_ID}:{}", claims.user_object_id);
        let response = self.sign_in(claims, "renewal-sign-in").await;
        let cookie = session_cookie(&response).expect("signed in");
        let principal = self
            .store
            .list_principals()
            .unwrap()
            .into_iter()
            .find(|principal| {
                self.store
                    .list_login_methods(&principal.principal_id)
                    .unwrap()
                    .iter()
                    .any(|method| method.external_subject.as_deref() == Some(&external_subject))
            })
            .unwrap()
            .principal_id;
        let method = self
            .store
            .list_login_methods(&principal)
            .unwrap()
            .into_iter()
            .find(|method| method.method == "oidc")
            .unwrap()
            .login_method_id;
        let issued = self
            .store
            .issue_broker_token(
                &self.hasher,
                BrokerTokenIssueRequest {
                    principal_id: principal.clone(),
                    name: "renewal-agent".into(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({"allowedExecutionContexts": ["default"]}),
                    expires_at: None,
                    created_by: "test".into(),
                },
            )
            .unwrap();
        let ring = self.broker.runtime().credential_key_ring().unwrap().clone();
        let secret = self.store.reveal_identity_token(&principal, &ring).unwrap();
        Person {
            principal,
            method,
            agent_token: issued.token,
            agent_token_id: issued.record.token_id,
            cookie,
            fingerprint: format!("sha256:{:x}", Sha256::digest(secret.as_bytes())),
        }
    }

    /// A complete Microsoft sign-in with `claims`.
    async fn sign_in(&self, claims: FakeTokenClaims, request_id: &str) -> axum::response::Response {
        self.provider.set_next_claims(claims);
        let start = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v1/auth/oidc/microsoft/start?returnTo=%2Fui%2Fsettings")
                    .extension(ConnectInfo(
                        "127.0.0.1:43510".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(REQUEST_ID_HEADER, request_id)
                    .header("Host", "broker.example.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start.status(), StatusCode::SEE_OTHER);
        let location = start.headers()[LOCATION].to_str().unwrap().to_string();
        let binding = start
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .find_map(|value| {
                let value = value.to_str().ok()?;
                value
                    .starts_with("__Host-aab_oidc_binding=")
                    .then(|| value.split(';').next().unwrap().to_string())
            })
            .unwrap();
        let callback = url::Url::parse(&self.provider.authorize(&location).unwrap()).unwrap();
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("{}?{}", callback.path(), callback.query().unwrap()))
                    .extension(ConnectInfo(
                        "127.0.0.1:43511".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(REQUEST_ID_HEADER, request_id)
                    .header("Host", "broker.example.test")
                    .header(COOKIE, binding)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[LOCATION],
            "/ui/settings",
            "sign-in failed"
        );
        response
    }

    /// Runs `statements` on the managed store, as an operator's SQL would.
    fn sql(&self, statements: &str) {
        rusqlite::Connection::open(&self.store_path)
            .unwrap()
            .execute_batch(statements)
            .unwrap();
    }

    /// Expires `method`'s evidence and makes its row due for an attempt.
    fn expire(&self, method: &str) {
        self.expire_evidence(method);
        self.make_due(method);
    }

    /// Expires `method`'s evidence only; the row's attempt state stays.
    fn expire_evidence(&self, method: &str) {
        self.sql(&format!(
            "UPDATE oidc_membership_refresh_state
               SET evidence_at = '{LONG_AGO_START}', valid_until = '{LONG_AGO}'
               WHERE login_method_id = '{method}';
             UPDATE external_principal_groups
               SET evidence_at = '{LONG_AGO_START}', valid_until = '{LONG_AGO}'
               WHERE login_method_id = '{method}';"
        ));
    }

    /// Clears `method`'s backoff and attempt interval; the stored token stays.
    fn make_due(&self, method: &str) {
        self.sql(&format!(
            "UPDATE oidc_membership_renewals SET state = 'active', last_failure_code = NULL,
               last_failure_at = NULL, next_attempt_after = NULL, last_attempt_at = NULL
             WHERE login_method_id = '{method}' AND state <> 'ended'"
        ));
    }

    /// Puts `method`'s evidence `seconds` from expiry by the provider's clock.
    fn expires_in(&self, method: &str, seconds: i64) {
        let at = |timestamp: i64| {
            chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, 0)
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        };
        let until = at(self.clock.now_timestamp() + seconds);
        let since = at(self.clock.now_timestamp() + seconds - 8 * 3600);
        self.sql(&format!(
            "UPDATE oidc_membership_refresh_state
               SET evidence_at = '{since}', observed_at = '{since}', valid_until = '{until}'
               WHERE login_method_id = '{method}';
             UPDATE external_principal_groups
               SET evidence_at = '{since}', observed_at = '{since}', valid_until = '{until}'
               WHERE login_method_id = '{method}';"
        ));
        self.make_due(method);
    }

    fn renewal(&self, method: &str) -> Option<OidcMembershipRenewalRecord> {
        self.store.oidc_membership_renewal(method).unwrap()
    }

    fn valid_until(&self, method: &str) -> String {
        rusqlite::Connection::open(&self.store_path)
            .unwrap()
            .query_row(
                "SELECT valid_until FROM oidc_membership_refresh_state WHERE login_method_id = ?1",
                [method],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn state(&self) -> Arc<crate::state::ReloadableState> {
        self.broker.state()
    }

    /// Audit records of `action`.
    fn audits(&self, action: &str) -> Vec<Value> {
        read_audit_records(&self.audit_path)
            .into_iter()
            .filter(|record| record["action"] == action)
            .collect()
    }

    /// The renewal audit record of request `request_id`.
    fn renewal_audit(&self, request_id: &str) -> Value {
        let records = read_audit_records(&self.audit_path)
            .into_iter()
            .filter(|record| {
                (record["action"] == RENEWED || record["action"] == RENEWAL_FAILED)
                    && record["agentRequestId"] == request_id
            })
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 1, "{request_id}: {records:?}");
        records[0].clone()
    }

    async fn send(&self, app: &Router, request: Request<Body>) -> axum::response::Response {
        tokio::time::timeout(Duration::from_secs(60), app.clone().oneshot(request))
            .await
            .expect("request timed out")
            .unwrap()
    }

    fn request(&self, method: Method, uri: &str, request_id: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .extension(ConnectInfo(
                "127.0.0.1:43520".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, request_id)
            .header("Host", "broker.example.test")
    }

    /// An HTTP invoke of the fake echo with `credential` headers.
    async fn invoke_with(
        &self,
        credential: &[(&str, String)],
        request_id: &str,
    ) -> axum::response::Response {
        let mut builder = self
            .request(Method::POST, "/v1/invoke/fake/echo", request_id)
            .header(CONTENT_TYPE, "application/json");
        for (name, value) in credential {
            builder = builder.header(*name, value);
        }
        self.send(
            &self.app,
            builder
                .body(Body::from(
                    r#"{"inputs":{"project":"TEST","message":"renewal"}}"#,
                ))
                .unwrap(),
        )
        .await
    }

    fn bearer(person: &Person) -> Vec<(&'static str, String)> {
        vec![(
            AUTHORIZATION.as_str(),
            format!("Bearer {}", person.agent_token),
        )]
    }

    fn forwarded(person: &Person) -> Vec<(&'static str, String)> {
        vec![
            (CALLER, format!("Bearer {RELAY}")),
            (FINGERPRINT, person.fingerprint.clone()),
        ]
    }

    async fn invoke(&self, request_id: &str) -> axum::response::Response {
        self.invoke_with(&Self::bearer(&self.person), request_id)
            .await
    }

    /// The services the person's browser session discovers.
    async fn discover_with_cookie(&self, request_id: &str) -> axum::response::Response {
        self.send(
            &self.app,
            self.request(Method::GET, "/v1/services", request_id)
                .header(COOKIE, &self.person.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    /// A Git ref discovery through the gateway with `credential` headers.
    async fn git_fetch(
        &self,
        credential: &[(&str, String)],
        request_id: &str,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri(UPLOAD_PACK_REFS)
            .extension(ConnectInfo(
                "127.0.0.1:43530".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, request_id)
            .header("Host", "git.example.test");
        for (name, value) in credential {
            builder = builder.header(*name, value);
        }
        self.send(&self.gateway, builder.body(Body::empty()).unwrap())
            .await
    }

    fn git_basic(person: &Person) -> Vec<(&'static str, String)> {
        vec![(
            AUTHORIZATION.as_str(),
            format!(
                "Basic {}",
                BASE64.encode(format!("agent-access:{}", person.agent_token))
            ),
        )]
    }

    async fn mcp(
        &self,
        session: Option<&str>,
        message: Value,
        request_id: &str,
    ) -> axum::response::Response {
        let mut builder = self
            .request(Method::POST, "/mcp", request_id)
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {}", self.person.agent_token));
        if let Some(session) = session {
            builder = builder
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", "2025-11-25");
        }
        self.send(
            &self.app,
            builder.body(Body::from(message.to_string())).unwrap(),
        )
        .await
    }

    async fn mcp_session(&self) -> String {
        let response = self
            .mcp(
                None,
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"membership-renewal","version":"1"}
                }}),
                "renewal-mcp-initialize",
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let session = response.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let _ = rpc_body(response).await;
        let initialized = self
            .mcp(
                Some(&session),
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                "renewal-mcp-initialized",
            )
            .await;
        assert_eq!(initialized.status(), StatusCode::ACCEPTED);
        session
    }

    async fn mcp_rpc(&self, session: &str, method: &str, params: Value, request_id: &str) -> Value {
        let response = self
            .mcp(
                Some(session),
                json!({"jsonrpc":"2.0","id":2,"method":method,"params":params}),
                request_id,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{method}");
        rpc_body(response).await
    }
}

fn echo_tool() -> String {
    agent_access_core::mcp::tool_name("fake", "echo")
}

/// Reaching the deliberately blocked upstream proves that authentication
/// and the group-derived grant passed without a network request.
fn assert_git_allowed(response: &axum::response::Response, case: &str) {
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{case}");
    assert_eq!(
        response.headers()[agent_access_core::REASON_CODE_HEADER],
        "gateway_upstream_denied",
        "{case}"
    );
}

/// Expired evidence renews once on every entry point that resolves the
/// person's identity, and the request succeeds through the group-derived
/// grant; the audit shows one renewal each.
#[tokio::test]
async fn expired_evidence_renews_once_on_every_entry_point() {
    let f = fixture().await;
    let person = &f.person;
    // Without renewal the group grant is gone: the control case fails.
    f.provider.push_refresh(FakeRefresh::Status {
        status: 503,
        retry_after: None,
        body: FakeBody::Failed,
    });
    let denied = f.invoke("renewal-control").await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(f.provider.refresh_count(), 1);

    // MCP sessions are opened while the evidence is current.
    f.expire(&person.method);
    f.clock.advance_seconds(61);
    let session = f.mcp_session().await;
    let mut redemptions = f.provider.refresh_count();
    assert_eq!(redemptions, 2, "initialize renewed");

    for case in [
        "http-invoke",
        "http-invoke-forwarded",
        "mcp-tools-list",
        "mcp-tools-call",
        "git-basic",
        "git-forwarded",
        "cookie-discovery",
    ] {
        f.expire(&person.method);
        f.clock.advance_seconds(61);
        let before = f.valid_until(&person.method);
        let request_id = format!("renewal-{case}");
        match case {
            "http-invoke" => {
                let response = f.invoke(&request_id).await;
                assert_eq!(response.status(), StatusCode::OK, "{case}");
            }
            "http-invoke-forwarded" => {
                let response = f
                    .invoke_with(&Fixture::forwarded(person), &request_id)
                    .await;
                assert_eq!(response.status(), StatusCode::OK, "{case}");
            }
            "mcp-tools-list" => {
                let listing = f
                    .mcp_rpc(&session, "tools/list", json!({}), &request_id)
                    .await;
                let names = listing["result"]["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|tool| tool["name"].as_str().unwrap().to_owned())
                    .collect::<Vec<_>>();
                assert!(names.contains(&echo_tool()), "{case}: {listing}");
            }
            "mcp-tools-call" => {
                let called = f
                    .mcp_rpc(
                        &session,
                        "tools/call",
                        json!({"name": echo_tool(), "arguments": {"inputs": {"project": "TEST", "message": "renewal"}}}),
                        &request_id,
                    )
                    .await;
                assert_eq!(structured(&called)["decision"], "allow", "{case}: {called}");
            }
            "git-basic" => {
                let response = f.git_fetch(&Fixture::git_basic(person), &request_id).await;
                assert_git_allowed(&response, case);
            }
            "git-forwarded" => {
                let response = f.git_fetch(&Fixture::forwarded(person), &request_id).await;
                assert_git_allowed(&response, case);
            }
            "cookie-discovery" => {
                let response = f.discover_with_cookie(&request_id).await;
                assert_eq!(response.status(), StatusCode::OK, "{case}");
                let services = response_json(response).await;
                assert!(
                    services
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|service| service["service"] == "fake"),
                    "{case}: {services}"
                );
            }
            _ => unreachable!(),
        }
        redemptions += 1;
        assert_eq!(f.provider.refresh_count(), redemptions, "{case}");
        let audit = f.renewal_audit(&request_id);
        assert_eq!(audit["action"], RENEWED, "{case}");
        assert_eq!(audit["decision"], "allow", "{case}");
        assert_eq!(audit["principal"], person.principal.as_str(), "{case}");
        assert_eq!(audit["groups"], json!(["microsoft-users"]), "{case}");
        let details = &audit["providerAudit"]["oidc"];
        assert_eq!(details["trigger"], "expired", "{case}");
        assert_eq!(details["evidence"], "replaced", "{case}");
        assert_eq!(details["loginMethodId"], person.method.as_str(), "{case}");
        assert_eq!(details["effectiveGroupCount"], 1, "{case}");
        assert_eq!(details["policyGroups"], json!(["microsoft-users"]));
        assert_eq!(details["membershipChanged"], false, "{case}");
        assert_ne!(f.valid_until(&person.method), before, "{case}");
        let row = f.renewal(&person.method).unwrap();
        assert_eq!(row.state, OidcMembershipRenewalState::Active, "{case}");
        assert_eq!(row.failure_count, 0, "{case}");
        assert!(row.last_renewed_at.is_some(), "{case}");
    }
    // Every redemption asked for the sign-in scopes with the client secret.
    for form in f.provider.refresh_requests() {
        assert_eq!(form["scope"], "openid profile email offline_access");
        assert_eq!(form["grant_type"], "refresh_token");
    }
}

/// Waits until `condition` holds.
async fn eventually(what: &str, condition: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !condition() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn gate() -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(0))
}

fn status(status: u16, retry_after: Option<String>, body: FakeBody) -> FakeRefresh {
    FakeRefresh::Status {
        status,
        retry_after,
        body,
    }
}

fn error_body(error: &str) -> FakeBody {
    FakeBody::Json(json!({
        "error": error,
        "error_description": format!("AADSTS70008 SENTINEL-description-{error}"),
        "error_codes": [70008, 50173],
        "trace_id": "SENTINEL-trace",
    }))
}

fn token(
    adjust: impl FnOnce(&mut super::microsoft_oidc::FakeRefreshToken) + Send + 'static,
) -> FakeRefresh {
    FakeRefresh::Token(Box::new(adjust))
}

/// Evidence inside the renewal window renews speculatively: the request
/// proceeds at once with its current evidence while the renewal runs.
#[tokio::test]
async fn evidence_inside_the_window_renews_speculatively() {
    let f = fixture().await;
    let method = f.person.method.clone();
    f.clock.advance_seconds(61);
    f.expires_in(&method, 3600);
    let before = f.valid_until(&method);
    let gate = gate();
    f.provider
        .push_refresh(FakeRefresh::Gate(Arc::clone(&gate)));
    let response = f.invoke("renewal-ahead").await;
    assert_eq!(response.status(), StatusCode::OK);
    eventually("the redemption arrives", || {
        f.provider.refresh_arrivals() == 1
    })
    .await;
    // The request has finished; the renewal is still at Microsoft.
    assert_eq!(f.renewal(&method).unwrap().last_renewed_at, None);
    gate.add_permits(1);
    f.state().membership_renewals.wait_idle().await;
    let audit = f.renewal_audit("renewal-ahead");
    assert_eq!(audit["action"], RENEWED);
    assert_eq!(audit["providerAudit"]["oidc"]["trigger"], "ahead");
    assert!(f.valid_until(&method) > before);
    // The renewed evidence is outside the window: nothing more happens.
    let response = f.invoke("renewal-ahead-after").await;
    assert_eq!(response.status(), StatusCode::OK);
    f.state().membership_renewals.wait_idle().await;
    assert_eq!(f.provider.refresh_count(), 1);
}

/// Twenty simultaneous requests with expired evidence share one redemption
/// and all wait for it; a stale hint afterwards does not redeem again.
#[tokio::test]
async fn concurrent_expired_requests_share_one_redemption() {
    let f = fixture().await;
    let method = f.person.method.clone();
    f.clock.advance_seconds(61);
    f.expire(&method);
    let gate = gate();
    f.provider
        .push_refresh(FakeRefresh::Gate(Arc::clone(&gate)));
    let mut requests = tokio::task::JoinSet::new();
    for index in 0..20 {
        let app = f.app.clone();
        let token = f.person.agent_token.clone();
        requests.spawn(async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/v1/invoke/fake/echo")
                        .extension(ConnectInfo(
                            "127.0.0.1:43540".parse::<SocketAddr>().unwrap(),
                        ))
                        .header(REQUEST_ID_HEADER, format!("renewal-concurrent-{index}"))
                        .header(AUTHORIZATION, format!("Bearer {token}"))
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            r#"{"inputs":{"project":"TEST","message":"renewal"}}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            response.status()
        });
    }
    eventually("the redemption arrives", || {
        f.provider.refresh_arrivals() == 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Every request is still waiting for the one redemption.
    assert_eq!(requests.len(), 20);
    assert!(requests.try_join_next().is_none());
    gate.add_permits(1);
    while let Some(status) = requests.join_next().await {
        assert_eq!(status.unwrap(), StatusCode::OK);
    }
    assert_eq!(f.provider.refresh_arrivals(), 1);
    assert_eq!(f.audits(RENEWED).len(), 1);
    // A request whose hint still says expired after the renewal (here the
    // evidence is expired again within the attempt interval) does not
    // redeem again: the durable attempt start refuses.
    f.state().membership_renewals.wait_idle().await;
    f.expire_evidence(&method);
    let response = f.invoke("renewal-stale-hint").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(f.provider.refresh_arrivals(), 1);
}

/// Two attempts for one person are never less than 60 s apart, including
/// across a reload and across a sign-in.
#[tokio::test]
async fn attempts_keep_their_interval_across_reload_and_sign_in() {
    let f = fixture().await;
    let method = f.person.method.clone();
    f.clock.advance_seconds(61);
    f.expire(&method);
    f.provider
        .push_refresh(status(503, None, FakeBody::Raw(b"busy".to_vec())));
    assert_eq!(
        f.invoke("renewal-interval-first").await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.provider.refresh_count(), 1);
    let row = f.renewal(&method).unwrap();
    assert_eq!(row.state, OidcMembershipRenewalState::Retrying);
    let first_attempt = row.last_attempt_at.clone().unwrap();

    // Forty seconds later the backoff (30 s ± 20%) has passed, the interval
    // has not; a reload keeps the durable interval.
    f.clock.advance_seconds(40);
    f.store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::Admin,
            self_service_enabled: None,
            principal_id: "admin".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".into(),
        })
        .unwrap();
    f.broker.reload_config(&f.config).await;
    assert_eq!(
        f.invoke("renewal-interval-reload").await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.provider.refresh_arrivals(), 1);

    // A sign-in clears the backoff but keeps the attempt time.
    f.sign_in(
        FakeTokenClaims::valid(f.clock.now_timestamp()),
        "renewal-interval-sign-in",
    )
    .await;
    let signed_in = f.renewal(&method).unwrap();
    assert_eq!(signed_in.next_attempt_after, None);
    assert_eq!(
        signed_in.last_attempt_at.as_deref(),
        Some(first_attempt.as_str())
    );
    f.expire_evidence(&method);
    assert_eq!(
        f.invoke("renewal-interval-after-sign-in").await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.provider.refresh_arrivals(), 1);

    // Sixty seconds after the first attempt the next one redeems.
    f.clock.advance_seconds(21);
    assert_eq!(
        f.invoke("renewal-interval-due").await.status(),
        StatusCode::OK
    );
    assert_eq!(f.provider.refresh_arrivals(), 2);
    assert_eq!(f.renewal_audit("renewal-interval-due")["action"], RENEWED);
}

/// A 429 sets the process-wide throttle to `Retry-After`; a later, shorter
/// one never shortens it, and no flight starts while it lasts.
#[tokio::test]
async fn concurrent_throttles_never_shorten_the_provider_throttle() {
    let captured = super::install_trace_capture().start();
    let f = fixture().await;
    let mut claims = FakeTokenClaims::valid(f.clock.now_timestamp());
    claims.user_object_id = OTHER_USER_OBJECT_ID.to_string();
    claims.subject = "other-microsoft-subject".to_string();
    let other = f.sign_in_person(claims).await;
    f.clock.advance_seconds(61);
    f.expires_in(&f.person.method, 3600);
    f.expires_in(&other.method, 3600);
    let gate = gate();
    f.provider
        .push_refresh(FakeRefresh::Gate(Arc::clone(&gate)));
    f.provider
        .push_refresh(FakeRefresh::Gate(Arc::clone(&gate)));
    f.provider
        .push_refresh(status(429, Some("300".into()), FakeBody::Oversized));
    f.provider
        .push_refresh(status(429, Some("10".into()), FakeBody::Failed));
    assert_eq!(
        captured.run(f.invoke("renewal-throttle-a")).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        captured
            .run(f.invoke_with(&Fixture::bearer(&other), "renewal-throttle-b"))
            .await
            .status(),
        StatusCode::OK
    );
    eventually("both redemptions arrive", || {
        f.provider.refresh_arrivals() == 2
    })
    .await;
    let registry = &f.state().membership_renewals;
    gate.add_permits(1);
    eventually("the first throttle", || {
        registry.throttled_until().is_some()
    })
    .await;
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp(f.clock.now_timestamp(), 0).unwrap();
    assert_eq!(
        registry.throttled_until(),
        Some(now + chrono::Duration::seconds(300))
    );
    gate.add_permits(1);
    registry.wait_idle().await;
    assert_eq!(f.provider.refresh_count(), 2);
    assert_eq!(
        registry.throttled_until(),
        Some(now + chrono::Duration::seconds(300))
    );
    // Activation is logged once, at warn; the shorter 429 changed nothing.
    let events = captured.take_events();
    let throttled = events
        .iter()
        .filter(|event| event["event"] == "oidc_membership_renewal_throttled")
        .collect::<Vec<_>>();
    assert_eq!(throttled.len(), 1, "{throttled:?}");
    assert_eq!(throttled[0]["level"], "WARN");
    assert_eq!(
        throttled[0]["throttledUntil"],
        (now + chrono::Duration::seconds(300)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    for (method, request_id) in [
        (&f.person.method, "renewal-throttle-a"),
        (&other.method, "renewal-throttle-b"),
    ] {
        let row = f.renewal(method).unwrap();
        assert_eq!(row.state, OidcMembershipRenewalState::Retrying);
        assert_eq!(
            row.last_failure_code,
            Some(OidcMembershipRenewalFailureCode::Throttled)
        );
        let audit = f.renewal_audit(request_id);
        assert_eq!(audit["reasonCode"], "oidc_unavailable");
        assert_eq!(
            audit["providerAudit"]["oidc"]["classification"],
            "throttled"
        );
    }
    // While it lasts, no flight starts, even for a due person.
    f.clock.advance_seconds(200);
    f.expire(&f.person.method);
    assert_eq!(
        f.invoke("renewal-throttle-skipped").await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.provider.refresh_arrivals(), 2);
    // Once it passes, renewal resumes.
    f.clock.advance_seconds(101);
    assert_eq!(
        f.invoke("renewal-throttle-over").await.status(),
        StatusCode::OK
    );
    assert_eq!(f.provider.refresh_arrivals(), 3);
}

/// A classification case's scripted responses, given the provider's time.
type Script = Box<dyn Fn(i64) -> Vec<FakeRefresh>>;

/// What a classification case expects.
enum Expect {
    Renewed(&'static str),
    Failed(OidcMembershipRenewalFailureCode, &'static str),
    Ended(OidcMembershipRenewalEndedReason),
}

/// Every classification of design §8.6, against the fake provider: the row
/// state, the retry time and the audit record.
#[tokio::test]
async fn every_classification_writes_its_row_and_audit() {
    use OidcMembershipRenewalEndedReason as Ended;
    use OidcMembershipRenewalFailureCode as Code;
    let f = fixture().await;
    let method = f.person.method.clone();
    let date = |seconds: i64| {
        chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
            .unwrap()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string()
    };
    let cases: Vec<(&str, Script, Expect)> = vec![
        ("renewed", Box::new(|_| vec![]), Expect::Renewed("replaced")),
        (
            "unavailable-503",
            Box::new(|_| vec![status(503, None, FakeBody::Failed)]),
            Expect::Failed(Code::Unavailable, "oidc_unavailable"),
        ),
        (
            "no-response",
            Box::new(|_| vec![FakeRefresh::NoResponse]),
            Expect::Failed(Code::Unavailable, "oidc_unavailable"),
        ),
        (
            "server-error",
            Box::new(|_| vec![status(400, None, error_body("server_error"))]),
            Expect::Failed(Code::Unavailable, "oidc_unavailable"),
        ),
        (
            "temporarily-unavailable",
            Box::new(|_| vec![status(400, None, error_body("temporarily_unavailable"))]),
            Expect::Failed(Code::Unavailable, "oidc_unavailable"),
        ),
        (
            "throttled-seconds",
            Box::new(|_| {
                vec![status(
                    429,
                    Some("120".into()),
                    FakeBody::Raw(b"{\"error\":".to_vec()),
                )]
            }),
            Expect::Failed(Code::Throttled, "oidc_unavailable"),
        ),
        (
            "throttled-date-oversized",
            Box::new(move |now| vec![status(429, Some(date(now + 150)), FakeBody::Oversized)]),
            Expect::Failed(Code::Throttled, "oidc_unavailable"),
        ),
        (
            "throttled-truncated",
            Box::new(|_| vec![status(429, None, FakeBody::Failed)]),
            Expect::Failed(Code::Throttled, "oidc_unavailable"),
        ),
        (
            "invalid-client",
            Box::new(|_| vec![status(401, None, error_body("invalid_client"))]),
            Expect::Failed(Code::ClientRejected, "oidc_client_rejected"),
        ),
        (
            "unauthorized-client",
            Box::new(|_| vec![status(400, None, error_body("unauthorized_client"))]),
            Expect::Failed(Code::ClientRejected, "oidc_client_rejected"),
        ),
        (
            "invalid-scope",
            Box::new(|_| vec![status(400, None, error_body("invalid_scope"))]),
            Expect::Failed(Code::RequestRejected, "oidc_provider_denied"),
        ),
        (
            "empty-400",
            Box::new(|_| vec![status(400, None, FakeBody::Raw(Vec::new()))]),
            Expect::Failed(Code::RequestRejected, "oidc_provider_denied"),
        ),
        (
            "truncated-400",
            Box::new(|_| vec![status(400, None, FakeBody::Failed)]),
            Expect::Failed(Code::RequestRejected, "oidc_provider_denied"),
        ),
        (
            "non-json-403",
            Box::new(|_| {
                vec![status(
                    403,
                    None,
                    FakeBody::Raw(b"<html>SENTINEL</html>".to_vec()),
                )]
            }),
            Expect::Failed(Code::RequestRejected, "oidc_provider_denied"),
        ),
        (
            "redirect-302",
            Box::new(|_| vec![status(302, None, FakeBody::Raw(Vec::new()))]),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "ok-non-json",
            Box::new(|_| {
                vec![status(
                    200,
                    None,
                    FakeBody::Raw(b"SENTINEL not json".to_vec()),
                )]
            }),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "ok-truncated",
            Box::new(|_| vec![status(200, None, FakeBody::Failed)]),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "ok-oversized",
            Box::new(|_| vec![status(200, None, FakeBody::Oversized)]),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "no-id-token",
            Box::new(|_| vec![token(|token| token.omit_id_token = true)]),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "unsigned",
            Box::new(|_| vec![token(|token| token.claims.unsigned = true)]),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "wrong-kid",
            Box::new(|_| vec![token(|token| token.signing_key_id = "unknown-key".into())]),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "bad-signature",
            Box::new(|_| vec![token(|token| token.claims.corrupt_signature = true)]),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "aud-as-string",
            Box::new(|_| vec![token(|token| token.claims.audience_as_string = true)]),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "aud-added",
            Box::new(|_| {
                vec![token(|token| {
                    token.claims.audience.push("api://other".into());
                    token.claims.authorized_party = Some(super::microsoft_oidc::CLIENT_ID.into());
                })]
            }),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "azp-appears",
            Box::new(|_| {
                vec![token(|token| {
                    token.claims.authorized_party = Some(super::microsoft_oidc::CLIENT_ID.into())
                })]
            }),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "nonce-different",
            Box::new(|_| {
                vec![token(|token| {
                    token.claims.omit_nonce = false;
                    token.claims.nonce_override = Some("other-nonce".into());
                })]
            }),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "nonce-repeated",
            Box::new(|_| vec![token(|token| token.claims.omit_nonce = false)]),
            Expect::Renewed("replaced"),
        ),
        (
            "auth-time-appears",
            Box::new(|now| vec![token(move |token| token.claims.auth_time = Some(now - 100))]),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "unexpected-at-hash",
            Box::new(|_| {
                vec![token(|token| {
                    token.claims.at_hash = Some("AAAAAAAAAAAAAAAAAAAAAA".into())
                })]
            }),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "expired-token",
            Box::new(|now| vec![token(move |token| token.claims.expires_at = now - 600)]),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "stale-iat",
            Box::new(|now| {
                vec![token(move |token| {
                    token.claims.issued_at = now - 7 * 3600;
                    token.claims.not_before = Some(now - 7 * 3600);
                })]
            }),
            Expect::Failed(Code::InvalidResponse, "oidc_identity_invalid"),
        ),
        (
            "overage",
            Box::new(|_| {
                vec![token(|token| {
                    token.claims.groups = FakeGroupClaims::Overage
                })]
            }),
            Expect::Failed(Code::GroupsIncomplete, "oidc_group_claims_incomplete"),
        ),
        (
            "malformed-groups",
            Box::new(|_| {
                vec![token(|token| {
                    token.claims.groups = FakeGroupClaims::Malformed
                })]
            }),
            Expect::Failed(Code::GroupsIncomplete, "oidc_group_claims_incomplete"),
        ),
        (
            "renewed-without-rotation",
            Box::new(|_| vec![token(|token| token.refresh_token = None)]),
            Expect::Renewed("replaced"),
        ),
        (
            "renewed-oversized-rotation",
            Box::new(|_| {
                vec![token(|token| {
                    token.refresh_token = Some("r".repeat(16 * 1024 + 1))
                })]
            }),
            Expect::Renewed("replaced"),
        ),
        (
            "kept-newer",
            Box::new(|_| vec![]),
            Expect::Renewed("kept_newer"),
        ),
        (
            "changed-sub",
            Box::new(|_| vec![token(|token| token.claims.subject = "other-subject".into())]),
            Expect::Ended(Ended::IdentityMismatch),
        ),
        (
            "changed-oid",
            Box::new(|_| {
                vec![token(|token| {
                    token.claims.user_object_id = OTHER_USER_OBJECT_ID.into()
                })]
            }),
            Expect::Ended(Ended::IdentityMismatch),
        ),
        (
            "invalid-grant",
            Box::new(|_| vec![status(400, None, error_body("invalid_grant"))]),
            Expect::Ended(Ended::SignInRequired),
        ),
        (
            "interaction-required",
            Box::new(|_| vec![status(400, None, error_body("interaction_required"))]),
            Expect::Ended(Ended::SignInRequired),
        ),
        (
            "consent-required",
            Box::new(|_| vec![status(400, None, error_body("consent_required"))]),
            Expect::Ended(Ended::SignInRequired),
        ),
        (
            "login-required",
            Box::new(|_| vec![status(400, None, error_body("login_required"))]),
            Expect::Ended(Ended::SignInRequired),
        ),
    ];
    let mut redemptions = 0;
    for (case, script, expect) in cases {
        // Beyond any throttle or backoff of the previous case.
        f.clock.advance_seconds(301);
        if f.renewal(&method).unwrap().state == OidcMembershipRenewalState::Ended {
            f.sign_in(
                FakeTokenClaims::valid(f.clock.now_timestamp()),
                &format!("renewal-case-sign-in-{case}"),
            )
            .await;
            f.clock.advance_seconds(1);
        }
        f.expire(&method);
        match case {
            "stale-iat" => f.sql(&format!(
                "UPDATE oidc_membership_renewals SET observation_iat = 0
                 WHERE login_method_id = '{method}'"
            )),
            "kept-newer" => f.sql(&format!(
                "UPDATE oidc_membership_renewals SET observation_iat = {}
                 WHERE login_method_id = '{method}'",
                f.clock.now_timestamp() + 1000
            )),
            _ => {}
        }
        let now = f.clock.now_timestamp();
        for response in script(now) {
            f.provider.push_refresh(response);
        }
        let before = f.renewal(&method).unwrap();
        let before_material = f
            .store
            .oidc_membership_renewal_material(
                f.broker.runtime().credential_key_ring().unwrap(),
                &method,
            )
            .unwrap()
            .unwrap();
        let request_id = format!("renewal-case-{case}");
        let response = f.invoke(&request_id).await;
        redemptions += 1;
        assert_eq!(f.provider.refresh_arrivals(), redemptions, "{case}");
        let row = f.renewal(&method).unwrap();
        let audit = f.renewal_audit(&request_id);
        let details = &audit["providerAudit"]["oidc"];
        assert_eq!(details["loginMethodId"], method.as_str(), "{case}");
        assert_eq!(details["trigger"], "expired", "{case}");
        let material = f
            .store
            .oidc_membership_renewal_material(
                f.broker.runtime().credential_key_ring().unwrap(),
                &method,
            )
            .unwrap();
        match expect {
            Expect::Renewed(evidence) => {
                let expected = if evidence == "kept_newer" {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::OK
                };
                assert_eq!(response.status(), expected, "{case}");
                assert_eq!(audit["action"], RENEWED, "{case}");
                assert_eq!(audit["decision"], "allow", "{case}");
                assert_eq!(details["evidence"], evidence, "{case}");
                assert_eq!(row.state, OidcMembershipRenewalState::Active, "{case}");
                assert_eq!(row.failure_count, 0, "{case}");
                let rotated = !matches!(
                    case,
                    "renewed-without-rotation" | "renewed-oversized-rotation"
                );
                assert_eq!(row.token_version != before.token_version, rotated, "{case}");
                assert_eq!(
                    material.unwrap().refresh_token() != before_material.refresh_token(),
                    rotated,
                    "{case}"
                );
            }
            Expect::Failed(code, reason) => {
                assert_eq!(response.status(), StatusCode::FORBIDDEN, "{case}");
                assert_eq!(audit["action"], RENEWAL_FAILED, "{case}");
                assert_eq!(audit["decision"], "deny", "{case}");
                assert_eq!(audit["reasonCode"], reason, "{case}");
                assert_eq!(details["classification"], code.as_str(), "{case}");
                assert_eq!(row.last_failure_code, Some(code), "{case}");
                let state = match code {
                    Code::Throttled | Code::Unavailable => OidcMembershipRenewalState::Retrying,
                    _ => OidcMembershipRenewalState::Blocked,
                };
                assert_eq!(row.state, state, "{case}");
                let next = row.next_attempt_after.clone().unwrap();
                assert_eq!(details["nextAttemptAfter"], next.as_str(), "{case}");
                let next = chrono::DateTime::parse_from_rfc3339(&next)
                    .unwrap()
                    .timestamp();
                match case {
                    "throttled-seconds" => assert!(next >= now + 120, "{case}"),
                    "throttled-date-oversized" => assert!(next >= now + 150, "{case}"),
                    _ if state == OidcMembershipRenewalState::Blocked => {
                        assert_eq!(next, now + 3600, "{case}")
                    }
                    _ => assert!(next > now, "{case}"),
                }
                // Only incomplete groups store the returned token.
                let rotated = code == Code::GroupsIncomplete;
                assert_eq!(row.token_version != before.token_version, rotated, "{case}");
                assert_eq!(
                    material.unwrap().refresh_token() != before_material.refresh_token(),
                    rotated,
                    "{case}"
                );
                // A trusted token raises the watermark; others do not.
                let raised = matches!(case, "stale-iat" | "overage" | "malformed-groups");
                assert_eq!(
                    row.observation_iat > before.observation_iat,
                    raised,
                    "{case}"
                );
            }
            Expect::Ended(reason) => {
                assert_eq!(response.status(), StatusCode::FORBIDDEN, "{case}");
                assert_eq!(audit["action"], RENEWAL_FAILED, "{case}");
                assert_eq!(audit["decision"], "deny", "{case}");
                let (classification, reason_code) = match reason {
                    Ended::SignInRequired => ("sign_in_required", "oidc_sign_in_required"),
                    _ => ("identity_mismatch", "oidc_identity_invalid"),
                };
                assert_eq!(audit["reasonCode"], reason_code, "{case}");
                assert_eq!(details["classification"], classification, "{case}");
                assert_eq!(details["nextAttemptAfter"], Value::Null, "{case}");
                assert_eq!(row.state, OidcMembershipRenewalState::Ended, "{case}");
                assert_eq!(row.ended_reason, Some(reason), "{case}");
                assert!(material.is_none(), "{case}");
                assert_eq!(row.observation_iat, before.observation_iat, "{case}");
            }
        }
        // An ended row no longer renews.
        if row.state == OidcMembershipRenewalState::Ended {
            f.clock.advance_seconds(61);
            assert_eq!(
                f.invoke(&format!("{request_id}-after")).await.status(),
                StatusCode::FORBIDDEN
            );
            assert_eq!(f.provider.refresh_arrivals(), redemptions, "{case}");
        }
    }
}

/// Starts `request` and waits until its renewal reaches the gated fake.
async fn while_redeeming<T: Send + 'static>(
    f: &Fixture,
    gate: &Arc<tokio::sync::Semaphore>,
    request: impl std::future::Future<Output = T> + Send + 'static,
) -> tokio::task::JoinHandle<T> {
    let arrivals = f.provider.refresh_arrivals();
    f.provider.push_refresh(FakeRefresh::Gate(Arc::clone(gate)));
    let handle = tokio::spawn(request);
    eventually("the redemption arrives", || {
        f.provider.refresh_arrivals() == arrivals + 1
    })
    .await;
    handle
}

fn invoke_request(
    app: &Router,
    credential: Vec<(&'static str, String)>,
    request_id: &str,
) -> impl std::future::Future<Output = axum::response::Response> + Send + 'static {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/v1/invoke/fake/echo")
        .extension(ConnectInfo(
            "127.0.0.1:43550".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, request_id)
        .header(CONTENT_TYPE, "application/json");
    for (name, value) in credential {
        builder = builder.header(name, value);
    }
    let request = builder
        .body(Body::from(
            r#"{"inputs":{"project":"TEST","message":"renewal"}}"#,
        ))
        .unwrap();
    let app = app.clone();
    async move { app.oneshot(request).await.unwrap() }
}

/// After a wait the entry point checks the identity once more: a Broker
/// token revoked meanwhile fails on HTTP and on Git, and an attested
/// identity whose controls changed meanwhile is rejected rather than
/// resolved afresh.
#[tokio::test]
async fn waiters_check_their_identity_again_after_the_wait() {
    let f = fixture().await;
    let method = f.person.method.clone();

    // A Broker token revoked during the wait.
    f.clock.advance_seconds(61);
    f.expire(&method);
    let gate = gate();
    let waiting = while_redeeming(
        &f,
        &gate,
        invoke_request(&f.app, Fixture::bearer(&f.person), "renewal-revoked"),
    )
    .await;
    f.store
        .revoke_broker_token(&f.person.agent_token_id, "admin")
        .unwrap();
    gate.add_permits(1);
    let response = waiting.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "broker_token_revoked"
    );
    // The renewal itself committed.
    assert_eq!(f.renewal_audit("renewal-revoked")["action"], RENEWED);

    // A Git Basic token revoked during the wait.
    let mut claims = FakeTokenClaims::valid(f.clock.now_timestamp());
    claims.user_object_id = OTHER_USER_OBJECT_ID.to_string();
    claims.subject = "other-microsoft-subject".to_string();
    let other = f.sign_in_person(claims).await;
    f.clock.advance_seconds(61);
    f.expire(&other.method);
    let gateway = f.gateway.clone();
    let basic = Fixture::git_basic(&other);
    let waiting = while_redeeming(&f, &gate, async move {
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri(UPLOAD_PACK_REFS)
            .extension(ConnectInfo(
                "127.0.0.1:43551".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, "renewal-git-revoked")
            .header("Host", "git.example.test");
        for (name, value) in basic {
            builder = builder.header(name, value);
        }
        gateway
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    })
    .await;
    f.store
        .revoke_broker_token(&other.agent_token_id, "admin")
        .unwrap();
    gate.add_permits(1);
    let response = waiting.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[agent_access_core::REASON_CODE_HEADER],
        "gateway_auth_invalid"
    );

    // An attested identity whose identity token settings changed during
    // the wait: its original proof no longer holds. A fresh resolution of
    // the same fingerprint would succeed (echo is a read), so a rejection
    // shows that the original proof was revalidated.
    f.clock.advance_seconds(61);
    f.expire(&method);
    let waiting = while_redeeming(
        &f,
        &gate,
        invoke_request(&f.app, Fixture::forwarded(&f.person), "renewal-attested"),
    )
    .await;
    let revision = f
        .store
        .identity_token_metadata(&f.person.principal)
        .unwrap()
        .revision;
    f.store
        .update_identity_token_settings(
            &f.person.principal,
            agent_access_core::IdentityTokenSettingsUpdate {
                enabled: None,
                read_only: Some(true),
            },
            revision,
        )
        .unwrap();
    gate.add_permits(1);
    let response = waiting.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // The same fingerprint resolves afresh now, with the new setting.
    let response = f
        .invoke_with(&Fixture::forwarded(&f.person), "renewal-attested-after")
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// A sign-in or unlink during an in-flight renewal wins, and a reload
/// discards the renewal's outcome; the waiting request then sees the
/// current state.
#[tokio::test]
async fn sign_in_reload_and_unlink_during_a_renewal_supersede_it() {
    let f = fixture().await;
    let method = f.person.method.clone();
    let gate = gate();

    // A sign-in during the redemption: its token version fences the renewal
    // out; the waiter proceeds with the sign-in's evidence.
    f.clock.advance_seconds(61);
    f.expire(&method);
    let waiting = while_redeeming(
        &f,
        &gate,
        invoke_request(&f.app, Fixture::bearer(&f.person), "renewal-vs-sign-in"),
    )
    .await;
    f.clock.advance_seconds(1);
    f.sign_in(
        FakeTokenClaims::valid(f.clock.now_timestamp()),
        "renewal-concurrent-sign-in",
    )
    .await;
    let signed_in = f.renewal(&method).unwrap();
    gate.add_permits(1);
    assert_eq!(waiting.await.unwrap().status(), StatusCode::OK);
    f.state().membership_renewals.wait_idle().await;
    assert_eq!(f.renewal(&method).unwrap(), signed_in);
    assert!(
        f.audits(RENEWED)
            .iter()
            .chain(f.audits(RENEWAL_FAILED).iter())
            .all(|record| record["agentRequestId"] != "renewal-vs-sign-in"),
        "a superseded renewal is not audited"
    );

    // A reload during the redemption discards the outcome.
    f.clock.advance_seconds(61);
    f.expire(&method);
    f.store
        .create_principal(agent_access_core::PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::Admin,
            self_service_enabled: None,
            principal_id: "admin".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".into(),
        })
        .unwrap();
    let waiting = while_redeeming(
        &f,
        &gate,
        invoke_request(&f.app, Fixture::bearer(&f.person), "renewal-vs-reload"),
    )
    .await;
    let attempted = f.renewal(&method).unwrap();
    f.broker.reload_config(&f.config).await;
    gate.add_permits(1);
    assert_eq!(waiting.await.unwrap().status(), StatusCode::FORBIDDEN);
    f.state().membership_renewals.wait_idle().await;
    assert_eq!(f.renewal(&method).unwrap(), attempted);
    assert_eq!(f.valid_until(&method), LONG_AGO);

    // An unlink during the redemption: the row is gone and stays gone.
    f.clock.advance_seconds(61);
    f.make_due(&method);
    let waiting = while_redeeming(
        &f,
        &gate,
        invoke_request(&f.app, Fixture::bearer(&f.person), "renewal-vs-unlink"),
    )
    .await;
    f.store
        .unlink_oidc_login_method(&f.person.principal, "admin")
        .unwrap();
    gate.add_permits(1);
    assert_eq!(waiting.await.unwrap().status(), StatusCode::FORBIDDEN);
    f.state().membership_renewals.wait_idle().await;
    assert!(f.renewal(&method).is_none());
}

/// A redemption slower than the request's wait: the request proceeds with
/// its expired evidence when its wait ends, the renewal keeps running, and
/// later requests see its result without another redemption.
#[tokio::test]
async fn a_renewal_slower_than_the_wait_keeps_running() {
    let f = fixture().await;
    let method = f.person.method.clone();
    *f.state().membership_renewals.test.wait.lock().unwrap() = Some(Duration::from_millis(300));
    f.clock.advance_seconds(61);
    f.expire(&method);
    let gate = gate();
    let waiting = while_redeeming(
        &f,
        &gate,
        invoke_request(&f.app, Fixture::bearer(&f.person), "renewal-slow"),
    )
    .await;
    let response = tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("the wait is bounded")
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    gate.add_permits(1);
    f.state().membership_renewals.wait_idle().await;
    assert_eq!(f.renewal_audit("renewal-slow")["action"], RENEWED);
    assert_eq!(
        f.invoke("renewal-slow-after").await.status(),
        StatusCode::OK
    );
    assert_eq!(f.provider.refresh_arrivals(), 1);
}

/// Graceful shutdown cancels a renewal still at Microsoft, which then
/// writes nothing beyond its attempt time.
#[tokio::test]
async fn shutdown_cancels_an_unsubmitted_renewal() {
    let f = fixture().await;
    let method = f.person.method.clone();
    f.clock.advance_seconds(61);
    f.expires_in(&method, 3600);
    let gate = gate();
    let waiting = while_redeeming(
        &f,
        &gate,
        invoke_request(
            &f.app,
            Fixture::bearer(&f.person),
            "renewal-shutdown-cancel",
        ),
    )
    .await;
    assert_eq!(waiting.await.unwrap().status(), StatusCode::OK);
    let attempted = f.renewal(&method).unwrap();
    assert!(attempted.last_attempt_at.is_some());
    let Fixture {
        broker,
        app,
        gateway,
        store,
        provider,
        audit_path,
        ..
    } = f;
    drop((app, gateway));
    let report = broker.stop().await;
    assert!(report.is_clean(), "{report:?}");
    assert_eq!(
        store.oidc_membership_renewal(&method).unwrap(),
        Some(attempted)
    );
    assert_eq!(provider.refresh_count(), 0);
    assert!(
        read_audit_records(&audit_path)
            .iter()
            .all(|record| record["action"] != RENEWED && record["action"] != RENEWAL_FAILED)
    );
}

/// Graceful shutdown waits for a submitted outcome write and its audit
/// append before the audit store closes.
#[tokio::test]
async fn graceful_shutdown_drains_a_submitted_renewal_and_its_audit() {
    let f = fixture().await;
    let method = f.person.method.clone();
    f.clock.advance_seconds(61);
    f.expires_in(&method, 3600);
    let barrier = Arc::new(crate::state::McpBlockingBarrier::default());
    *f.state()
        .membership_renewals
        .test
        .commit_gate
        .lock()
        .unwrap() = Some(Arc::clone(&barrier));
    assert_eq!(
        f.invoke("renewal-shutdown-drain").await.status(),
        StatusCode::OK
    );
    tokio::time::timeout(Duration::from_secs(30), barrier.reached.notified())
        .await
        .expect("the outcome write starts");
    let Fixture {
        broker,
        app,
        gateway,
        store,
        audit_path,
        ..
    } = f;
    drop((app, gateway));
    broker.running().shutdown();
    let release = Arc::clone(&barrier);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        release.release();
    });
    let report = broker.stop().await;
    assert!(report.is_clean(), "{report:?}");
    let row = store.oidc_membership_renewal(&method).unwrap().unwrap();
    assert!(row.last_renewed_at.is_some());
    let renewed = read_audit_records(&audit_path)
        .into_iter()
        .filter(|record| record["action"] == RENEWED)
        .collect::<Vec<_>>();
    assert_eq!(renewed.len(), 1);
    assert_eq!(renewed[0]["agentRequestId"], "renewal-shutdown-drain");
}

/// When the drain budget expires first, a submitted write still commits
/// (its state locks stay held until it returns) but is never audited; the
/// drain reports each unfinished renewal with its phase.
#[tokio::test]
async fn forced_shutdown_reports_a_renewal_that_may_be_unaudited() {
    let f = fixture_with(Duration::from_millis(500)).await;
    let method = f.person.method.clone();
    f.clock.advance_seconds(61);
    f.expires_in(&method, 3600);
    let barrier = Arc::new(crate::state::McpBlockingBarrier::default());
    *f.state()
        .membership_renewals
        .test
        .commit_gate
        .lock()
        .unwrap() = Some(Arc::clone(&barrier));
    assert_eq!(
        f.invoke("renewal-shutdown-forced").await.status(),
        StatusCode::OK
    );
    tokio::time::timeout(Duration::from_secs(30), barrier.reached.notified())
        .await
        .expect("the outcome write starts");
    let Fixture {
        broker,
        app,
        gateway,
        store,
        audit_path,
        ..
    } = f;
    drop((app, gateway));
    let release = Arc::clone(&barrier);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        release.release();
    });
    broker.stop().await;
    let row = store.oidc_membership_renewal(&method).unwrap().unwrap();
    assert!(
        row.last_renewed_at.is_some(),
        "the submitted write committed"
    );
    assert!(
        read_audit_records(&audit_path)
            .iter()
            .all(|record| record["action"] != RENEWED),
        "the audit store closed before the append"
    );
}

/// The drain logs one error per unfinished renewal, naming its login method
/// and phase.
#[tokio::test(flavor = "current_thread")]
async fn draining_logs_each_unfinished_renewal() {
    let captured = super::install_trace_capture().start();
    let f = fixture().await;
    let method = f.person.method.clone();
    f.clock.advance_seconds(61);
    f.expires_in(&method, 3600);
    let barrier = Arc::new(crate::state::McpBlockingBarrier::default());
    *f.state()
        .membership_renewals
        .test
        .commit_gate
        .lock()
        .unwrap() = Some(Arc::clone(&barrier));
    assert_eq!(
        captured.run(f.invoke("renewal-drain-log")).await.status(),
        StatusCode::OK
    );
    tokio::time::timeout(Duration::from_secs(30), barrier.reached.notified())
        .await
        .expect("the outcome write starts");
    let unfinished = captured
        .run(
            f.state()
                .membership_renewals
                .drain(Duration::from_millis(100)),
        )
        .await;
    assert_eq!(unfinished, [(method.clone(), "committing")]);
    let events = captured.take_events();
    let logged = events
        .iter()
        .filter(|event| event["event"] == "oidc_membership_renewal_unfinished")
        .collect::<Vec<_>>();
    assert_eq!(logged.len(), 1, "{events:?}");
    assert_eq!(logged[0]["level"], "ERROR");
    assert_eq!(logged[0]["loginMethodId"], method.as_str());
    assert_eq!(logged[0]["phase"], "committing");
    barrier.release();
    eventually("the write commits", || {
        f.renewal(&method).unwrap().last_renewed_at.is_some()
    })
    .await;
    f.state().membership_renewals.wait_idle().await;
}

/// Neither logs nor audit records carry tokens, raw response bodies,
/// `error_description` or the client secret; the renewal event carries the
/// allowlisted `error` and Microsoft's numeric codes.
#[tokio::test(flavor = "current_thread")]
async fn renewal_logs_and_audit_never_carry_tokens_or_microsoft_text() {
    let captured = super::install_trace_capture().start();
    let f = fixture().await;
    let method = f.person.method.clone();
    let mut cases = vec![
        ("renewal-sentinel-success", None),
        (
            "renewal-sentinel-raw",
            Some(status(
                500,
                None,
                FakeBody::Raw(b"SENTINEL raw body".to_vec()),
            )),
        ),
        (
            "renewal-sentinel-other",
            Some(status(
                400,
                None,
                FakeBody::Json(json!({
                    "error": "SENTINEL_unknown_error",
                    "error_description": "SENTINEL description",
                    "error_codes": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                })),
            )),
        ),
        (
            "renewal-sentinel-throttled",
            Some(status(
                429,
                Some("5".into()),
                error_body("temporarily_unavailable"),
            )),
        ),
        (
            "renewal-sentinel-server",
            Some(status(503, None, error_body("server_error"))),
        ),
        (
            "renewal-sentinel-grant",
            Some(status(400, None, error_body("invalid_grant"))),
        ),
    ];
    for (request_id, script) in cases.drain(..) {
        f.clock.advance_seconds(3601);
        f.expire(&method);
        if let Some(script) = script {
            f.provider.push_refresh(script);
        }
        captured.run(f.invoke(request_id)).await;
    }
    let events = captured.take_events();
    let renewals = events
        .iter()
        .filter(|event| event["event"] == "oidc_membership_renewal")
        .collect::<Vec<_>>();
    let by_outcome = |classification: &str| {
        renewals
            .iter()
            .find(|event| event["classification"] == classification)
            .unwrap_or_else(|| panic!("no {classification} event in {renewals:?}"))
    };
    let renewed = by_outcome("renewed");
    assert_eq!(renewed["outcome"], "renewed");
    assert_eq!(renewed["evidence"], "replaced");
    assert_eq!(renewed["httpStatus"], 200);
    assert_eq!(renewed["loginMethodId"], method.as_str());
    let unavailable = renewals
        .iter()
        .find(|event| event["httpStatus"] == 500)
        .unwrap();
    assert_eq!(unavailable["classification"], "unavailable");
    assert_eq!(unavailable["level"], "WARN");
    assert_eq!(unavailable["error"], "");
    // A 429 and a 5xx keep Microsoft's sanitized error and codes.
    let throttled = by_outcome("throttled");
    assert_eq!(throttled["httpStatus"], 429);
    assert_eq!(throttled["error"], "temporarily_unavailable");
    assert_eq!(throttled["errorCodes"], "[70008, 50173]");
    let server = renewals
        .iter()
        .find(|event| event["httpStatus"] == 503)
        .unwrap();
    assert_eq!(server["classification"], "unavailable");
    assert_eq!(server["error"], "server_error");
    assert_eq!(server["errorCodes"], "[70008, 50173]");
    let rejected = by_outcome("request_rejected");
    assert_eq!(rejected["error"], "other");
    assert_eq!(rejected["errorCodes"], "[1, 2, 3, 4, 5, 6, 7, 8]");
    let ended = by_outcome("sign_in_required");
    assert_eq!(ended["error"], "invalid_grant");
    assert_eq!(ended["errorCodes"], "[70008, 50173]");
    let logs = serde_json::to_string(&events).unwrap();
    let audit = std::fs::read_to_string(&f.audit_path).unwrap();
    let mut sentinels = vec![
        "SENTINEL".to_string(),
        CLIENT_SECRET.to_string(),
        "fake-refresh-token".to_string(),
        "fake-access-token".to_string(),
        "AADSTS".to_string(),
        "error_description".to_string(),
    ];
    sentinels.extend(f.provider.issued_refresh_tokens());
    for sentinel in &sentinels {
        assert!(!logs.contains(sentinel.as_str()), "logs carry {sentinel}");
        assert!(
            !audit.contains(sentinel.as_str()),
            "audit carries {sentinel}"
        );
    }
}

/// Membership changes Microsoft reports reach the Broker at the next
/// renewal, in both directions; the audit says the membership changed.
#[tokio::test]
async fn renewals_apply_membership_changes_microsoft_reports() {
    let f = fixture().await;
    let method = f.person.method.clone();
    f.provider.set_refresh_groups(FakeGroupClaims::Empty);
    f.clock.advance_seconds(61);
    f.expire(&method);
    assert_eq!(
        f.invoke("renewal-group-removed").await.status(),
        StatusCode::FORBIDDEN
    );
    let audit = f.renewal_audit("renewal-group-removed");
    assert_eq!(audit["action"], RENEWED);
    assert_eq!(audit["groups"], json!([]));
    assert_eq!(audit["providerAudit"]["oidc"]["membershipChanged"], true);
    assert_eq!(audit["providerAudit"]["oidc"]["effectiveGroupCount"], 0);
    // Removed groups stay removed while the evidence is current.
    assert_eq!(
        f.invoke("renewal-group-removed-after").await.status(),
        StatusCode::FORBIDDEN
    );

    f.provider
        .set_refresh_groups(FakeGroupClaims::Complete(vec![GROUP_ID.to_string()]));
    f.clock.advance_seconds(61);
    f.expire(&method);
    assert_eq!(
        f.invoke("renewal-group-added").await.status(),
        StatusCode::OK
    );
    let audit = f.renewal_audit("renewal-group-added");
    assert_eq!(audit["groups"], json!(["microsoft-users"]));
    assert_eq!(audit["providerAudit"]["oidc"]["membershipChanged"], true);
}

impl Fixture {
    /// An administrator's Broker token.
    fn admin_token(&self) -> String {
        self.store
            .create_principal(agent_access_core::PrincipalWriteRequest {
                role: agent_access_core::PrincipalRole::Admin,
                self_service_enabled: None,
                principal_id: "admin".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            })
            .unwrap();
        self.store
            .issue_broker_token(
                &self.hasher,
                BrokerTokenIssueRequest {
                    principal_id: "admin".into(),
                    name: "renewal-admin".into(),
                    token_class: BrokerTokenClass::Admin,
                    scopes: json!({}),
                    expires_at: None,
                    created_by: "test".into(),
                },
            )
            .unwrap()
            .token
    }

    async fn get_json(&self, uri: &str, token: &str, request_id: &str) -> Value {
        let response = self
            .send(
                &self.app,
                self.request(Method::GET, uri, request_id)
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        response_json(response).await
    }

    /// The Microsoft method's `oidc` object in the admin login-method list.
    async fn admin_oidc(&self, admin: &str, request_id: &str) -> Value {
        let listing = self
            .get_json(
                &format!(
                    "/v1/admin/principals/{}/login-methods",
                    self.person.principal
                ),
                admin,
                request_id,
            )
            .await;
        listing["result"]
            .as_array()
            .unwrap()
            .iter()
            .find(|method| method["method"] == "oidc")
            .unwrap_or_else(|| panic!("{listing}"))["oidc"]
            .clone()
    }
}

/// `GET /v1/me` and the admin login-method listing report one renewal
/// status shape in every state, `null` without a renewal row, and the
/// evidence window; callers without a Microsoft method get no field, and
/// an administrator's view never renews the person.
#[tokio::test]
async fn me_and_the_admin_listing_report_renewal_status_in_every_state() {
    let f = fixture().await;
    let method = f.person.method.clone();
    let admin = f.admin_token();
    // An administrator viewing an expired person does not renew them.
    let oidc = f.admin_oidc(&admin, "renewal-admin-expired").await;
    assert_eq!(oidc["provider"], "microsoft");
    assert_eq!(oidc["userObjectId"], super::microsoft_oidc::USER_OBJECT_ID);
    assert_eq!(oidc["membershipRenewal"]["state"], "active");
    assert_eq!(f.provider.refresh_arrivals(), 0);

    // Current evidence, so that /v1/me itself does not renew.
    f.expires_in(&method, 7 * 3600);
    let valid_until = f.valid_until(&method);
    let set = |assignments: &str| {
        f.sql(&format!(
            "UPDATE oidc_membership_renewals SET {assignments} WHERE login_method_id = '{method}'"
        ))
    };
    let failure = "last_renewed_at = '2026-10-20T00:30:00Z', last_failure_code = 'unavailable',
        last_failure_at = '2026-10-20T01:00:00Z', next_attempt_after = '2026-10-20T02:00:00Z'";
    let ended = |reason: &str| {
        format!(
            "state = 'ended', ended_reason = '{reason}', payload_version = NULL, key_id = NULL,
             nonce = NULL, ciphertext = NULL, last_failure_code = NULL, last_failure_at = NULL,
             next_attempt_after = NULL"
        )
    };
    for (state, assignments) in [
        ("active", String::new()),
        ("retrying", format!("state = 'retrying', {failure}")),
        (
            "blocked",
            format!(
                "state = 'blocked', {}",
                failure.replace("unavailable", "client_rejected")
            ),
        ),
        ("sign_in_required", ended("sign_in_required")),
        ("not_issued", ended("not_issued")),
        ("identity_mismatch", ended("identity_mismatch")),
    ] {
        if !assignments.is_empty() {
            set(&assignments);
        }
        let expected = serde_json::to_value(f.renewal(&method).unwrap().status()).unwrap();
        assert_eq!(expected["state"], state);
        let me = f
            .get_json(
                "/v1/me",
                &f.person.agent_token,
                &format!("renewal-me-{state}"),
            )
            .await;
        assert_eq!(me["principal"], f.person.principal.as_str(), "{state}");
        assert_eq!(
            me["microsoftMembership"],
            json!({"validUntil": valid_until, "renewal": expected}),
            "{state}"
        );
        let oidc = f
            .admin_oidc(&admin, &format!("renewal-admin-{state}"))
            .await;
        assert_eq!(oidc["membershipRenewal"], expected, "{state}");
    }
    let me = f
        .get_json("/v1/me", &f.person.agent_token, "renewal-me-shape")
        .await;
    assert_eq!(
        me["microsoftMembership"]["renewal"],
        json!({
            "state": "identity_mismatch",
            "lastRenewedAt": "2026-10-20T00:30:00Z",
            "nextAttemptAfter": null,
            "lastFailure": null,
        })
    );
    let ended = f.admin_oidc(&admin, "renewal-admin-shape").await;
    assert_eq!(ended["membershipRenewal"]["lastFailure"], Value::Null);

    // Without a renewal row or evidence: nulls.
    f.sql(&format!(
        "DELETE FROM oidc_membership_renewals WHERE login_method_id = '{method}';
         DELETE FROM external_principal_groups WHERE login_method_id = '{method}';
         DELETE FROM oidc_membership_refresh_state WHERE login_method_id = '{method}';"
    ));
    let me = f
        .get_json("/v1/me", &f.person.agent_token, "renewal-me-none")
        .await;
    assert_eq!(
        me["microsoftMembership"],
        json!({"validUntil": null, "renewal": null})
    );
    let oidc = f.admin_oidc(&admin, "renewal-admin-none").await;
    assert_eq!(oidc["membershipRenewal"], Value::Null);
    // A caller without a Microsoft method has no field at all.
    let me = f.get_json("/v1/me", &admin, "renewal-me-admin").await;
    assert_eq!(me["principal"], "admin");
    assert!(me.get("microsoftMembership").is_none(), "{me}");
    assert_eq!(f.provider.refresh_arrivals(), 0);
}

/// Linking the Microsoft identity a principal already has keeps the method's
/// renewal record, and the link response reports its status as the listing
/// does.
#[tokio::test]
async fn relinking_a_linked_method_reports_its_renewal_status() {
    let f = fixture().await;
    let method = f.person.method.clone();
    let admin = f.admin_token();
    let link = |request_id: &str| {
        f.send(
            &f.app,
            f.request(
                Method::PUT,
                &format!(
                    "/v1/admin/principals/{}/login-methods/oidc/microsoft",
                    f.person.principal
                ),
                request_id,
            )
            .header(AUTHORIZATION, format!("Bearer {admin}"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"userObjectId": super::microsoft_oidc::USER_OBJECT_ID}).to_string(),
            ))
            .unwrap(),
        )
    };
    for (state, assignments) in [
        ("active", None),
        (
            "blocked",
            Some(
                "state = 'blocked', last_failure_code = 'client_rejected',
                 last_failure_at = '2026-10-20T01:00:00Z', next_attempt_after = '2026-10-20T02:00:00Z'",
            ),
        ),
    ] {
        if let Some(assignments) = assignments {
            f.sql(&format!(
                "UPDATE oidc_membership_renewals SET {assignments} WHERE login_method_id = '{method}'"
            ));
        }
        let record = f.renewal(&method).unwrap();
        let expected = serde_json::to_value(record.status()).unwrap();
        assert_eq!(expected["state"], state);
        let response = link(&format!("renewal-relink-{state}")).await;
        assert_eq!(response.status(), StatusCode::OK, "{state}");
        let linked = response_json(response).await;
        assert_eq!(linked["result"]["loginMethodId"], method.as_str(), "{state}");
        assert_eq!(
            linked["result"]["oidc"]["membershipRenewal"], expected,
            "{state}"
        );
        assert_eq!(
            f.admin_oidc(&admin, &format!("renewal-relink-list-{state}"))
                .await["membershipRenewal"],
            expected,
            "{state}"
        );
        assert_eq!(f.renewal(&method).unwrap(), record, "{state}");
    }
    assert_eq!(f.provider.refresh_arrivals(), 0);
}

/// `GET /v1/me` passes renewal admission: with expired evidence it waits
/// for the renewal and reports the renewed window.
#[tokio::test]
async fn me_reports_the_window_of_a_renewal_it_waited_for() {
    let f = fixture().await;
    let method = f.person.method.clone();
    f.clock.advance_seconds(61);
    let me = f
        .get_json("/v1/me", &f.person.agent_token, "renewal-me-renews")
        .await;
    assert_eq!(f.provider.refresh_count(), 1);
    let membership = &me["microsoftMembership"];
    assert_eq!(membership["validUntil"], f.valid_until(&method).as_str());
    assert_ne!(membership["validUntil"], LONG_AGO);
    assert_eq!(membership["renewal"]["state"], "active");
    assert!(membership["renewal"]["lastRenewedAt"].is_string());
    assert_eq!(f.renewal_audit("renewal-me-renews")["action"], RENEWED);
}

/// A renewal wait holds the caller's per-principal capacity: while one
/// person's requests wait for a slow renewal, their excess requests are
/// refused on HTTP, browser session reads, MCP and Git, and another person
/// keeps their capacity.
#[tokio::test]
async fn renewal_waits_hold_per_principal_capacity() {
    let f = fixture_configured(Duration::from_secs(30), |config| {
        config.limits.max_concurrent_requests_per_principal = 4;
        config.mcp.max_control_requests_per_principal = 2;
    })
    .await;
    let mut claims = FakeTokenClaims::valid(f.clock.now_timestamp());
    claims.user_object_id = OTHER_USER_OBJECT_ID.to_string();
    claims.subject = "other-microsoft-subject".to_string();
    let other = f.sign_in_person(claims).await;
    f.expires_in(&other.method, 7 * 3600);
    // Sessions opened while the person's evidence is current.
    f.expires_in(&f.person.method, 7 * 3600);
    let session = f.mcp_session().await;
    f.clock.advance_seconds(61);
    f.expire(&f.person.method);

    let gate = gate();
    let first = while_redeeming(
        &f,
        &gate,
        invoke_request(&f.app, Fixture::bearer(&f.person), "renewal-capacity-0"),
    )
    .await;
    let mut waiting = vec![first];
    for index in 1..3 {
        waiting.push(tokio::spawn(invoke_request(
            &f.app,
            Fixture::bearer(&f.person),
            &format!("renewal-capacity-{index}"),
        )));
    }
    // A browser session read of the same person takes the fourth slot.
    let session_request = |person: &Person, request_id: &str| {
        let app = f.app.clone();
        let request = f
            .request(Method::GET, "/v1/auth/session", request_id)
            .header(COOKIE, &person.cookie)
            .body(Body::empty())
            .unwrap();
        async move { app.oneshot(request).await.unwrap() }
    };
    let session_waiting = tokio::spawn(session_request(&f.person, "renewal-capacity-session"));
    // Two MCP requests of the same person wait too, on their own intake
    // capacity.
    let mcp_request = |request_id: &str| {
        let app = f.app.clone();
        let request = f
            .request(Method::POST, "/mcp", request_id)
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {}", f.person.agent_token))
            .header("mcp-session-id", &session)
            .header("mcp-protocol-version", "2025-11-25")
            .body(Body::from(
                json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}).to_string(),
            ))
            .unwrap();
        async move { app.oneshot(request).await.unwrap() }
    };
    let mcp_waiting = (0..2)
        .map(|index| tokio::spawn(mcp_request(&format!("renewal-capacity-mcp-{index}"))))
        .collect::<Vec<_>>();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(waiting.iter().all(|request| !request.is_finished()));
    assert!(!session_waiting.is_finished());
    assert!(mcp_waiting.iter().all(|request| !request.is_finished()));

    // The person's excess requests are refused at once.
    let response = f.invoke("renewal-capacity-excess").await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "concurrency_limited"
    );
    let response = f
        .git_fetch(
            &Fixture::git_basic(&f.person),
            "renewal-capacity-git-excess",
        )
        .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let response = mcp_request("renewal-capacity-mcp-excess").await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let response = session_request(&f.person, "renewal-capacity-session-excess").await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "concurrency_limited"
    );

    // Another person keeps their capacity on every path.
    assert_eq!(
        f.invoke_with(&Fixture::bearer(&other), "renewal-capacity-other")
            .await
            .status(),
        StatusCode::OK
    );
    assert_git_allowed(
        &f.git_fetch(&Fixture::git_basic(&other), "renewal-capacity-other-git")
            .await,
        "other person",
    );
    let response = session_request(&other, "renewal-capacity-other-session").await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = response_json(response).await;
    assert_eq!(session["result"]["authenticated"], true);
    assert_eq!(session["result"]["principal"], other.principal.as_str());

    gate.add_permits(1);
    for request in waiting {
        assert_eq!(request.await.unwrap().status(), StatusCode::OK);
    }
    let response = session_waiting.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session = response_json(response).await;
    assert_eq!(session["result"]["authenticated"], true);
    assert_eq!(session["result"]["principal"], f.person.principal.as_str());
    for request in mcp_waiting {
        let response = request.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listing = rpc_body(response).await;
        assert!(
            listing["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["name"] == echo_tool()),
            "{listing}"
        );
    }
    assert_eq!(f.provider.refresh_arrivals(), 1);
}

/// The durable attempt time is read once the attempt start holds the
/// mutation and store locks: a start that waited for them records when it
/// ran, so the attempt interval counts from the real start.
#[tokio::test]
async fn the_attempt_time_is_read_after_the_start_waits_for_its_locks() {
    let f = fixture().await;
    let method = f.person.method.clone();
    f.clock.advance_seconds(61);
    f.expires_in(&method, 3600);
    let state = f.state();
    let held = state.policy_mutation_lock.lock().await;
    assert_eq!(
        f.invoke("renewal-start-blocked").await.status(),
        StatusCode::OK
    );
    // The flight waits for the mutation lock while time passes.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(f.renewal(&method).unwrap().last_attempt_at, None);
    f.clock.advance_seconds(20);
    let started_at = chrono::DateTime::<chrono::Utc>::from_timestamp(f.clock.now_timestamp(), 0)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    drop(held);
    state.membership_renewals.wait_idle().await;
    let row = f.renewal(&method).unwrap();
    assert_eq!(row.last_attempt_at.as_deref(), Some(started_at.as_str()));
    assert_eq!(f.renewal_audit("renewal-start-blocked")["action"], RENEWED);
}
