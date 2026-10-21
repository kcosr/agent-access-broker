//! Jira and Confluence through a person's `atlassian` OAuth connection: the
//! real Jira and Confluence providers and the `atlassian` dialect against
//! one stub serving Atlassian's OAuth endpoints and, in place of
//! `https://api.atlassian.com`, the gateway routes `/ex/jira/{cloudId}` and
//! `/ex/confluence/{cloudId}`. The providers' configuration is the
//! production shape; only the gateway origin of the served providers moves.
use super::atlassian_dialect::{
    CALLBACK, CLOUD_ID, OTHER_CLOUD_ID, mount_consent, mount_sites, site, token,
};
use super::*;
use agent_access_atlassian::ATLASSIAN_OAUTH_AUDIENCE;
use agent_access_core::{
    ConnectionConfig, ConnectionOAuthConfig, CreateResourceRequest,
    ManagedPolicyGrantCreateRequest, OAuthConnectionStatus, PrincipalWriteRequest, ProvidersConfig,
};
use agent_access_provider::test_support::TestHost;
use agent_access_provider::{OAuthClientAuth, OAuthRotation, OAuthScopeMode, OAuthTokenEncoding};
use wiremock::matchers::{body_partial_json, query_param};

const JIRA_GATEWAY: &str = "/ex/jira/11111111-2222-4333-8444-555555555555/rest/api/3";
const CONFLUENCE_GATEWAY: &str = "/ex/confluence/11111111-2222-4333-8444-555555555555/wiki";
/// The Jira scopes of the action inventory.
const JIRA_SCOPES: [&str; 2] = ["read:jira-work", "write:jira-work"];
/// The Confluence scopes of the action inventory.
const CONFLUENCE_SCOPES: [&str; 15] = [
    "read:confluence-content.all",
    "write:confluence-content",
    "search:confluence",
    "write:confluence-file",
    "readonly:content.attachment:confluence",
    "read:page:confluence",
    "write:page:confluence",
    "delete:page:confluence",
    "read:space:confluence",
    "read:content.metadata:confluence",
    "read:hierarchical-content:confluence",
    "read:attachment:confluence",
    "read:comment:confluence",
    "write:comment:confluence",
    "delete:comment:confluence",
];

/// The shared registration's scopes: the inventory with `read:me` and
/// `offline_access`.
fn profile_scopes() -> Vec<String> {
    ["read:me", "offline_access"]
        .into_iter()
        .chain(JIRA_SCOPES)
        .chain(CONFLUENCE_SCOPES)
        .map(str::to_owned)
        .collect()
}

/// The site's two product containers in `accessible-resources`.
fn both_products(cloud_id: &str) -> Value {
    json!([
        site(cloud_id, &JIRA_SCOPES),
        site(cloud_id, &CONFLUENCE_SCOPES)
    ])
}

/// Jira on the site through the gateway; `gateway` adds the stub's route
/// to the allowlist of the served provider.
fn jira_config(gateway: Option<&str>) -> agent_access_jira::JiraProviderConfig {
    let mut hosts = vec![
        "https://example.atlassian.net/rest/api/3/**".to_owned(),
        "https://api.atlassian.com/ex/jira/**".to_owned(),
    ];
    hosts.extend(gateway.map(|gateway| format!("{gateway}/ex/jira/**")));
    serde_json::from_value(json!({
        "tenant_host": "example.atlassian.net",
        "cloud_id": CLOUD_ID,
        "allowed_upstream_hosts": hosts,
    }))
    .unwrap()
}

/// Confluence on the site through the gateway; `gateway` adds the stub's
/// route to the allowlist of the served provider.
fn confluence_config(gateway: Option<&str>) -> agent_access_confluence::ConfluenceProviderConfig {
    let mut hosts = vec![
        "https://example.atlassian.net/wiki/**".to_owned(),
        "https://api.atlassian.com/ex/confluence/**".to_owned(),
    ];
    hosts.extend(gateway.map(|gateway| format!("{gateway}/ex/confluence/**")));
    serde_json::from_value(json!({
        "tenant_host": "example.atlassian.net",
        "cloud_id": CLOUD_ID,
        "allowed_upstream_hosts": hosts,
        "content": { "page_formats": ["storage"] },
    }))
    .unwrap()
}

/// The OAuth fixture with Jira and Confluence on one site, both consuming
/// an `atlassian` connection through an `atlassian` registration for the
/// site, with the token profile `atlassian-bearer-token` beside OAuth when
/// `token_profile` is set; `atlassian` serves the OAuth endpoints and the
/// gateway. Alice has `per_user` grants on project `ENG` and space
/// `~alice`.
async fn products_fixture(atlassian: &MockServer, token_profile: bool) -> OAuthFixture {
    let gateway = atlassian.uri();
    let host = TestHost::default();
    let providers = vec![
        agent_access_jira::test_support::provider_with_gateway(
            jira_config(Some(&gateway)),
            &host.context(),
            &gateway,
        )
        .unwrap(),
        agent_access_confluence::test_support::provider_with_gateway(
            confluence_config(Some(&gateway)),
            &host.context(),
            &gateway,
        )
        .unwrap(),
    ];
    let dialect = agent_access_atlassian::test_support::dialect(&atlassian.uri());
    let fixture = oauth_fixture_with(
        None,
        |_, config| {
            let stub = config.oauth.registrations.remove("stub").unwrap();
            config.credentials.connections.remove("oauth_stub");
            config.credentials.per_user.remove("oauth_stub");
            config.oauth.registrations.insert(
                "atlassian".into(),
                OAuthRegistrationConfig {
                    login_binding: None,
                    adapter: OAuthAdapter::new("atlassian"),
                    base_url: "https://auth.atlassian.com".into(),
                    redirect_uri: CALLBACK.into(),
                    client_id: "broker-app".into(),
                    client_secret_ref: stub.client_secret_ref,
                    adapter_settings: Default::default(),
                    client_auth: OAuthClientAuth::ClientSecretPost,
                    encoding: OAuthTokenEncoding::Json,
                    rotation: OAuthRotation::RotateRefresh,
                    allow_insecure_loopback: true,
                    permission_profiles: BTreeMap::from([(
                        "default".into(),
                        OAuthPermissionProfile {
                            scope_mode: OAuthScopeMode::Explicit,
                            scopes: Some(profile_scopes()),
                            audience: ATLASSIAN_OAUTH_AUDIENCE.into(),
                            target: CLOUD_ID.into(),
                        },
                    )]),
                },
            );
            config.credentials.connections.insert(
                "atlassian".into(),
                ConnectionConfig {
                    display_name: Some("Atlassian".into()),
                    user_token_profiles: None,
                    service_account_token_profiles: token_profile
                        .then(|| vec!["atlassian-bearer-token".into()]),
                    oauth: Some(ConnectionOAuthConfig {
                        registration: "atlassian".into(),
                        profile: "default".into(),
                    }),
                },
            );
            for product in ["jira", "confluence"] {
                config
                    .credentials
                    .per_user
                    .insert(product.into(), connection_credential("atlassian"));
            }
            config.providers = ProvidersConfig::new(Arc::new(
                crate::test_composition::backend_registry_with_dialect(dialect),
            ))
            .with(agent_access_fake::FakeProviderConfig::default())
            .with(jira_config(None))
            .with(confluence_config(None));
        },
        providers,
    )
    .await;
    for (id, resource_type, value) in [
        (
            "jira-eng",
            agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
            "ENG",
        ),
        (
            "confluence-alice",
            agent_access_confluence::CONFLUENCE_SPACE_RESOURCE
                .id()
                .clone(),
            "~alice",
        ),
    ] {
        fixture
            .runtime
            .create_managed_resource(CreateResourceRequest {
                id: Some(id.into()),
                display_name: None,
                resource_type,
                selector: ResourceSelector::Exact {
                    value: value.into(),
                },
                allowed_execution_contexts: vec!["default".into()],
                enabled: true,
                attributes: Default::default(),
                created_by: "admin".into(),
            })
            .unwrap();
    }
    fixture.grant_product("alice", "jira", &["issue.view", "comment.list"], "jira-eng");
    fixture.grant_product(
        "alice",
        "confluence",
        &["page.view", "search"],
        "confluence-alice",
    );
    fixture
}

impl OAuthFixture {
    fn grant_product(&self, principal: &str, service: &str, actions: &[&str], resource: &str) {
        self.runtime
            .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
                grant_id: Some(format!("{principal}-{service}")),
                subjects: vec![format!("user:{principal}")],
                service: service.into(),
                actions: actions.iter().map(|action| action.to_string()).collect(),
                resources: ResourceSelection {
                    resource_ids: vec![resource.into()],
                    resource_group_ids: Vec::new(),
                },
                execution_contexts: vec!["default".into()],
                credential_mode: "per_user".into(),
                priority: None,
                status: None,
                description: None,
                created_by: "admin".into(),
            })
            .unwrap();
    }

    /// Runs alice's consent on the `atlassian` registration with `intent`,
    /// returning the callback response.
    async fn atlassian_connect(&self, intent: &str) -> axum::response::Response {
        let connect = self
            .browser(
                Method::POST,
                "/v1/oauth/connect",
                "atlassian-products-connect",
                Some(json!({"registration": "atlassian", "intent": intent})),
            )
            .await;
        let status = connect.status();
        let connect = response_json(connect).await;
        assert_eq!(status, StatusCode::OK, "{connect}");
        let authorization_url =
            url::Url::parse(connect["result"]["authorizationUrl"].as_str().unwrap()).unwrap();
        let state = authorization_url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        self.browser(
            Method::GET,
            &format!(
                "/v1/oauth/callback/atlassian?{}",
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("state", &state)
                    .append_pair("code", "one-use-code")
                    .finish()
            ),
            "atlassian-products-callback",
            None,
        )
        .await
    }

    /// Connects alice with access token `number`, granting the profile, for
    /// both products on the site; the access expires in `expires_in`
    /// seconds.
    async fn atlassian_connected(&self, atlassian: &MockServer, number: u32, intent: &str) {
        self.atlassian_connected_expiring(atlassian, number, intent, 3600)
            .await;
    }

    async fn atlassian_connected_expiring(
        &self,
        atlassian: &MockServer,
        number: u32,
        intent: &str,
        expires_in: u64,
    ) {
        let mut grant = token(number, Some(&profile_scopes().join(" ")));
        grant["expires_in"] = json!(expires_in);
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_partial_json(
                json!({"grant_type": "authorization_code"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(grant))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(atlassian)
            .await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "account_id": "5b10ac8d82e05b22cc7d4ef5",
                "email": "alice@example.com",
                "name": "Alice Example",
                "account_status": "active"
            })))
            .mount(atlassian)
            .await;
        mount_sites(atlassian, both_products(CLOUD_ID)).await;
        let callback = self.atlassian_connect(intent).await;
        assert_eq!(callback.status(), StatusCode::OK);
        assert_eq!(
            self.atlassian_connection().status,
            OAuthConnectionStatus::Ready
        );
    }

    async fn invoke_as(
        &self,
        token: &str,
        service: &str,
        action: &str,
        request_id: &str,
        inputs: Value,
    ) -> (StatusCode, Value) {
        let response = authed_json_request(
            self.app.clone(),
            Method::POST,
            format!("/v1/invoke/{service}/{action}"),
            request_id,
            "Authorization",
            format!("Bearer {token}"),
            Some(&json!({"inputs": inputs}).to_string()),
        )
        .await;
        (response.status(), response_json(response).await)
    }

    async fn invoke_product(
        &self,
        service: &str,
        action: &str,
        request_id: &str,
        inputs: Value,
    ) -> (StatusCode, Value) {
        self.invoke_as(&self.agent_token, service, action, request_id, inputs)
            .await
    }

    fn atlassian_connection(&self) -> agent_access_core::OAuthConnection {
        self.runtime
            .oauth_manager()
            .unwrap()
            .status("alice", "atlassian")
            .unwrap()
    }
}

/// The method, path and presented authorization of each gateway request
/// `atlassian` got since `skip` earlier ones.
async fn gateway_requests(atlassian: &MockServer, skip: usize) -> Vec<String> {
    atlassian
        .received_requests()
        .await
        .unwrap()
        .iter()
        .skip(skip)
        .filter(|request| request.url.path().starts_with("/ex/"))
        .map(|request| {
            format!(
                "{} {} {}",
                request.method,
                request.url.path(),
                header(request, "authorization").unwrap_or("-")
            )
        })
        .collect()
}

/// Refresh-token grants Atlassian received since `skip` earlier requests.
async fn refreshes(atlassian: &MockServer, skip: usize) -> usize {
    atlassian
        .received_requests()
        .await
        .unwrap()
        .iter()
        .skip(skip)
        .filter(|request| {
            request.url.path() == "/oauth/token"
                && serde_json::from_slice::<Value>(&request.body)
                    .is_ok_and(|body| body["grant_type"] == "refresh_token")
        })
        .count()
}

/// Serves `route` on the gateway to access token `number` with `response`.
async fn mount_gateway(
    atlassian: &MockServer,
    route: &str,
    number: u32,
    response: ResponseTemplate,
) {
    Mock::given(method("GET"))
        .and(path(route))
        .and(header_is(
            "authorization",
            format!("Bearer atlassian-access-{number}").as_str(),
        ))
        .respond_with(response)
        .mount(atlassian)
        .await;
}

fn jira_issue() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "id": "10001",
        "key": "ENG-1",
        "fields": {
            "project": { "key": "ENG" },
            "summary": "Broken build",
            "status": { "name": "Open" },
            "issuetype": { "name": "Task" },
            "description": null
        }
    }))
}

fn personal_page() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(personal_page_json())
}

fn personal_page_json() -> Value {
    json!({
        "id": "123456", "type": "page", "status": "current", "title": "Notes",
        "space": {"key": "~alice"}, "version": {"number": 7},
        "body": {"storage": {"value": "<p>notes</p>"}}
    })
}

/// Alice reads a Jira issue and lists its comments, both lookup-backed,
/// then reads a page in her personal space and searches it, all through
/// the gateway with her one Atlassian connection. Audit names the
/// connection.
#[tokio::test]
async fn a_person_reads_jira_and_a_personal_confluence_space_through_the_gateway() {
    let atlassian = MockServer::start().await;
    let fixture = products_fixture(&atlassian, false).await;
    fixture.atlassian_connected(&atlassian, 1, "connect").await;
    let consented = atlassian.received_requests().await.unwrap().len();
    let issue = format!("{JIRA_GATEWAY}/issue/ENG-1");
    let comments = format!("{issue}/comment");
    let page = format!("{CONFLUENCE_GATEWAY}/rest/api/content/123456");
    let search = format!("{CONFLUENCE_GATEWAY}/rest/api/content/search");
    mount_gateway(&atlassian, &issue, 1, jira_issue()).await;
    mount_gateway(
        &atlassian,
        &comments,
        1,
        ResponseTemplate::new(200)
            .set_body_json(json!({"startAt": 0, "maxResults": 50, "total": 0, "comments": []})),
    )
    .await;
    mount_gateway(&atlassian, &page, 1, personal_page()).await;
    Mock::given(method("GET"))
        .and(path(search.as_str()))
        .and(query_param("cql", "space IN (\"~alice\") AND type = page"))
        .and(header_is("authorization", "Bearer atlassian-access-1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"results": [personal_page_json()]})),
        )
        .mount(&atlassian)
        .await;

    let (status, body) = fixture
        .invoke_product(
            "jira",
            "issue.view",
            "jira-issue",
            json!({"issue": "ENG-1"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["key"], "ENG-1");
    let (status, body) = fixture
        .invoke_product(
            "jira",
            "comment.list",
            "jira-comments",
            json!({"issue": "ENG-1"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = fixture
        .invoke_product(
            "confluence",
            "page.view",
            "confluence-page",
            json!({"pageId": "123456"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["space"], "~alice");
    let (status, body) = fixture
        .invoke_product(
            "confluence",
            "search",
            "confluence-search",
            json!({"query": {"type": "cql", "value": ""}}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["pages"][0]["space"], "~alice", "{body}");

    let bearer = "Bearer atlassian-access-1";
    assert_eq!(
        gateway_requests(&atlassian, consented).await,
        [
            // issue.view: lookups before policy and at execution, then the read.
            format!("GET {issue} {bearer}"),
            format!("GET {issue} {bearer}"),
            format!("GET {issue} {bearer}"),
            // comment.list: the same lookups, then the comments.
            format!("GET {issue} {bearer}"),
            format!("GET {issue} {bearer}"),
            format!("GET {comments} {bearer}"),
            // page.view: the lookup before policy, then the read.
            format!("GET {page} {bearer}"),
            format!("GET {page} {bearer}"),
            format!("GET {search} {bearer}"),
        ]
    );
    let audit = read_audit_records(&fixture.audit_path);
    let invocations = audit
        .iter()
        .filter(|record| record["service"] == "jira" || record["service"] == "confluence")
        .collect::<Vec<_>>();
    assert_eq!(invocations.len(), 4);
    for record in invocations {
        assert_eq!(record["credentialMode"], "per_user", "{record}");
        assert_eq!(record["credentialConnection"], "atlassian", "{record}");
        assert_eq!(record["decision"], "allow", "{record}");
    }
}

/// Another request refreshes while one is in flight with the earlier
/// access, which Atlassian then rejects: the in-flight request marks it
/// rejected and recovers once with the stored successor, without refreshing
/// again.
#[tokio::test]
async fn a_request_in_flight_across_a_refresh_recovers_once_with_the_successor() {
    let atlassian = MockServer::start().await;
    let fixture = products_fixture(&atlassian, false).await;
    // Access 1 is due for refresh two seconds after consent.
    fixture
        .atlassian_connected_expiring(&atlassian, 1, "connect", 2)
        .await;
    let consented = atlassian.received_requests().await.unwrap().len();
    // The refresh rotates the family once.
    let mut successor = token(2, None);
    successor["expires_in"] = json!(3600);
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_partial_json(json!({
            "grant_type": "refresh_token",
            "refresh_token": "atlassian-refresh-1"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(successor))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&atlassian)
        .await;
    let issue = format!("{JIRA_GATEWAY}/issue/ENG-1");
    // The in-flight request reaches Atlassian after the refresh.
    mount_gateway(
        &atlassian,
        &issue,
        1,
        ResponseTemplate::new(401).set_delay(Duration::from_secs(3)),
    )
    .await;
    mount_gateway(&atlassian, &issue, 2, jira_issue()).await;

    let in_flight = fixture.invoke_product(
        "jira",
        "issue.view",
        "jira-in-flight",
        json!({"issue": "ENG-1"}),
    );
    let refreshing = async {
        tokio::time::sleep(Duration::from_millis(2100)).await;
        fixture
            .invoke_product(
                "jira",
                "issue.view",
                "jira-refreshing",
                json!({"issue": "ENG-1"}),
            )
            .await
    };
    let ((in_flight_status, in_flight), (refreshing_status, refreshing)) =
        tokio::join!(in_flight, refreshing);
    assert_eq!(in_flight_status, StatusCode::OK, "{in_flight}");
    assert_eq!(refreshing_status, StatusCode::OK, "{refreshing}");
    assert_eq!(refreshes(&atlassian, consented).await, 1);
    let mut requests = gateway_requests(&atlassian, consented).await;
    requests.sort();
    let mut expected = vec![format!("GET {issue} Bearer atlassian-access-1")];
    expected.extend(std::iter::repeat_n(
        format!("GET {issue} Bearer atlassian-access-2"),
        6,
    ));
    assert_eq!(requests, expected);
    assert_eq!(
        fixture.atlassian_connection().status,
        OAuthConnectionStatus::Ready
    );
}

/// A refresh whose response is lost after Atlassian rotated the refresh
/// token leaves the family uncertain: Jira and Confluence requests fail as
/// needing reconnect without reaching the gateway or sending the old
/// refresh token again, and reconnecting restores access.
#[tokio::test]
async fn a_refresh_response_lost_in_transit_requires_reconnect() {
    let atlassian = MockServer::start().await;
    let fixture = products_fixture(&atlassian, false).await;
    fixture
        .atlassian_connected_expiring(&atlassian, 1, "connect", 1)
        .await;
    let consented = atlassian.received_requests().await.unwrap().len();
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_partial_json(json!({"grant_type": "refresh_token"})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"access_token":"atlassian-access-2","refresh_tok"#),
        )
        .expect(1)
        .mount(&atlassian)
        .await;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    for (service, action, inputs) in [
        ("confluence", "page.view", json!({"pageId": "123456"})),
        ("jira", "issue.view", json!({"issue": "ENG-1"})),
    ] {
        let (status, body) = fixture
            .invoke_product(service, action, &format!("{service}-uncertain"), inputs)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["reasonCode"], "credential_invalid", "{body}");
        assert_eq!(
            body["error"]["message"], "oauth_refresh_uncertain",
            "{body}"
        );
    }
    assert_eq!(refreshes(&atlassian, consented).await, 1);
    assert!(gateway_requests(&atlassian, consented).await.is_empty());
    let connection = fixture.atlassian_connection();
    assert_eq!(connection.status, OAuthConnectionStatus::ReconnectRequired);
    assert_eq!(
        connection.reason.as_deref(),
        Some("oauth_refresh_uncertain")
    );

    // Reconnecting issues a new family.
    atlassian.reset().await;
    fixture
        .atlassian_connected(&atlassian, 3, "reconnect")
        .await;
    let page = format!("{CONFLUENCE_GATEWAY}/rest/api/content/123456");
    mount_gateway(&atlassian, &page, 3, personal_page()).await;
    let (status, body) = fixture
        .invoke_product(
            "confluence",
            "page.view",
            "confluence-reconnected",
            json!({"pageId": "123456"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// With `atlassian-bearer-token` beside OAuth, people use OAuth and a
/// service account uses its administrator-provisioned scoped token, both
/// through the gateway.
#[tokio::test]
async fn service_accounts_use_their_bearer_token_through_the_gateway_beside_oauth() {
    let atlassian = MockServer::start().await;
    let fixture = products_fixture(&atlassian, true).await;
    let store = fixture.runtime.managed_store().unwrap().clone();
    store
        .create_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "robot".into(),
            kind: "service_account".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".into(),
        })
        .unwrap();
    fixture.grant_product("robot", "jira", &["issue.view"], "jira-eng");
    let hasher = fixture.runtime.broker_token_hasher().unwrap();
    let issue_token = |principal: &str, token_class: BrokerTokenClass, scopes: Value| {
        store
            .issue_broker_token(
                hasher,
                BrokerTokenIssueRequest {
                    principal_id: principal.into(),
                    name: format!("{principal} token"),
                    token_class,
                    scopes,
                    expires_at: None,
                    created_by: "test".into(),
                },
            )
            .unwrap()
            .token
    };
    let admin = issue_token("admin", BrokerTokenClass::Admin, json!({}));
    let robot = issue_token(
        "robot",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedExecutionContexts": ["default"]}),
    );
    let response = authed_json_request(
        fixture.app.clone(),
        Method::PUT,
        "/v1/admin/principals/robot/credentials/connections/atlassian",
        "atlassian-robot-token",
        "Authorization",
        format!("Bearer {admin}"),
        Some(&json!({"secret": {"token": "robot-scoped-token"}}).to_string()),
    )
    .await;
    let status = response.status();
    let stored = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "{stored}");
    assert_eq!(stored["result"]["profile"], "atlassian-bearer-token");

    fixture.atlassian_connected(&atlassian, 1, "connect").await;
    let consented = atlassian.received_requests().await.unwrap().len();
    let issue = format!("{JIRA_GATEWAY}/issue/ENG-1");
    mount_gateway(&atlassian, &issue, 1, jira_issue()).await;
    Mock::given(method("GET"))
        .and(path(issue.as_str()))
        .and(header_is("authorization", "Bearer robot-scoped-token"))
        .respond_with(jira_issue())
        .mount(&atlassian)
        .await;

    let (status, body) = fixture
        .invoke_as(
            &robot,
            "jira",
            "issue.view",
            "jira-robot",
            json!({"issue": "ENG-1"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = fixture
        .invoke_product(
            "jira",
            "issue.view",
            "jira-alice",
            json!({"issue": "ENG-1"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut expected = vec![format!("GET {issue} Bearer robot-scoped-token"); 3];
    expected.extend(vec![format!("GET {issue} Bearer atlassian-access-1"); 3]);
    assert_eq!(gateway_requests(&atlassian, consented).await, expected);
    let audit = read_audit_records(&fixture.audit_path);
    let jira = audit
        .iter()
        .filter(|record| record["service"] == "jira")
        .collect::<Vec<_>>();
    assert_eq!(jira.len(), 2);
    assert!(
        jira.iter()
            .all(|record| record["credentialConnection"] == "atlassian")
    );
}

/// Owner decision 8, option A: the shared profile needs both products on the
/// configured site. A consent for another site, or without Confluence,
/// installs nothing, so neither product can act; and an account whose
/// refresh shows the site lost Confluence leaves both products unusable
/// until it is reconnected, without reaching the gateway.
#[tokio::test]
async fn a_wrong_site_or_a_missing_product_leaves_the_connection_ineligible() {
    let atlassian = MockServer::start().await;
    let fixture = products_fixture(&atlassian, false).await;
    let jira_only = ["read:me", "offline_access"]
        .into_iter()
        .chain(JIRA_SCOPES)
        .collect::<Vec<_>>()
        .join(" ");
    for (scope, sites) in [
        (profile_scopes().join(" "), both_products(OTHER_CLOUD_ID)),
        (jira_only.clone(), json!([site(CLOUD_ID, &JIRA_SCOPES)])),
    ] {
        atlassian.reset().await;
        mount_consent(&atlassian, Some(&scope), sites).await;
        let callback = fixture.atlassian_connect("connect").await;
        assert_eq!(callback.status(), StatusCode::BAD_REQUEST);
        let body = response_json(callback).await;
        assert_eq!(
            body["error"]["message"], "oauth_permission_denied",
            "{body}"
        );
        assert!(fixture.atlassian_connection().connection_id.is_none());
        for (service, action, inputs) in [
            ("jira", "issue.view", json!({"issue": "ENG-1"})),
            ("confluence", "page.view", json!({"pageId": "123456"})),
        ] {
            let (status, body) = fixture
                .invoke_product(service, action, "atlassian-unconnected", inputs)
                .await;
            assert_ne!(status, StatusCode::OK, "{body}");
        }
        assert!(gateway_requests(&atlassian, 0).await.is_empty());
    }

    // A connected account whose refresh shows the site without Confluence.
    atlassian.reset().await;
    fixture
        .atlassian_connected_expiring(&atlassian, 1, "connect", 1)
        .await;
    atlassian.reset().await;
    let mut successor = token(2, None);
    successor["expires_in"] = json!(3600);
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(successor))
        .mount(&atlassian)
        .await;
    mount_sites(&atlassian, json!([site(CLOUD_ID, &JIRA_SCOPES)])).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    for (service, action, inputs) in [
        ("jira", "issue.view", json!({"issue": "ENG-1"})),
        ("confluence", "page.view", json!({"pageId": "123456"})),
    ] {
        let (status, body) = fixture
            .invoke_product(service, action, "atlassian-ineligible", inputs)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["reasonCode"], "credential_invalid", "{body}");
        assert_eq!(
            body["error"]["message"], "oauth_permission_denied",
            "{body}"
        );
    }
    assert!(gateway_requests(&atlassian, 0).await.is_empty());
    // The refreshed site no longer grants Confluence, which the shared
    // profile requires.
    let connection = fixture.atlassian_connection();
    assert!(
        connection
            .targets
            .iter()
            .all(|target| target.id != CLOUD_ID || !target.scopes.contains("read:page:confluence")),
        "{:?}",
        connection.targets
    );
}
