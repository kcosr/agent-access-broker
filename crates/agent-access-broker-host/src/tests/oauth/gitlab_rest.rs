//! GitLab REST through a person's `gitlab` OAuth connection: the real
//! GitLab provider and `gitlab` dialect against one stubbed GitLab instance
//! serving both the OAuth endpoints and the REST API. GitLab invalidates
//! both earlier tokens on every refresh, which the stub models by answering
//! each refresh token once.
use super::*;
use agent_access_core::{
    ConnectionConfig, ConnectionOAuthConfig, CreateResourceRequest, ManagedPolicyGrantCreateRequest,
};
use agent_access_provider::{OAuthClientAuth, OAuthRotation, OAuthScopeMode, OAuthTokenEncoding};

const CALLBACK: &str = "http://127.0.0.1/v1/oauth/callback/gitlab";
const PROJECT: &str = "/api/v4/projects/sip%2Fservice";
const ISSUE: &str = "/api/v4/projects/42/issues/7";
const TOKEN_ONLY_DENIAL: &str =
    "this action requires a token credential, and the caller's credential connection uses OAuth";

/// The OAuth fixture with GitLab REST on the stubbed instance `gitlab`,
/// whose `gitlab` connection alice connects through a `gitlab`
/// registration on the same instance, and a `per_user` grant for alice on
/// `sip/service`.
async fn gitlab_rest_fixture(gitlab: &MockServer) -> OAuthFixture {
    let instance = gitlab.uri();
    let fixture = oauth_fixture_with(
        None,
        |_, config| {
            let client_secret_ref = config.oauth.registrations["stub"].client_secret_ref.clone();
            config.oauth.registrations.insert(
                "gitlab".into(),
                OAuthRegistrationConfig {
                    adapter: OAuthAdapter::new("gitlab"),
                    base_url: instance.clone(),
                    redirect_uri: CALLBACK.into(),
                    client_id: "broker-app".into(),
                    client_secret_ref,
                    adapter_settings: Default::default(),
                    client_auth: OAuthClientAuth::ClientSecretPost,
                    encoding: OAuthTokenEncoding::Form,
                    rotation: OAuthRotation::RotateBoth,
                    allow_insecure_loopback: true,
                    login_binding: None,
                    permission_profiles: BTreeMap::from([(
                        "default".into(),
                        OAuthPermissionProfile {
                            scope_mode: OAuthScopeMode::Explicit,
                            scopes: Some(vec!["api".into(), "write_repository".into()]),
                            audience: "gitlab".into(),
                            target: instance.clone(),
                        },
                    )]),
                },
            );
            config.credentials.connections.insert(
                "gitlab".into(),
                ConnectionConfig {
                    display_name: Some("GitLab".into()),
                    token_profile: Some("gitlab-access-token".into()),
                    oauth: Some(ConnectionOAuthConfig {
                        registration: "gitlab".into(),
                        profile: "default".into(),
                    }),
                },
            );
            config
                .credentials
                .per_user
                .insert("gitlab".into(), connection_credential("gitlab"));
            config
                .providers
                .insert(agent_access_gitlab::GitlabProviderConfig {
                    provisioning: Default::default(),
                    attachments: Default::default(),
                    api_base_url: format!("{instance}/api/v4"),
                    web_base_url: instance.clone(),
                    egress_proxy: None,
                    allowed_upstream_hosts: vec![format!("{instance}/api/v4/**")],
                    webhooks: Default::default(),
                    content: Default::default(),
                    search: Default::default(),
                });
        },
        Vec::new(),
    )
    .await;
    fixture
        .runtime
        .create_managed_resource(CreateResourceRequest {
            id: Some("repository-sip-service".into()),
            display_name: None,
            resource_type: agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
            selector: ResourceSelector::Exact {
                value: "sip/service".into(),
            },
            allowed_execution_contexts: vec!["default".into()],
            enabled: true,
            attributes: Default::default(),
            created_by: "admin".into(),
        })
        .unwrap();
    fixture
        .runtime
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: Some("alice-gitlab".into()),
            subjects: vec!["user:alice".into()],
            service: "gitlab".into(),
            actions: ["project.view", "issue.view", "project.access_token.create"]
                .map(String::from)
                .to_vec(),
            resources: ResourceSelection {
                resource_ids: vec!["repository-sip-service".into()],
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
    fixture
}

/// GitLab's token response for access and refresh token `number`, with the
/// granted scopes.
fn gitlab_token(number: u32, expires_in: u64) -> Value {
    json!({
        "access_token": format!("gitlab-access-{number}"),
        "refresh_token": format!("gitlab-refresh-{number}"),
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": "api write_repository",
        "created_at": 1_760_000_000
    })
}

/// Code exchange issuing tokens `number`, and the identity check.
async fn mount_consent(gitlab: &MockServer, number: u32, expires_in: u64) {
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(gitlab_token(number, expires_in)))
        .up_to_n_times(1)
        .mount(gitlab)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/user"))
        .and(header_is(
            "authorization",
            format!("Bearer gitlab-access-{number}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42,
            "username": "alice",
            "name": "Alice Example"
        })))
        .mount(gitlab)
        .await;
}

/// GitLab's answer to the REST `route` presented with access token
/// `number`.
async fn mount_api(gitlab: &MockServer, route: &str, number: u32, response: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(route))
        .and(header_is(
            "authorization",
            format!("Bearer gitlab-access-{number}").as_str(),
        ))
        .respond_with(response)
        .mount(gitlab)
        .await;
}

fn project() -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(json!({ "id": 42, "path_with_namespace": "sip/service" }))
}

fn issue() -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(json!({ "id": 1007, "iid": 7, "project_id": 42, "title": "Broken build" }))
}

/// The method, path and presented token of each GitLab request since
/// `skip` earlier ones.
async fn gitlab_requests(gitlab: &MockServer, skip: usize) -> Vec<String> {
    gitlab
        .received_requests()
        .await
        .unwrap()
        .iter()
        .skip(skip)
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

/// Refresh-token grants GitLab received since `skip` earlier requests.
async fn refreshes(gitlab: &MockServer, skip: usize) -> Vec<BTreeMap<String, String>> {
    gitlab
        .received_requests()
        .await
        .unwrap()
        .iter()
        .skip(skip)
        .filter(|request| {
            request.url.path() == "/oauth/token"
                && std::str::from_utf8(&request.body)
                    .is_ok_and(|body| body.contains("grant_type=refresh_token"))
        })
        .map(|request| {
            url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect()
        })
        .collect()
}

impl OAuthFixture {
    /// Runs alice's consent on the `gitlab` registration with `intent`.
    async fn gitlab_rest_consent(&self, intent: &str) {
        let connect = self
            .browser(
                Method::POST,
                "/v1/oauth/connect",
                "gitlab-rest-connect",
                Some(json!({"registration": "gitlab", "intent": intent})),
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
        let callback = self
            .browser(
                Method::GET,
                &format!(
                    "/v1/oauth/callback/gitlab?{}",
                    url::form_urlencoded::Serializer::new(String::new())
                        .append_pair("state", &state)
                        .append_pair("code", "one-use-code")
                        .finish()
                ),
                "gitlab-rest-callback",
                None,
            )
            .await;
        assert_completion_page(callback, "Authorized", &[&state, "one-use-code"]).await;
    }

    async fn invoke_gitlab(
        &self,
        action: &str,
        request_id: &str,
        inputs: Value,
    ) -> (StatusCode, Value) {
        let response = authed_json_request(
            self.app.clone(),
            Method::POST,
            format!("/v1/invoke/gitlab/{action}"),
            request_id,
            "Authorization",
            format!("Bearer {}", self.agent_token),
            Some(&json!({"inputs": inputs}).to_string()),
        )
        .await;
        (response.status(), response_json(response).await)
    }

    fn gitlab_connection(&self) -> agent_access_core::OAuthConnection {
        self.runtime
            .oauth_manager()
            .unwrap()
            .status("alice", "gitlab")
            .unwrap()
    }
}

fn project_inputs() -> Value {
    json!({ "project": "sip/service" })
}

fn issue_inputs() -> Value {
    json!({ "project": "sip/service", "iid": 7 })
}

/// Alice reads a project and runs a lookup-backed action through her GitLab
/// connection: the lookup before policy, the lookup at execution and the
/// execution all present her access, and audit names the connection.
#[tokio::test]
async fn a_person_reads_a_project_and_an_issue_through_their_gitlab_connection() {
    let gitlab = MockServer::start().await;
    let fixture = gitlab_rest_fixture(&gitlab).await;
    mount_consent(&gitlab, 1, 7200).await;
    fixture.gitlab_rest_consent("connect").await;
    let consented = gitlab.received_requests().await.unwrap().len();
    mount_api(&gitlab, PROJECT, 1, project()).await;
    mount_api(&gitlab, ISSUE, 1, issue()).await;

    let (status, body) = fixture
        .invoke_gitlab("project.view", "gitlab-project", project_inputs())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["project"]["id"], 42, "{body}");
    let (status, body) = fixture
        .invoke_gitlab("issue.view", "gitlab-issue", issue_inputs())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["issue"]["iid"], 7);
    let bearer = "Bearer gitlab-access-1";
    assert_eq!(
        gitlab_requests(&gitlab, consented).await,
        [
            // project.view: lookups before policy and at execution, then the read.
            format!("GET {PROJECT} {bearer}"),
            format!("GET {PROJECT} {bearer}"),
            format!("GET {PROJECT} {bearer}"),
            // issue.view: the same two lookups, then the issue.
            format!("GET {PROJECT} {bearer}"),
            format!("GET {PROJECT} {bearer}"),
            format!("GET {ISSUE} {bearer}"),
        ]
    );
    let audit = read_audit_records(&fixture.audit_path);
    let record = audit.last().unwrap();
    assert_eq!(record["service"], "gitlab");
    assert_eq!(record["credentialMode"], "per_user");
    assert_eq!(record["credentialConnection"], "gitlab");
    assert_eq!(record["matchedGrant"]["grantId"], "alice-gitlab");
}

/// GitLab revokes both earlier tokens on refresh. A request already in
/// flight with the old access when another request refreshes gets 401; it
/// marks that access rejected, recovers once with the successor the other
/// request stored, without refreshing again, and succeeds.
#[tokio::test]
async fn a_request_in_flight_across_a_refresh_recovers_once_with_the_successor() {
    let gitlab = MockServer::start().await;
    let fixture = gitlab_rest_fixture(&gitlab).await;
    // Access 1 is due for refresh two seconds after consent.
    mount_consent(&gitlab, 1, 2).await;
    fixture.gitlab_rest_consent("connect").await;
    let consented = gitlab.received_requests().await.unwrap().len();
    // Refresh token 1 is answered once; GitLab then rejects it.
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("refresh_token=gitlab-refresh-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(gitlab_token(2, 7200)))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&gitlab)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .with_priority(2)
        .mount(&gitlab)
        .await;
    // The in-flight request reaches GitLab after the refresh revoked access 1.
    mount_api(
        &gitlab,
        PROJECT,
        1,
        ResponseTemplate::new(401)
            .set_delay(Duration::from_secs(3))
            .set_body_json(json!({"message": "401 Unauthorized"})),
    )
    .await;
    mount_api(&gitlab, PROJECT, 2, project()).await;

    let in_flight = fixture.invoke_gitlab("project.view", "gitlab-in-flight", project_inputs());
    let refreshing = async {
        tokio::time::sleep(Duration::from_millis(2100)).await;
        fixture
            .invoke_gitlab("project.view", "gitlab-refreshing", project_inputs())
            .await
    };
    let ((in_flight_status, in_flight), (refreshing_status, refreshing)) =
        tokio::join!(in_flight, refreshing);
    assert_eq!(in_flight_status, StatusCode::OK, "{in_flight}");
    assert_eq!(refreshing_status, StatusCode::OK, "{refreshing}");

    let refreshed = refreshes(&gitlab, consented).await;
    assert_eq!(refreshed.len(), 1, "{refreshed:?}");
    assert_eq!(refreshed[0]["refresh_token"], "gitlab-refresh-1");
    let mut requests = gitlab_requests(&gitlab, consented).await;
    requests.retain(|request| request.starts_with("GET"));
    requests.sort();
    // The in-flight request's lookup was rejected once; its repeat, its
    // execution lookup and read, and the refreshing request's three reads
    // present the successor.
    let mut expected = vec![format!("GET {PROJECT} Bearer gitlab-access-1")];
    expected.extend(std::iter::repeat_n(
        format!("GET {PROJECT} Bearer gitlab-access-2"),
        6,
    ));
    assert_eq!(requests, expected);
    let connection = fixture.gitlab_connection();
    assert_eq!(
        connection.status,
        agent_access_core::OAuthConnectionStatus::Ready
    );
}

/// A refresh whose response is lost after GitLab consumed the refresh token
/// leaves the family uncertain: the request fails as needing reconnect,
/// later requests fail the same way without sending the old refresh token
/// again, and reconnecting restores access. The predecessor is revoked, but
/// the successor GitLab may have issued is unknown, so the connection
/// reports its remote revocation `unconfirmed`.
#[tokio::test]
async fn a_refresh_response_lost_in_transit_requires_reconnect() {
    let gitlab = MockServer::start().await;
    let fixture = gitlab_rest_fixture(&gitlab).await;
    mount_consent(&gitlab, 1, 1).await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&gitlab)
        .await;
    fixture.gitlab_rest_consent("connect").await;
    let consented = gitlab.received_requests().await.unwrap().len();
    // GitLab rotated the family, but the response broke off mid-body.
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"access_token":"gitlab-access-2","refresh_tok"#),
        )
        .expect(1)
        .mount(&gitlab)
        .await;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    for request_id in ["gitlab-uncertain", "gitlab-still-uncertain"] {
        let (status, body) = fixture
            .invoke_gitlab("project.view", request_id, project_inputs())
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["reasonCode"], "credential_invalid", "{body}");
        assert_eq!(
            body["error"]["message"], "oauth_refresh_uncertain",
            "{body}"
        );
    }
    assert_eq!(refreshes(&gitlab, consented).await.len(), 1);
    assert!(
        gitlab_requests(&gitlab, consented)
            .await
            .iter()
            .all(|request| !request.contains("/api/v4/projects"))
    );
    let connection = fixture.gitlab_connection();
    assert_eq!(
        connection.status,
        agent_access_core::OAuthConnectionStatus::ReconnectRequired
    );
    assert_eq!(
        connection.reason.as_deref(),
        Some("oauth_refresh_uncertain")
    );
    // The serving broker's revocation worker revokes the predecessor.
    let started = std::time::Instant::now();
    loop {
        let revoked = gitlab_requests(&gitlab, consented)
            .await
            .iter()
            .filter(|request| request.contains("/oauth/revoke"))
            .count();
        if revoked == 2 {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(20), "{revoked}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let revoked = gitlab
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() == "/oauth/revoke")
        .map(|request| {
            url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect::<BTreeMap<String, String>>()["token"]
                .clone()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        revoked,
        BTreeSet::from(["gitlab-access-1".to_owned(), "gitlab-refresh-1".to_owned()])
    );
    let rows = response_json(
        fixture
            .browser(
                Method::GET,
                "/v1/oauth/connections",
                "gitlab-uncertain-rows",
                None,
            )
            .await,
    )
    .await;
    let row = rows["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["registration"] == "gitlab")
        .unwrap()
        .clone();
    assert_eq!(row["remoteRevocation"], "unconfirmed");

    mount_consent(&gitlab, 3, 7200).await;
    fixture.gitlab_rest_consent("reconnect").await;
    mount_api(&gitlab, PROJECT, 3, project()).await;
    let (status, body) = fixture
        .invoke_gitlab("project.view", "gitlab-reconnected", project_inputs())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(refreshes(&gitlab, consented).await.len(), 1);
    // Disconnecting the new connection revokes its family, while the old
    // one stays unconfirmed: only revoking the application in GitLab ends
    // its unknown successor.
    let response = fixture
        .browser(
            Method::DELETE,
            "/v1/oauth/connections/gitlab",
            "gitlab-uncertain-disconnect",
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await["result"],
        json!({"disconnected": true, "remoteRevocation": "unconfirmed"})
    );
    let revoked = gitlab
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() == "/oauth/revoke")
        .count();
    assert_eq!(revoked, 4);
}

/// Project token issuance needs a personal access token, so it is refused
/// for alice's OAuth selection before her connection is acquired, refreshed
/// or used for its project lookup.
#[tokio::test]
async fn token_only_gitlab_actions_are_refused_for_an_oauth_connection() {
    let gitlab = MockServer::start().await;
    let fixture = gitlab_rest_fixture(&gitlab).await;
    mount_consent(&gitlab, 1, 1).await;
    fixture.gitlab_rest_consent("connect").await;
    let consented = gitlab.received_requests().await.unwrap().len();
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let (status, body) = fixture
        .invoke_gitlab(
            "project.access_token.create",
            "gitlab-token-only",
            json!({
                "project": "sip/service",
                "name": "ci",
                "scopes": ["read_api"],
                "role": "developer",
                "expiresAt": "2026-11-01"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "credential_not_provisioned", "{body}");
    assert_eq!(body["error"]["message"], TOKEN_ONLY_DENIAL, "{body}");
    assert!(gitlab_requests(&gitlab, consented).await.is_empty());
}

/// The production sample with GitLab REST alone using a `gitlab`
/// connection that people satisfy through a GitLab OAuth registration on
/// its instance, with or without a token profile for service accounts.
fn gitlab_rest_oauth_config(token_profile: bool) -> String {
    let token_profile = if token_profile {
        "token_profile = \"gitlab-access-token\"\n"
    } else {
        ""
    };
    format!(
        r#"{sample}
[oauth.registrations.gitlab]
adapter = "gitlab"
base_url = "https://gitlab.example.com"
redirect_uri = "https://broker.example.com/v1/oauth/callback/gitlab"
client_id = "broker-app"
client_secret_ref = "file:/etc/agent-access-broker/secrets/gitlab-oauth-client-secret"
client_auth = "client_secret_post"
rotation = "rotate_both"

[oauth.registrations.gitlab.permission_profiles.default]
scopes = ["api", "write_repository"]
audience = "gitlab"
target = "https://gitlab.example.com"

[credentials.connections.gitlab]
display_name = "GitLab"
{token_profile}oauth = {{ registration = "gitlab", profile = "default" }}

[credentials.per_user.gitlab]
type = "connection"
connection = "gitlab"

[providers.gitlab]
api_base_url = "https://gitlab.example.com/api/v4"
web_base_url = "https://gitlab.example.com"
allowed_upstream_hosts = ["https://gitlab.example.com/api/v4/**"]
"#,
        sample = include_str!("../../../../../agent-access-broker.production.sample.toml"),
    )
}

#[test]
fn gitlab_rest_alone_on_a_gitlab_oauth_connection_passes_full_config_validation() {
    for token_profile in [true, false] {
        let config = agent_access_core::parse_broker_config_raw(
            "gitlab-rest-oauth.toml",
            &gitlab_rest_oauth_config(token_profile),
            &Arc::new(crate::test_composition::backend_registry()),
        )
        .unwrap();
        assert_eq!(
            agent_access_core::validate_broker_config(&config).map_err(|error| error.to_string()),
            Ok(()),
            "token_profile: {token_profile}"
        );
    }
}
