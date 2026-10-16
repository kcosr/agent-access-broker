//! GitLab REST with delegated (OAuth) access: per-request pinning, one 401
//! recovery per operation across lookups and execution, and static tokens
//! presented as before.
use super::*;
use agent_access_provider::host::{HostPort, delegated_credential, port_failure};
use agent_access_provider::test_support::{
    InvocationBuilder, ScopeRequestFixture, TestHost, basic_credential, bearer_credential,
    delegated_binding_id,
};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PROJECT_PATH: &str = "/api/v4/projects/sip%2Fservice";

/// A delegated lease with the host's contract: access `oauth-<n>` with
/// version `v<n>`, one recovery per operation, which renews the access, and
/// a record of the versions marked rejected.
struct Lease {
    target: String,
    audience: &'static str,
    binding: &'static str,
    current: AtomicUsize,
    /// Each revalidation renews the access, as a refresh by another
    /// operation between two requests does.
    renew_on_revalidate: bool,
    revalidation_failure: Option<ProviderError>,
    recovered: AtomicBool,
    recoveries: AtomicUsize,
    rejected: Mutex<Vec<String>>,
}

impl Lease {
    fn new(target: &str) -> Self {
        Self {
            target: target.to_owned(),
            audience: "gitlab",
            binding: "alice-gitlab",
            current: AtomicUsize::new(1),
            renew_on_revalidate: false,
            revalidation_failure: None,
            recovered: AtomicBool::new(false),
            recoveries: AtomicUsize::new(0),
            rejected: Mutex::default(),
        }
    }

    fn rejected(&self) -> Vec<String> {
        self.rejected.lock().unwrap().clone()
    }
}

/// The host's failure for an operation that already recovered.
fn already_recovered() -> ProviderError {
    port_failure(
        HostPort::DelegatedLease,
        ProviderError::deny(
            ReasonCode::CredentialInvalid,
            "delegated credential was already recovered for this invocation",
        ),
    )
}

#[async_trait]
impl DelegatedLease for Lease {
    fn access(&self) -> DelegatedAccess {
        let n = self.current.load(Ordering::SeqCst);
        DelegatedAccess::new(
            format!("oauth-{n}"),
            self.target.clone(),
            self.audience,
            format!("v{n}"),
            i64::MAX,
        )
    }
    fn binding_identity(&self) -> DelegatedBindingId {
        delegated_binding_id(self.binding)
    }
    async fn revalidate(&self) -> Result<(), ProviderError> {
        if let Some(failure) = &self.revalidation_failure {
            return Err(failure.clone());
        }
        if self.renew_on_revalidate {
            self.current.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
    fn mark_rejected(&self, version: &str) -> Result<(), ProviderError> {
        self.rejected.lock().unwrap().push(version.to_owned());
        Ok(())
    }
    async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
        if self.recovered.swap(true, Ordering::SeqCst) {
            return Err(already_recovered());
        }
        self.recoveries.fetch_add(1, Ordering::SeqCst);
        self.current.fetch_add(1, Ordering::SeqCst);
        Ok(self.access())
    }
}

/// GitLab REST on the test server's instance, accepting HTML uploads.
fn config(server: &MockServer) -> GitlabProviderConfig {
    let mut config: GitlabProviderConfig = serde_json::from_value(json!({
        "api_base_url": format!("{}/api/v4", server.uri()),
        "web_base_url": server.uri(),
        "allowed_upstream_hosts": [format!("{}/api/v4/**", server.uri())],
    }))
    .unwrap();
    config.attachments.media_types.push("text/html".to_string());
    config
}

fn provider(server: &MockServer) -> GitlabProvider {
    GitlabProvider::new(config(server), &TestHost::default().context()).unwrap()
}

/// `inputs` for `action`, admitted on `sip/service` with `credential` as the
/// execution material and lookup access.
fn delegated_invocation(
    action: &str,
    inputs: Value,
    credential: &DelegatedCredential,
) -> ProviderInvocation {
    InvocationBuilder::new("gitlab", action)
        .inputs(inputs)
        .identity(crate::InvocationIdentity::new("alice".to_string(), true))
        .resources(repository_scopes_from_path("sip/service"))
        .credential_mode(CredentialMode::PerUser)
        .delegated(credential.clone())
        .delegated_lookup(credential.clone())
        .build()
}

fn project_inputs() -> Value {
    json!({ "project": "sip/service" })
}

async fn resolve(
    provider: &GitlabProvider,
    action: &str,
    credential: &DelegatedCredential,
) -> Result<ScopeResolution, ProviderError> {
    resolve_with(provider, action, project_inputs(), credential).await
}

async fn resolve_with(
    provider: &GitlabProvider,
    action: &str,
    inputs: Value,
    credential: &DelegatedCredential,
) -> Result<ScopeResolution, ProviderError> {
    let fixture =
        ScopeRequestFixture::new("gitlab", action, inputs).delegated_lookup(credential.clone());
    provider.resolve_scopes(fixture.request()).await
}

/// Serves `path` to `token` with `status` and `body`.
async fn answer(
    server: &MockServer,
    verb: &str,
    route: &str,
    token: &str,
    status: u16,
    body: Value,
) {
    Mock::given(method(verb))
        .and(path(route))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(server)
        .await;
}

fn project() -> Value {
    json!({ "id": 42, "path_with_namespace": "sip/service" })
}

/// The method, path and presented token of each request the server got.
async fn requests(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| {
            format!(
                "{} {} {}",
                request.method,
                request.url.path(),
                request
                    .headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("-")
            )
        })
        .collect()
}

/// Backend validation accepts a per-user connection that offers only OAuth,
/// or a token profile alongside OAuth, beside a static service credential.
#[test]
fn gitlab_validation_accepts_delegated_per_user_connections() {
    let config: GitlabProviderConfig = serde_json::from_value(json!({
        "api_base_url": "https://gitlab.example.com/api/v4",
        "web_base_url": "https://gitlab.example.com",
        "allowed_upstream_hosts": ["https://gitlab.example.com/api/v4/**"],
    }))
    .unwrap();
    let limits = ProviderLimits::default();
    for credentials in [
        ServiceCredentialKinds::new(None, Some("oauth")).with_per_user_delegated(true),
        ServiceCredentialKinds::new(Some("bearer_token"), Some("bearer_token"))
            .with_per_user_delegated(true),
    ] {
        let mut errors = Vec::new();
        config.validate(
            &ValidationContext::new("production", "managed", &limits, credentials),
            &mut errors,
        );
        assert_eq!(errors, Vec::<String>::new(), "{credentials:?}");
    }
}

#[test]
fn gitlab_rest_declares_delegated_access_beside_its_token_profile() {
    let server_less: GitlabProviderConfig = serde_json::from_value(json!({
        "api_base_url": "https://gitlab.example.com/api/v4",
        "web_base_url": "https://gitlab.example.com",
        "allowed_upstream_hosts": ["https://gitlab.example.com/api/v4/**"],
    }))
    .unwrap();
    let descriptor = gitlab_descriptor(&server_less);
    assert!(descriptor.credentials.delegated.is_some());
    assert_eq!(
        descriptor.credential_profile_kind("gitlab-access-token"),
        Some("bearer_token")
    );
}

/// A lookup's 401 spends the operation's one recovery: the rejected version
/// is marked, the lookup repeats once with renewed access, and the rest of
/// the operation, including execution, presents the renewed access.
#[tokio::test]
async fn a_lookup_401_recovers_once_and_execution_presents_the_renewed_access() {
    let server = MockServer::start().await;
    answer(&server, "GET", PROJECT_PATH, "oauth-1", 401, json!({})).await;
    answer(&server, "GET", PROJECT_PATH, "oauth-2", 200, project()).await;
    let lease = Arc::new(Lease::new(&server.uri()));
    let credential = delegated_credential(lease.clone());
    let provider = provider(&server);

    let resolution = resolve(&provider, "project.view", &credential)
        .await
        .unwrap();
    assert_eq!(
        resolution.scopes(),
        &repository_scopes_from_path("sip/service")
    );
    let result = provider
        .invoke(delegated_invocation(
            "project.view",
            project_inputs(),
            &credential,
        ))
        .await
        .unwrap();
    assert_eq!(result.result["project"]["id"], 42);
    assert_eq!(
        requests(&server).await,
        [
            format!("GET {PROJECT_PATH} Bearer oauth-1"),
            format!("GET {PROJECT_PATH} Bearer oauth-2"),
            format!("GET {PROJECT_PATH} Bearer oauth-2"),
            format!("GET {PROJECT_PATH} Bearer oauth-2"),
        ]
    );
    assert_eq!(lease.rejected(), ["v1"]);
    assert_eq!(lease.recoveries.load(Ordering::SeqCst), 1);
}

/// After the operation's one recovery, a later 401, whether it answers
/// execution or the repeated request itself, marks its version rejected and
/// fails as `credential_invalid` without another recovery or request: the
/// lease's own refusal passes through unchanged, and a repeated request's
/// second 401 asks the person to reconnect.
#[tokio::test]
async fn a_second_401_fails_as_reconnect_required_without_another_recovery() {
    // The lookup recovered; execution's 401 then exhausts the lease.
    let server = MockServer::start().await;
    answer(&server, "GET", PROJECT_PATH, "oauth-1", 401, json!({})).await;
    answer(&server, "GET", PROJECT_PATH, "oauth-2", 200, project()).await;
    let issue = "/api/v4/projects/42/issues/7";
    answer(&server, "GET", issue, "oauth-2", 401, json!({})).await;
    let lease = Arc::new(Lease::new(&server.uri()));
    let credential = delegated_credential(lease.clone());
    let provider = provider(&server);
    let inputs = json!({ "project": "sip/service", "iid": 7 });
    resolve_with(&provider, "issue.view", inputs.clone(), &credential)
        .await
        .unwrap();
    let error = provider
        .invoke(delegated_invocation("issue.view", inputs, &credential))
        .await
        .unwrap_err();
    assert_eq!(error, already_recovered());
    assert_eq!(
        requests(&server).await,
        [
            format!("GET {PROJECT_PATH} Bearer oauth-1"),
            format!("GET {PROJECT_PATH} Bearer oauth-2"),
            format!("GET {PROJECT_PATH} Bearer oauth-2"),
            format!("GET {issue} Bearer oauth-2"),
        ]
    );
    assert_eq!(lease.rejected(), ["v1", "v2"]);
    assert_eq!(lease.recoveries.load(Ordering::SeqCst), 1);

    // One request rejected before and after the recovery.
    let server = MockServer::start().await;
    answer(&server, "GET", PROJECT_PATH, "oauth-1", 401, json!({})).await;
    answer(&server, "GET", PROJECT_PATH, "oauth-2", 401, json!({})).await;
    let lease = Arc::new(Lease::new(&server.uri()));
    let credential = delegated_credential(lease.clone());
    let provider = self::provider(&server);
    let error = resolve(&provider, "project.view", &credential)
        .await
        .unwrap_err();
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
    assert!(
        error.message.contains("reconnect GitLab"),
        "{}",
        error.message
    );
    assert_eq!(requests(&server).await.len(), 2);
    assert_eq!(lease.rejected(), ["v1", "v2"]);
    assert_eq!(lease.recoveries.load(Ordering::SeqCst), 1);
}

/// Access renewed between requests, by a refresh elsewhere, is pinned
/// afresh before each request; nothing is rejected or recovered.
#[tokio::test]
async fn access_refreshed_between_requests_is_presented_without_recovery() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PROJECT_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(project()))
        .mount(&server)
        .await;
    let lease = Arc::new(Lease {
        renew_on_revalidate: true,
        ..Lease::new(&server.uri())
    });
    let credential = delegated_credential(lease.clone());
    let provider = provider(&server);
    resolve(&provider, "project.view", &credential)
        .await
        .unwrap();
    provider
        .invoke(delegated_invocation(
            "project.view",
            project_inputs(),
            &credential,
        ))
        .await
        .unwrap();
    assert_eq!(
        requests(&server).await,
        [2, 3, 4].map(|n| format!("GET {PROJECT_PATH} Bearer oauth-{n}"))
    );
    assert!(lease.rejected().is_empty());
    assert_eq!(lease.recoveries.load(Ordering::SeqCst), 0);
}

/// A search's page token binds the delegated binding of the execution
/// access, so it opens after a refresh and not under another connection.
#[tokio::test]
async fn delegated_search_page_tokens_survive_refresh_but_not_another_connection() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PROJECT_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(project()))
        .mount(&server)
        .await;
    let issue = |iid: u64| json!({ "id": 1000 + iid, "iid": iid, "project_id": 42 });
    let next = format!(
        "<{}/api/v4/projects/42/issues?page=2&per_page=50>; rel=\"next\"",
        server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/issues"))
        .and(query_param_is_missing("page"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-next-page", "2")
                .insert_header("link", next.as_str())
                .set_body_json(vec![issue(1)]),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/issues"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(vec![issue(2)]))
        .mount(&server)
        .await;
    let provider = provider(&server);
    let lease = Arc::new(Lease {
        renew_on_revalidate: true,
        ..Lease::new(&server.uri())
    });
    let credential = delegated_credential(lease);
    let first = provider
        .invoke(delegated_invocation(
            "issue.search",
            project_inputs(),
            &credential,
        ))
        .await
        .unwrap();
    let token = first.result["nextPageToken"].as_str().unwrap().to_owned();
    let next_inputs = json!({ "project": "sip/service", "pageToken": token });
    let second = provider
        .invoke(delegated_invocation(
            "issue.search",
            next_inputs.clone(),
            &credential,
        ))
        .await
        .unwrap();
    assert_eq!(second.result["issues"][0]["iid"], 2);

    let reconnected = delegated_credential(Arc::new(Lease {
        binding: "alice-gitlab-reconnected",
        ..Lease::new(&server.uri())
    }));
    let error = provider
        .invoke(delegated_invocation(
            "issue.search",
            next_inputs,
            &reconnected,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
}

/// A write GitLab answers with 401 applied nothing, so it is repeated once
/// with renewed access; rejected again, it fails without a receipt.
#[tokio::test]
async fn a_rejected_write_is_repeated_once_with_renewed_access() {
    let issues = "/api/v4/projects/42/issues";
    let created = json!({ "id": 1007, "iid": 7, "project_id": 42, "title": "New issue" });
    for second_status in [201, 401] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(PROJECT_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(project()))
            .mount(&server)
            .await;
        answer(&server, "POST", issues, "oauth-1", 401, json!({})).await;
        answer(
            &server,
            "POST",
            issues,
            "oauth-2",
            second_status,
            created.clone(),
        )
        .await;
        let lease = Arc::new(Lease::new(&server.uri()));
        let credential = delegated_credential(lease.clone());
        let outcome = provider(&server)
            .invoke(delegated_invocation(
                "issue.create",
                json!({ "project": "sip/service", "title": "New issue" }),
                &credential,
            ))
            .await;
        let posts = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.method == "POST")
            .collect::<Vec<_>>();
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[0].body, posts[1].body);
        assert_eq!(
            requests(&server).await[1..],
            [
                format!("POST {issues} Bearer oauth-1"),
                format!("POST {issues} Bearer oauth-2"),
            ]
        );
        assert_eq!(lease.recoveries.load(Ordering::SeqCst), 1);
        if second_status == 201 {
            assert_eq!(outcome.unwrap().result["issue"]["iid"], 7);
            assert_eq!(lease.rejected(), ["v1"]);
        } else {
            let error = outcome.unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
            assert!(error.result.is_none(), "{:?}", error.result);
            assert_eq!(lease.rejected(), ["v1", "v2"]);
        }
    }
}

/// An upload GitLab answers with 401 is sent again whole with renewed
/// access, its spooled file reopened.
#[tokio::test]
async fn a_rejected_upload_is_sent_again_whole_with_renewed_access() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PROJECT_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(project()))
        .mount(&server)
        .await;
    let uploads = "/api/v4/projects/42/uploads";
    answer(&server, "POST", uploads, "oauth-1", 401, json!({})).await;
    answer(
        &server,
        "POST",
        uploads,
        "oauth-2",
        201,
        json!({"id": 17, "alt": "session", "url": "/uploads/secret/session.html",
            "full_path": "/-/project/42/uploads/secret/session.html",
            "markdown": "[session](/uploads/secret/session.html)"}),
    )
    .await;
    let lease = Arc::new(Lease::new(&server.uri()));
    let credential = delegated_credential(lease.clone());
    let contents = b"<html>private session</html>".to_vec();
    let part = BrokerBodyPart::in_memory(
        "session".to_string(),
        Some("session.html".to_string()),
        Some("text/html".to_string()),
        contents.clone(),
    );
    let temp_path = std::env::temp_dir().join(format!("gitlab-upload-{}", uuid::Uuid::new_v4()));
    std::fs::write(&temp_path, &contents).unwrap();
    let inputs = json!({"project": "sip/service", "attachments": [{
        "field": "session", "filename": "session.html", "contentType": "text/html",
        "size": part.size(), "sha256": part.sha256_hex(),
    }]});
    let request =
        InvocationBuilder::from(delegated_invocation("project.upload", inputs, &credential))
            .body_part(agent_access_provider::host::spooled_body_part(
                part.name.clone(),
                part.file_name.clone(),
                part.content_type.clone(),
                temp_path.clone(),
                part.size(),
                part.sha256_hex(),
            ))
            .build();
    let result = provider(&server).invoke(request).await.unwrap();
    assert_eq!(result.upstream_status, Some(201));
    let posts = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.method == "POST")
        .collect::<Vec<_>>();
    assert_eq!(posts.len(), 2);
    for post in &posts {
        assert!(
            std::str::from_utf8(&post.body)
                .unwrap()
                .contains("<html>private session</html>")
        );
    }
    assert_eq!(lease.rejected(), ["v1"]);
    assert!(!temp_path.exists());
}

/// Delegated access is pinned to this instance's target and the `gitlab`
/// audience, and a lease that cannot be revalidated fails unchanged; either
/// way nothing is sent.
#[tokio::test]
async fn delegated_access_is_refused_before_sending_unless_pinned_to_this_instance() {
    let server = MockServer::start().await;
    let provider = provider(&server);
    for lease in [
        Lease::new("https://gitlab.other.example"),
        Lease::new(&format!("{}/", server.uri())),
        Lease {
            audience: "records-api",
            ..Lease::new(&server.uri())
        },
    ] {
        let error = resolve(
            &provider,
            "project.view",
            &delegated_credential(Arc::new(lease)),
        )
        .await
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
        assert_eq!(
            error.message,
            "the GitLab OAuth connection does not grant access to this GitLab instance"
        );
    }
    let busy = port_failure(
        HostPort::DelegatedLease,
        ProviderError::error(ReasonCode::ConcurrencyLimited, "oauth_refresh_busy"),
    );
    let lease = Lease {
        revalidation_failure: Some(busy.clone()),
        ..Lease::new(&server.uri())
    };
    let credential = delegated_credential(Arc::new(lease));
    assert_eq!(
        resolve(&provider, "project.view", &credential)
            .await
            .unwrap_err(),
        busy
    );
    assert_eq!(
        provider
            .invoke(delegated_invocation(
                "project.view",
                project_inputs(),
                &credential
            ))
            .await
            .unwrap_err(),
        busy
    );

    // A provider whose API base names no GitLab instance pins nothing.
    let mut config = config(&server);
    config.api_base_url = format!("{}/custom", server.uri());
    let elsewhere = GitlabProvider::with_backend(
        config.clone(),
        Arc::new(HttpGitlabBackend::for_tests(config, ProviderLimits::default()).unwrap()),
    );
    let credential = delegated_credential(Arc::new(Lease::new(&server.uri())));
    assert_eq!(
        resolve(&elsewhere, "project.view", &credential)
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::CredentialInvalid
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// A static token is presented as before: its 401 is reported as GitLab's
/// rejection and never repeated, and a Basic credential never reaches
/// GitLab.
#[tokio::test]
async fn static_tokens_are_presented_as_before_and_never_repeated() {
    let server = MockServer::start().await;
    answer(&server, "GET", PROJECT_PATH, "gitlab-token", 401, json!({})).await;
    let provider = provider(&server);
    let lookup = |credential: ExecutionCredential| {
        ScopeRequestFixture::new("gitlab", "project.view", project_inputs())
            .lookup_credential(credential)
    };
    let error = provider
        .resolve_scopes(lookup(bearer_credential("gitlab-token")).request())
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamUnauthorized);
    assert_eq!(error.message, "GitLab rejected the selected credential");
    assert_eq!(
        requests(&server).await,
        [format!("GET {PROJECT_PATH} Bearer gitlab-token")]
    );
    let error = provider
        .resolve_scopes(lookup(basic_credential("alice", "gitlab-token")).request())
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(requests(&server).await.len(), 1);
}
