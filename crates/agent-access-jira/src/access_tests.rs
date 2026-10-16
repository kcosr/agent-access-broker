//! Jira with delegated (OAuth) access: requests route through the Atlassian
//! gateway on the configured site, pinned to its cloud ID and the gateway
//! audience before each one, with one 401 recovery per operation across
//! lookups and execution, and receipts for writes whose read-back the
//! connection stopped. Static tokens keep their routes. Attachment
//! downloads present either only within the configured site, revalidating
//! delegated access before each authorized redirect hop.
use super::*;
use agent_access_atlassian::ATLASSIAN_OAUTH_AUDIENCE;
use agent_access_provider::host::{HostPort, delegated_credential, port_failure};
use agent_access_provider::test_support::{
    InvocationBuilder, ScopeRequestFixture, TestHost, basic_credential, bearer_credential,
    delegated_binding_id,
};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const CLOUD_ID: &str = "11111111-2222-4333-8444-555555555555";
const OTHER_CLOUD_ID: &str = "99999999-8888-4777-8666-555555555555";
const GATEWAY: &str = "/ex/jira/11111111-2222-4333-8444-555555555555/rest/api/3";
const SITE: &str = "/rest/api/3";

/// A delegated lease with the host's contract: access `oauth-<n>` with
/// version `v<n>` for `target`, one recovery per operation, which renews the
/// access, and a record of the versions marked rejected.
struct Lease {
    target: &'static str,
    current: AtomicUsize,
    revalidation_failure: Mutex<Option<ProviderError>>,
    recovered: AtomicBool,
    recoveries: AtomicUsize,
    rejected: Mutex<Vec<String>>,
}

impl Lease {
    fn new(target: &'static str) -> Arc<Self> {
        Arc::new(Self {
            target,
            current: AtomicUsize::new(1),
            revalidation_failure: Mutex::default(),
            recovered: AtomicBool::new(false),
            recoveries: AtomicUsize::new(0),
            rejected: Mutex::default(),
        })
    }

    fn rejected(&self) -> Vec<String> {
        self.rejected.lock().unwrap().clone()
    }

    fn fail_revalidation(&self, failure: ProviderError) {
        *self.revalidation_failure.lock().unwrap() = Some(failure);
    }
}

#[async_trait]
impl DelegatedLease for Lease {
    fn access(&self) -> DelegatedAccess {
        let n = self.current.load(Ordering::SeqCst);
        DelegatedAccess::new(
            format!("oauth-{n}"),
            self.target,
            ATLASSIAN_OAUTH_AUDIENCE,
            format!("v{n}"),
            i64::MAX,
        )
    }
    fn binding_identity(&self) -> DelegatedBindingId {
        delegated_binding_id("alice-atlassian")
    }
    async fn revalidate(&self) -> Result<(), ProviderError> {
        match self.revalidation_failure.lock().unwrap().clone() {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
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

/// The host's lease failures when access needs refreshing: the refresh was
/// throttled, is in progress elsewhere, or needs a reconnect.
fn lease_failures() -> [ProviderError; 3] {
    [
        port_failure(
            HostPort::DelegatedLease,
            ProviderError::error(
                ReasonCode::UpstreamRateLimited,
                "jira OAuth token refresh is rate limited",
            )
            .with_upstream_rate_limit("jira", Some(UpstreamRetryAfter::after_seconds(30))),
        ),
        port_failure(
            HostPort::DelegatedLease,
            ProviderError::error(ReasonCode::ConcurrencyLimited, "oauth_refresh_busy"),
        ),
        port_failure(
            HostPort::DelegatedLease,
            ProviderError::deny(ReasonCode::CredentialInvalid, "oauth_reconnect_required"),
        ),
    ]
}

/// Jira on one site with the gateway enabled, its site route and gateway
/// route both served by `server`.
fn provider(server: &MockServer) -> JiraProvider {
    let mut config: JiraProviderConfig = serde_json::from_value(json!({
        "tenant_host": "example.atlassian.net",
        "cloud_id": CLOUD_ID,
        "allowed_upstream_hosts": [
            format!("{}/**", server.uri()),
            "https://api.atlassian.com/ex/jira/**",
        ],
    }))
    .unwrap();
    config
        .attachments
        .media_types
        .push("text/plain".to_string());
    let backend = HttpJiraBackend::new_with_api_base(
        config.clone(),
        ProviderLimits::default(),
        Url::parse(&format!("{}{SITE}/", server.uri())).unwrap(),
    )
    .with_gateway_origin(&server.uri(), &TestHost::default())
    .unwrap();
    JiraProvider::from_backend(config, ProviderLimits::default(), Arc::new(backend))
}

fn eng_scopes() -> ResourceScopes {
    BTreeMap::from([("project".to_string(), vec!["ENG".to_string()])])
}

/// `inputs` for `action`, admitted on project `ENG` with `credential` as the
/// execution material and lookup access.
fn delegated_invocation(
    action: &str,
    inputs: Value,
    credential: &DelegatedCredential,
) -> ProviderInvocation {
    InvocationBuilder::new("jira", action)
        .inputs(inputs)
        .resources(eng_scopes())
        .credential_mode(CredentialMode::PerUser)
        .delegated(credential.clone())
        .delegated_lookup(credential.clone())
        .build()
}

async fn resolve(
    provider: &JiraProvider,
    action: &str,
    inputs: Value,
    credential: &DelegatedCredential,
) -> Result<ScopeResolution, ProviderError> {
    let fixture =
        ScopeRequestFixture::new("jira", action, inputs).delegated_lookup(credential.clone());
    provider.resolve_scopes(fixture.request()).await
}

fn issue(key: &str) -> Value {
    json!({
        "id": "10001",
        "key": key,
        "fields": {
            "project": { "key": "ENG" },
            "summary": "Broken build",
            "status": { "name": "Open" },
            "issuetype": { "name": "Task" },
            "description": null
        }
    })
}

/// Serves `verb` on `route` to `authorization` with `status` and `body`.
async fn answer(
    server: &MockServer,
    verb: &str,
    route: &str,
    authorization: &str,
    status: u16,
    body: Value,
) {
    Mock::given(method(verb))
        .and(path(route))
        .and(header("authorization", authorization))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(server)
        .await;
}

/// Answers with `response`, after which every revalidation of `lease`
/// fails with `failure`: Jira took this request, then the OAuth connection
/// failed before the next one.
struct ThenLeaseFails {
    lease: Arc<Lease>,
    failure: ProviderError,
    response: ResponseTemplate,
}

impl Respond for ThenLeaseFails {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        self.lease.fail_revalidation(self.failure.clone());
        self.response.clone()
    }
}

/// The method, path and presented authorization of each request `server`
/// got.
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

#[test]
fn jira_declares_delegated_access_beside_its_token_profiles() {
    let config: JiraProviderConfig = serde_json::from_value(json!({
        "tenant_host": "example.atlassian.net",
        "cloud_id": CLOUD_ID,
        "allowed_upstream_hosts": ["https://api.atlassian.com/ex/jira/**"],
    }))
    .unwrap();
    let descriptor = jira_descriptor(&config);
    assert!(descriptor.credentials.delegated.is_some());
    assert_eq!(
        descriptor.credential_profile_kind("atlassian-bearer-token"),
        Some("bearer_token")
    );
}

/// OAuth always goes through the gateway on the configured site: the lookup
/// before policy, the lookup at execution and the read all present the
/// connection's access, pinned to the site's cloud ID and the gateway
/// audience. Access for another site is refused before anything is sent.
#[tokio::test]
async fn oauth_reads_go_through_the_gateway_pinned_to_the_site() {
    let server = MockServer::start().await;
    let route = format!("{GATEWAY}/issue/ENG-1");
    answer(
        &server,
        "GET",
        &route,
        "Bearer oauth-1",
        200,
        issue("ENG-1"),
    )
    .await;
    let lease = Lease::new(CLOUD_ID);
    let credential = delegated_credential(lease.clone());
    let provider = provider(&server);
    let inputs = json!({ "issue": "ENG-1" });

    let resolution = resolve(&provider, "issue.view", inputs.clone(), &credential)
        .await
        .unwrap();
    assert_eq!(resolution.scopes(), &eng_scopes());
    let result = provider
        .invoke(delegated_invocation(
            "issue.view",
            inputs.clone(),
            &credential,
        ))
        .await
        .unwrap();
    assert_eq!(result.result["key"], "ENG-1", "{}", result.result);
    assert_eq!(
        requests(&server).await,
        vec![format!("GET {route} Bearer oauth-1"); 3]
    );
    assert!(lease.rejected().is_empty());

    let elsewhere = delegated_credential(Lease::new(OTHER_CLOUD_ID));
    let error = resolve(&provider, "issue.view", inputs.clone(), &elsewhere)
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
    let error = provider
        .invoke(delegated_invocation("issue.view", inputs, &elsewhere))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
    assert_eq!(requests(&server).await.len(), 3);
}

/// Static tokens keep their routes: a Basic API token reaches the site and a
/// bearer token the gateway.
#[tokio::test]
async fn static_tokens_keep_routing_by_kind() {
    let server = MockServer::start().await;
    let basic = "Basic YWxpY2VAZXhhbXBsZS5jb206dG9rZW4=";
    answer(
        &server,
        "GET",
        &format!("{SITE}/issue/ENG-1"),
        basic,
        200,
        issue("ENG-1"),
    )
    .await;
    answer(
        &server,
        "GET",
        &format!("{GATEWAY}/issue/ENG-1"),
        "Bearer service-token",
        200,
        issue("ENG-1"),
    )
    .await;
    let provider = provider(&server);
    for credential in [
        basic_credential("alice@example.com", "token"),
        bearer_credential("service-token"),
    ] {
        provider
            .invoke(
                InvocationBuilder::new("jira", "issue.view")
                    .inputs(json!({ "issue": "ENG-1" }))
                    .resources(eng_scopes())
                    .credential(credential.clone())
                    .lookup_credential(credential)
                    .build(),
            )
            .await
            .unwrap();
    }
    assert_eq!(
        requests(&server).await,
        [
            format!("GET {SITE}/issue/ENG-1 {basic}"),
            format!("GET {SITE}/issue/ENG-1 {basic}"),
            format!("GET {GATEWAY}/issue/ENG-1 Bearer service-token"),
            format!("GET {GATEWAY}/issue/ENG-1 Bearer service-token"),
        ]
    );
}

/// A lookup's 401 spends the operation's one recovery: the rejected version
/// is marked, the lookup repeats once with renewed access, and execution
/// presents the renewed access. A later 401 in the same operation fails
/// with the lease's own refusal, without another recovery.
#[tokio::test]
async fn one_recovery_spans_the_lookups_and_execution() {
    let server = MockServer::start().await;
    let route = format!("{GATEWAY}/issue/ENG-1");
    answer(&server, "GET", &route, "Bearer oauth-1", 401, json!({})).await;
    answer(
        &server,
        "GET",
        &route,
        "Bearer oauth-2",
        200,
        issue("ENG-1"),
    )
    .await;
    let lease = Lease::new(CLOUD_ID);
    let credential = delegated_credential(lease.clone());
    let provider = provider(&server);
    let inputs = json!({ "issue": "ENG-1" });

    resolve(&provider, "issue.view", inputs.clone(), &credential)
        .await
        .unwrap();
    provider
        .invoke(delegated_invocation(
            "issue.view",
            inputs.clone(),
            &credential,
        ))
        .await
        .unwrap();
    assert_eq!(
        requests(&server).await,
        [
            format!("GET {route} Bearer oauth-1"),
            format!("GET {route} Bearer oauth-2"),
            format!("GET {route} Bearer oauth-2"),
            format!("GET {route} Bearer oauth-2"),
        ]
    );
    assert_eq!(lease.rejected(), ["v1"]);
    assert_eq!(lease.recoveries.load(Ordering::SeqCst), 1);

    // The lookups recovered; execution's 401 then exhausts the lease.
    let server = MockServer::start().await;
    let comments = format!("{GATEWAY}/issue/ENG-1/comment");
    answer(&server, "GET", &route, "Bearer oauth-1", 401, json!({})).await;
    answer(
        &server,
        "GET",
        &route,
        "Bearer oauth-2",
        200,
        issue("ENG-1"),
    )
    .await;
    answer(&server, "GET", &comments, "Bearer oauth-2", 401, json!({})).await;
    let lease = Lease::new(CLOUD_ID);
    let credential = delegated_credential(lease.clone());
    let provider = self::provider(&server);
    let error = provider
        .invoke(delegated_invocation("comment.list", inputs, &credential))
        .await
        .unwrap_err();
    assert_eq!(error, already_recovered());
    assert_eq!(
        requests(&server).await,
        [
            format!("GET {route} Bearer oauth-1"),
            format!("GET {route} Bearer oauth-2"),
            format!("GET {comments} Bearer oauth-2"),
        ]
    );
    assert_eq!(lease.rejected(), ["v1", "v2"]);
    assert_eq!(lease.recoveries.load(Ordering::SeqCst), 1);
}

/// A request Jira rejects before and after the recovery fails as
/// `credential_invalid`, asking the person to reconnect.
#[tokio::test]
async fn a_second_401_is_credential_invalid_with_reconnect() {
    let server = MockServer::start().await;
    let route = format!("{GATEWAY}/issue/ENG-1");
    answer(&server, "GET", &route, "Bearer oauth-1", 401, json!({})).await;
    answer(&server, "GET", &route, "Bearer oauth-2", 401, json!({})).await;
    let lease = Lease::new(CLOUD_ID);
    let credential = delegated_credential(lease.clone());
    let error = resolve(
        &provider(&server),
        "issue.view",
        json!({ "issue": "ENG-1" }),
        &credential,
    )
    .await
    .unwrap_err();
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
    assert_eq!(
        error.message,
        "Jira rejected the connected Atlassian account's access again; reconnect Atlassian in the Broker portal if this repeats"
    );
    assert_eq!(requests(&server).await.len(), 2);
    assert_eq!(lease.rejected(), ["v1", "v2"]);
    assert_eq!(lease.recoveries.load(Ordering::SeqCst), 1);
}

fn create_inputs() -> Value {
    json!({ "project": "ENG", "issueTypeId": "10001", "summary": "Broken build" })
}

/// Jira created the issue, then the connection failed before the read-back
/// could be sent, or Jira rejected the read-back's access again: the write
/// is reported applied but unverified, never as a plain credential error
/// inviting a retry.
#[tokio::test]
async fn delegated_failures_at_a_read_back_report_the_write_applied_unverified() {
    let created = json!({ "id": "10002", "key": "ENG-2" });
    let locators = json!({ "issueId": "10002", "issueKey": "ENG-2" });
    for failure in lease_failures() {
        let server = MockServer::start().await;
        let lease = Lease::new(CLOUD_ID);
        Mock::given(method("POST"))
            .and(path(format!("{GATEWAY}/issue")))
            .respond_with(ThenLeaseFails {
                lease: lease.clone(),
                failure: failure.clone(),
                response: ResponseTemplate::new(201).set_body_json(created.clone()),
            })
            .mount(&server)
            .await;
        let credential = delegated_credential(lease.clone());
        let error = provider(&server)
            .invoke(delegated_invocation(
                "issue.create",
                create_inputs(),
                &credential,
            ))
            .await
            .unwrap_err();
        assert_eq!(
            error.reason_code(),
            ReasonCode::MutationVerificationFailed,
            "{failure:?}"
        );
        let result = error.result.as_deref().unwrap();
        assert_eq!(result["mutationStatus"], "applied_unverified");
        assert_eq!(result["retrySafe"], false);
        assert_eq!(result["verificationStage"], "post_create_readback");
        assert_eq!(result["safeLocators"], locators);
        assert_eq!(
            requests(&server).await,
            [format!("POST {GATEWAY}/issue Bearer oauth-1")]
        );
    }

    // The read-back is rejected before and after the recovery.
    let server = MockServer::start().await;
    answer(
        &server,
        "POST",
        &format!("{GATEWAY}/issue"),
        "Bearer oauth-1",
        201,
        created,
    )
    .await;
    let readback = format!("{GATEWAY}/issue/ENG-2");
    answer(&server, "GET", &readback, "Bearer oauth-1", 401, json!({})).await;
    answer(&server, "GET", &readback, "Bearer oauth-2", 401, json!({})).await;
    let credential = delegated_credential(Lease::new(CLOUD_ID));
    let error = provider(&server)
        .invoke(delegated_invocation(
            "issue.create",
            create_inputs(),
            &credential,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::MutationVerificationFailed);
    assert_eq!(error.result.as_deref().unwrap()["safeLocators"], locators);
    assert_eq!(requests(&server).await.len(), 3);
}

/// Before the write, the connection's failure passes through unchanged:
/// nothing was sent, or Jira's 401 applied nothing.
#[tokio::test]
async fn delegated_failures_before_the_write_pass_through_unchanged() {
    for failure in lease_failures() {
        let server = MockServer::start().await;
        let lease = Lease::new(CLOUD_ID);
        lease.fail_revalidation(failure.clone());
        let credential = delegated_credential(lease);
        let error = provider(&server)
            .invoke(delegated_invocation(
                "issue.create",
                create_inputs(),
                &credential,
            ))
            .await
            .unwrap_err();
        assert_eq!(error, failure);
        assert!(requests(&server).await.is_empty());
    }

    // Jira rejects the write, and the operation has already recovered.
    let server = MockServer::start().await;
    answer(
        &server,
        "POST",
        &format!("{GATEWAY}/issue"),
        "Bearer oauth-1",
        401,
        json!({}),
    )
    .await;
    let lease = Lease::new(CLOUD_ID);
    lease.recovered.store(true, Ordering::SeqCst);
    let credential = delegated_credential(lease.clone());
    let error = provider(&server)
        .invoke(delegated_invocation(
            "issue.create",
            create_inputs(),
            &credential,
        ))
        .await
        .unwrap_err();
    assert_eq!(error, already_recovered());
    assert_eq!(lease.rejected(), ["v1"]);
}

/// An upload's 401 recovers once and sends the upload again, reopening its
/// body; a download's 401 from Jira recovers once and starts over.
#[tokio::test]
async fn uploads_and_downloads_repeat_once_after_a_delegated_401() {
    let server = MockServer::start().await;
    let uploads = format!("{GATEWAY}/issue/ENG-1/attachments");
    answer(&server, "POST", &uploads, "Bearer oauth-1", 401, json!({})).await;
    answer(
        &server,
        "POST",
        &uploads,
        "Bearer oauth-2",
        200,
        json!([{
            "id": "10055",
            "filename": "evidence.txt",
            "mimeType": "text/plain",
            "size": 8
        }]),
    )
    .await;
    let lease = Lease::new(CLOUD_ID);
    let credential = AtlassianCredential::delegated(
        delegated_credential(lease.clone()),
        Some(Arc::from(CLOUD_ID)),
    );
    let provider = provider(&server);
    let backend = provider.backend.clone();
    let response = backend
        .add_attachment(
            "ENG-1",
            JiraAttachmentUpload {
                filename: "evidence.txt".to_string(),
                content_type: "text/plain".to_string(),
                size: 8,
                sha256: sha256_hex(b"evidence"),
                bytes: b"evidence".to_vec(),
                temp_file: None,
            },
            &credential,
        )
        .await
        .unwrap();
    assert_eq!(response.value.id, "10055");
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2);
    for request in &received {
        assert!(
            String::from_utf8_lossy(&request.body).contains("evidence"),
            "the upload is sent whole each time"
        );
    }
    assert_eq!(lease.rejected(), ["v1"]);

    let server = MockServer::start().await;
    let content = format!("{GATEWAY}/attachment/content/10055");
    answer(&server, "GET", &content, "Bearer oauth-1", 401, json!({})).await;
    Mock::given(method("GET"))
        .and(path(content.as_str()))
        .and(header("authorization", "Bearer oauth-2"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_bytes(b"evidence".to_vec()),
        )
        .mount(&server)
        .await;
    let lease = Lease::new(CLOUD_ID);
    let credential = AtlassianCredential::delegated(
        delegated_credential(lease.clone()),
        Some(Arc::from(CLOUD_ID)),
    );
    let response = self::provider(&server)
        .backend
        .attachment_content("10055", &credential)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        requests(&server).await,
        [
            format!("GET {content} Bearer oauth-1"),
            format!("GET {content} Bearer oauth-2"),
        ]
    );
    assert_eq!(lease.rejected(), ["v1"]);
}

/// Jira's backend for one site with the gateway enabled and served by
/// `server`, allowing `media` as an Atlassian media host.
fn backend_with_media(server: &MockServer, media: &MockServer) -> HttpJiraBackend {
    let config: JiraProviderConfig = serde_json::from_value(json!({
        "tenant_host": "example.atlassian.net",
        "cloud_id": CLOUD_ID,
        "allowed_upstream_hosts": [
            format!("{}/**", server.uri()),
            format!("{}/**", media.uri()),
            "https://api.atlassian.com/ex/jira/**",
        ],
    }))
    .unwrap();
    HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}{SITE}/", server.uri())).unwrap(),
    )
    .with_gateway_origin(&server.uri(), &TestHost::default())
    .unwrap()
}

async fn redirect(server: &MockServer, route: &str, location: String) {
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", location))
        .mount(server)
        .await;
}

async fn serve(server: &MockServer, route: &str) {
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_bytes(b"evidence".to_vec()),
        )
        .mount(server)
        .await;
}

/// An attachment download on the gateway presents OAuth access or a
/// service account's bearer token only within the configured site. A
/// redirect to another site's cloud ID, directly or back from a media host,
/// fails before it is sent; a plain media redirect still works and carries
/// no credential.
#[tokio::test]
async fn attachment_downloads_never_present_credentials_to_another_site() {
    let lease = Lease::new(CLOUD_ID);
    let credentials = [
        (
            AtlassianCredential::delegated(
                delegated_credential(lease.clone()),
                Some(Arc::from(CLOUD_ID)),
            ),
            "Bearer oauth-1",
        ),
        (
            AtlassianCredential::from_static(bearer_credential("service-token")),
            "Bearer service-token",
        ),
    ];
    for (credential, presented) in credentials {
        let server = MockServer::start().await;
        let media = MockServer::start().await;
        let content = |id: &str| format!("{GATEWAY}/attachment/content/{id}");
        let elsewhere = |id: &str| {
            format!(
                "{}{}/attachment/content/{id}",
                server.uri(),
                GATEWAY.replace(CLOUD_ID, OTHER_CLOUD_ID)
            )
        };
        redirect(&server, &content("10001"), elsewhere("10001")).await;
        redirect(
            &server,
            &content("10002"),
            format!("{}/file/10002", media.uri()),
        )
        .await;
        redirect(&media, "/file/10002", elsewhere("10002")).await;
        redirect(
            &server,
            &content("10003"),
            format!("{}/file/10003", media.uri()),
        )
        .await;
        serve(&media, "/file/10003").await;
        // Whatever the other site would serve.
        for id in ["10001", "10002"] {
            let other_site = GATEWAY.replace(CLOUD_ID, OTHER_CLOUD_ID);
            serve(&server, &format!("{other_site}/attachment/content/{id}")).await;
        }
        let backend = backend_with_media(&server, &media);

        for id in ["10001", "10002"] {
            let error = backend
                .attachment_content(id, &credential)
                .await
                .err()
                .unwrap();
            assert_eq!(
                error,
                JiraBackendError::Protocol("Jira attachment redirect is invalid".to_string()),
                "{id}"
            );
        }
        let response = backend
            .attachment_content("10003", &credential)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            requests(&server).await,
            [
                format!("GET {} {presented}", content("10001")),
                format!("GET {} {presented}", content("10002")),
                format!("GET {} {presented}", content("10003")),
            ]
        );
        let media_hops = media.received_requests().await.unwrap();
        assert_eq!(media_hops.len(), 2);
        assert!(
            media_hops
                .iter()
                .all(|hop| !hop.headers.contains_key("authorization"))
        );
    }
    assert!(lease.rejected().is_empty());
}

/// Answers with `response` after another operation refreshed `lease`.
struct ThenRefreshed {
    lease: Arc<Lease>,
    response: ResponseTemplate,
}

impl Respond for ThenRefreshed {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        self.lease.current.fetch_add(1, Ordering::SeqCst);
        self.response.clone()
    }
}

/// Each authorized hop of a download presents access revalidated
/// immediately before it: a refresh between hops reaches the next hop, and a
/// connection lost between hops fails the download with the lease's own
/// failure before the next hop is sent.
#[tokio::test]
async fn attachment_downloads_revalidate_access_before_each_hop() {
    let server = MockServer::start().await;
    let media = MockServer::start().await;
    let backend = backend_with_media(&server, &media);
    let content = |id: &str| format!("{GATEWAY}/attachment/content/{id}");
    let attachment = |id: &str| format!("{GATEWAY}/attachment/{id}/evidence.txt");
    let found = |id: &str| {
        ResponseTemplate::new(302)
            .insert_header("Location", format!("{}{}", server.uri(), attachment(id)))
    };

    let lease = Lease::new(CLOUD_ID);
    Mock::given(path(content("10001")))
        .respond_with(ThenRefreshed {
            lease: lease.clone(),
            response: found("10001"),
        })
        .mount(&server)
        .await;
    serve(&server, &attachment("10001")).await;
    let credential = AtlassianCredential::delegated(
        delegated_credential(lease.clone()),
        Some(Arc::from(CLOUD_ID)),
    );
    let response = backend
        .attachment_content("10001", &credential)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        requests(&server).await,
        [
            format!("GET {} Bearer oauth-1", content("10001")),
            format!("GET {} Bearer oauth-2", attachment("10001")),
        ]
    );

    for (index, failure) in lease_failures().into_iter().enumerate() {
        let id = format!("1002{index}");
        let lease = Lease::new(CLOUD_ID);
        Mock::given(path(content(&id)))
            .respond_with(ThenLeaseFails {
                lease: lease.clone(),
                failure: failure.clone(),
                response: found(&id),
            })
            .mount(&server)
            .await;
        serve(&server, &attachment(&id)).await;
        let credential = AtlassianCredential::delegated(
            delegated_credential(lease.clone()),
            Some(Arc::from(CLOUD_ID)),
        );
        let before = requests(&server).await.len();
        let error = backend
            .attachment_content(&id, &credential)
            .await
            .err()
            .unwrap();
        assert_eq!(error, JiraBackendError::Credential(failure));
        assert_eq!(
            requests(&server).await[before..],
            [format!("GET {} Bearer oauth-1", content(&id))]
        );
        assert!(lease.rejected().is_empty());
    }
}
