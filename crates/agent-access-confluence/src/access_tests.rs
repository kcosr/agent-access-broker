//! Confluence with delegated (OAuth) access: requests route through the
//! Atlassian gateway on the configured site, pinned to its cloud ID and the
//! gateway audience before each one, with one 401 recovery per operation
//! across lookups and execution, and receipts for writes whose read-back the
//! connection stopped. Static tokens keep their routes. Attachment
//! downloads present either only within the configured site, revalidating
//! delegated access before each authorized redirect hop. Personal spaces
//! (`~key`) read and search through the gateway like any other.
use super::*;
use agent_access_atlassian::ATLASSIAN_OAUTH_AUDIENCE;
use agent_access_provider::host::{
    HostPort, delegated_credential, port_failure, with_correlation_context,
};
use agent_access_provider::test_support::{
    InvocationBuilder, ScopeRequestFixture, TestHost, basic_credential, bearer_credential,
    delegated_binding_id,
};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const CLOUD_ID: &str = "11111111-2222-4333-8444-555555555555";
const OTHER_CLOUD_ID: &str = "99999999-8888-4777-8666-555555555555";
const GATEWAY: &str = "/ex/confluence/11111111-2222-4333-8444-555555555555/wiki";
const SITE: &str = "/wiki";

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
                "confluence OAuth token refresh is rate limited",
            )
            .with_upstream_rate_limit("confluence", Some(UpstreamRetryAfter::after_seconds(30))),
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

/// Confluence on one site with the gateway enabled, its site route and
/// gateway route both served by `server`.
fn provider(server: &MockServer) -> ConfluenceProvider {
    let mut config: ConfluenceProviderConfig = serde_json::from_value(json!({
        "tenant_host": "example.atlassian.net",
        "cloud_id": CLOUD_ID,
        "allowed_upstream_hosts": [
            format!("{}/**", server.uri()),
            "https://api.atlassian.com/ex/confluence/**",
        ],
    }))
    .unwrap();
    config.content.page_formats = vec!["storage".to_string()];
    let backend = HttpConfluenceBackend::new_with_api_base(
        config.clone(),
        ProviderLimits::default(),
        Url::parse(&format!("{}{SITE}/rest/api/", server.uri())).unwrap(),
    )
    .with_gateway_origin(&server.uri(), &TestHost::default())
    .unwrap();
    ConfluenceProvider::with_backend(config, ProviderLimits::default(), Arc::new(backend))
}

fn space_scopes(key: &str) -> ResourceScopes {
    ResourceScopes::from([("space".to_string(), vec![key.to_string()])])
}

/// `inputs` for `action`, admitted on space `key` with `credential` as the
/// execution material and lookup access.
fn delegated_invocation(
    action: &str,
    inputs: Value,
    key: &str,
    credential: &DelegatedCredential,
) -> ProviderInvocation {
    InvocationBuilder::new("confluence", action)
        .inputs(inputs)
        .resources(space_scopes(key))
        .credential_mode(CredentialMode::PerUser)
        .delegated(credential.clone())
        .delegated_lookup(credential.clone())
        .build()
}

async fn resolve(
    provider: &ConfluenceProvider,
    action: &str,
    inputs: Value,
    credential: &DelegatedCredential,
) -> Result<ScopeResolution, ProviderError> {
    let fixture =
        ScopeRequestFixture::new("confluence", action, inputs).delegated_lookup(credential.clone());
    provider.resolve_scopes(fixture.request()).await
}

async fn invoke(
    provider: &ConfluenceProvider,
    request: ProviderInvocation,
) -> Result<ProviderResult, ProviderError> {
    with_correlation_context(CorrelationContext::for_tests(), provider.invoke(request)).await
}

/// A current page in space `key`, with its storage body.
fn page(key: &str) -> Value {
    json!({
        "id": "123456", "type": "page", "status": "current", "title": "Notes",
        "space": {"key": key}, "version": {"number": 7},
        "body": {"storage": {"value": "<p>notes</p>"}}
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
/// fails with `failure`: Confluence took this request, then the OAuth
/// connection failed before the next one.
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
fn confluence_declares_delegated_access_beside_its_token_profiles() {
    let config: ConfluenceProviderConfig = serde_json::from_value(json!({
        "tenant_host": "example.atlassian.net",
        "cloud_id": CLOUD_ID,
        "allowed_upstream_hosts": ["https://api.atlassian.com/ex/confluence/**"],
    }))
    .unwrap();
    let descriptor = confluence_descriptor(&config);
    assert!(descriptor.credentials.delegated.is_some());
    assert_eq!(
        descriptor.credential_profile_kind("atlassian-bearer-token"),
        Some("bearer_token")
    );
}

/// OAuth always goes through the gateway on the configured site: a page in
/// a personal space resolves its `~key` scope and reads through the gateway
/// with the connection's access, pinned to the site's cloud ID and the
/// gateway audience. Access for another site is refused before anything is
/// sent.
#[tokio::test]
async fn oauth_reads_a_personal_space_page_through_the_gateway() {
    let server = MockServer::start().await;
    let route = format!("{GATEWAY}/rest/api/content/123456");
    answer(
        &server,
        "GET",
        &route,
        "Bearer oauth-1",
        200,
        page("~alice"),
    )
    .await;
    let lease = Lease::new(CLOUD_ID);
    let credential = delegated_credential(lease.clone());
    let provider = provider(&server);
    let inputs = json!({ "pageId": "123456" });

    let resolution = resolve(&provider, "page.view", inputs.clone(), &credential)
        .await
        .unwrap();
    assert_eq!(resolution.scopes(), &space_scopes("~alice"));
    let result = invoke(
        &provider,
        delegated_invocation("page.view", inputs.clone(), "~alice", &credential),
    )
    .await
    .unwrap();
    assert_eq!(result.result["space"], "~alice", "{}", result.result);
    assert_eq!(
        result.result["spaceUrl"],
        "https://example.atlassian.net/wiki/spaces/~alice"
    );
    assert_eq!(
        requests(&server).await,
        vec![format!("GET {route} Bearer oauth-1"); 2]
    );
    assert!(lease.rejected().is_empty());

    let elsewhere = delegated_credential(Lease::new(OTHER_CLOUD_ID));
    let error = resolve(&provider, "page.view", inputs, &elsewhere)
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
    assert_eq!(requests(&server).await.len(), 2);
}

/// A CQL search limited to a personal space goes through the gateway with
/// the connection's access and returns that space's pages.
#[tokio::test]
async fn oauth_searches_a_personal_space_through_the_gateway() {
    let server = MockServer::start().await;
    let route = format!("{GATEWAY}/rest/api/content/search");
    Mock::given(method("GET"))
        .and(path(route.as_str()))
        .and(query_param("cql", "space IN (\"~alice\") AND type = page"))
        .and(header("authorization", "Bearer oauth-1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "results": [page("~alice")] })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let credential = delegated_credential(Lease::new(CLOUD_ID));
    let request = InvocationBuilder::from(delegated_invocation(
        "search",
        json!({ "query": { "type": "cql", "value": "" } }),
        "~alice",
        &credential,
    ))
    .search(SearchAuthorization::new(
        "space".to_string(),
        SearchAuthorizationScope::Finite {
            values: vec!["~alice".to_string()],
        },
    ))
    .build();
    let result = invoke(&provider(&server), request).await.unwrap();
    assert_eq!(
        result.result["pages"][0]["space"], "~alice",
        "{}",
        result.result
    );
    assert_eq!(
        requests(&server).await,
        [format!("GET {route} Bearer oauth-1")]
    );
}

/// Static tokens keep their routes: a Basic API token reaches the site and a
/// bearer token the gateway.
#[tokio::test]
async fn static_tokens_keep_routing_by_kind() {
    let server = MockServer::start().await;
    let basic = "Basic YWxpY2VAZXhhbXBsZS5jb206dG9rZW4=";
    let site = format!("{SITE}/rest/api/content/123456");
    let gateway = format!("{GATEWAY}/rest/api/content/123456");
    answer(&server, "GET", &site, basic, 200, page("ENG")).await;
    answer(
        &server,
        "GET",
        &gateway,
        "Bearer service-token",
        200,
        page("ENG"),
    )
    .await;
    let provider = provider(&server);
    for credential in [
        basic_credential("alice@example.com", "token"),
        bearer_credential("service-token"),
    ] {
        invoke(
            &provider,
            InvocationBuilder::new("confluence", "page.view")
                .inputs(json!({ "pageId": "123456" }))
                .resources(space_scopes("ENG"))
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
            format!("GET {site} {basic}"),
            format!("GET {gateway} Bearer service-token"),
        ]
    );
}

/// A lookup's 401 spends the operation's one recovery, and execution
/// presents the renewed access; a later 401 in the same operation fails with
/// the lease's own refusal. A request rejected before and after the
/// recovery fails as `credential_invalid`, asking for reconnection.
#[tokio::test]
async fn one_recovery_spans_the_lookup_and_execution() {
    let server = MockServer::start().await;
    let route = format!("{GATEWAY}/rest/api/content/123456");
    answer(&server, "GET", &route, "Bearer oauth-1", 401, json!({})).await;
    answer(&server, "GET", &route, "Bearer oauth-2", 200, page("ENG")).await;
    let lease = Lease::new(CLOUD_ID);
    let credential = delegated_credential(lease.clone());
    let provider = provider(&server);
    let inputs = json!({ "pageId": "123456" });
    resolve(&provider, "page.view", inputs.clone(), &credential)
        .await
        .unwrap();
    invoke(
        &provider,
        delegated_invocation("page.view", inputs.clone(), "ENG", &credential),
    )
    .await
    .unwrap();
    assert_eq!(
        requests(&server).await,
        [
            format!("GET {route} Bearer oauth-1"),
            format!("GET {route} Bearer oauth-2"),
            format!("GET {route} Bearer oauth-2"),
        ]
    );
    assert_eq!(lease.rejected(), ["v1"]);
    assert_eq!(lease.recoveries.load(Ordering::SeqCst), 1);

    // The lookup recovered; execution's 401 then exhausts the lease.
    let server = MockServer::start().await;
    answer(&server, "GET", &route, "Bearer oauth-1", 401, json!({})).await;
    Mock::given(method("GET"))
        .and(path(route.as_str()))
        .and(header("authorization", "Bearer oauth-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page("ENG")))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    answer(&server, "GET", &route, "Bearer oauth-2", 401, json!({})).await;
    let lease = Lease::new(CLOUD_ID);
    let credential = delegated_credential(lease.clone());
    let provider = self::provider(&server);
    resolve(&provider, "page.view", inputs.clone(), &credential)
        .await
        .unwrap();
    let error = invoke(
        &provider,
        delegated_invocation("page.view", inputs.clone(), "ENG", &credential),
    )
    .await
    .unwrap_err();
    assert_eq!(error, already_recovered());
    assert_eq!(lease.rejected(), ["v1", "v2"]);
    assert_eq!(lease.recoveries.load(Ordering::SeqCst), 1);

    // Rejected before and after the recovery.
    let server = MockServer::start().await;
    answer(&server, "GET", &route, "Bearer oauth-1", 401, json!({})).await;
    answer(&server, "GET", &route, "Bearer oauth-2", 401, json!({})).await;
    let lease = Lease::new(CLOUD_ID);
    let error = resolve(
        &self::provider(&server),
        "page.view",
        inputs,
        &delegated_credential(lease.clone()),
    )
    .await
    .unwrap_err();
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
    assert_eq!(
        error.message,
        "Confluence rejected the connected Atlassian account's access again; reconnect Atlassian in the Broker portal if this repeats"
    );
    assert_eq!(requests(&server).await.len(), 2);
    assert_eq!(lease.rejected(), ["v1", "v2"]);
}

fn create_inputs() -> Value {
    json!({
        "space": "ENG",
        "title": "Created",
        "contentFormat": "storage",
        "content": "<p>created</p>"
    })
}

async fn mount_space(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("{GATEWAY}/api/v2/spaces")))
        .and(query_param("keys", "ENG"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"id": "98765", "key": "ENG", "status": "current", "homepageId": "55555"}]
        })))
        .mount(server)
        .await;
}

fn created_page() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "id": "900001",
        "type": "page",
        "title": "Created",
        "spaceId": "98765",
        "parentId": "55555",
        "parentType": "page",
        "status": "current",
        "version": { "number": 1 }
    }))
}

/// Confluence created the page, then the connection failed before the
/// read-back could be sent: the write is reported applied but unverified,
/// never as a plain credential error inviting a retry. Before the write, the
/// connection's failure passes through unchanged.
#[tokio::test]
async fn delegated_failures_report_writes_by_whether_they_applied() {
    let locators = json!({ "pageId": "900001", "parentPageId": "55555" });
    for failure in lease_failures() {
        let server = MockServer::start().await;
        mount_space(&server).await;
        let lease = Lease::new(CLOUD_ID);
        Mock::given(method("POST"))
            .and(path(format!("{GATEWAY}/api/v2/pages")))
            .respond_with(ThenLeaseFails {
                lease: lease.clone(),
                failure: failure.clone(),
                response: created_page(),
            })
            .mount(&server)
            .await;
        let credential = delegated_credential(lease.clone());
        let error = invoke(
            &provider(&server),
            delegated_invocation("page.create", create_inputs(), "ENG", &credential),
        )
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
        assert_eq!(requests(&server).await.len(), 2);

        // The same failure before the write.
        let server = MockServer::start().await;
        mount_space(&server).await;
        let lease = Lease::new(CLOUD_ID);
        Mock::given(method("GET"))
            .and(path(format!("{GATEWAY}/api/v2/spaces")))
            .respond_with(ThenLeaseFails {
                lease: lease.clone(),
                failure: failure.clone(),
                response: ResponseTemplate::new(200).set_body_json(json!({
                    "results": [{"id": "98765", "key": "ENG", "status": "current", "homepageId": "55555"}]
                })),
            })
            .with_priority(1)
            .mount(&server)
            .await;
        let credential = delegated_credential(lease);
        let error = invoke(
            &provider(&server),
            delegated_invocation("page.create", create_inputs(), "ENG", &credential),
        )
        .await
        .unwrap_err();
        // The outcome is the lease's own, with no receipt; the write's
        // failure audit is added.
        assert_eq!(
            (
                error.decision(),
                error.reason_code(),
                &error.message,
                &error.result
            ),
            (
                failure.decision(),
                failure.reason_code(),
                &failure.message,
                &failure.result
            )
        );
        assert_eq!(
            error.audit.as_deref().unwrap()["upstreamFailure"],
            "delegated_access_failed"
        );
        assert_eq!(
            requests(&server).await,
            [format!("GET {GATEWAY}/api/v2/spaces Bearer oauth-1")]
        );
    }
}

/// Confluence's backend for one site with the gateway enabled and served by
/// `server`, allowing `media` as an Atlassian media host.
fn backend_with_media(server: &MockServer, media: &MockServer) -> HttpConfluenceBackend {
    let config: ConfluenceProviderConfig = serde_json::from_value(json!({
        "tenant_host": "example.atlassian.net",
        "cloud_id": CLOUD_ID,
        "allowed_upstream_hosts": [
            format!("{}/**", server.uri()),
            format!("{}/**", media.uri()),
            "https://api.atlassian.com/ex/confluence/**",
        ],
    }))
    .unwrap();
    HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}{SITE}/rest/api/", server.uri())).unwrap(),
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

/// The REST download route of attachment `id` on page 55555.
fn download_route(id: &str) -> String {
    format!("{GATEWAY}/rest/api/content/55555/child/attachment/{id}/download")
}

/// Where Confluence keeps attachment `id`'s bytes on `site`'s gateway path.
fn stored(site: &str, id: &str) -> String {
    format!("/ex/confluence/{site}/wiki/download/attachments/55555/{id}.txt")
}

/// An attachment download on the gateway presents OAuth access or a
/// service account's bearer token only within the configured site,
/// including its `/wiki/download/attachments/` path outside the REST API. A
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
        let at = |route: String| format!("{}{route}", server.uri());
        redirect(
            &server,
            &download_route("1"),
            at(stored(OTHER_CLOUD_ID, "1")),
        )
        .await;
        redirect(
            &server,
            &download_route("2"),
            format!("{}/file/2", media.uri()),
        )
        .await;
        redirect(&media, "/file/2", at(stored(OTHER_CLOUD_ID, "2"))).await;
        redirect(
            &server,
            &download_route("3"),
            format!("{}/file/3", media.uri()),
        )
        .await;
        serve(&media, "/file/3").await;
        redirect(&server, &download_route("4"), at(stored(CLOUD_ID, "4"))).await;
        serve(&server, &stored(CLOUD_ID, "4")).await;
        // Whatever the other site would serve.
        for id in ["1", "2"] {
            serve(&server, &stored(OTHER_CLOUD_ID, id)).await;
        }
        let backend = backend_with_media(&server, &media);

        for id in ["1", "2"] {
            let error = backend
                .attachment_content("55555", id, &credential)
                .await
                .err()
                .unwrap();
            assert_eq!(
                error,
                ConfluenceBackendError::Protocol(
                    "Confluence attachment redirect is invalid".to_string()
                ),
                "{id}"
            );
        }
        for id in ["3", "4"] {
            let response = backend
                .attachment_content("55555", id, &credential)
                .await
                .unwrap();
            assert_eq!(response.status, 200, "{id}");
        }
        assert_eq!(
            requests(&server).await,
            [
                format!("GET {} {presented}", download_route("1")),
                format!("GET {} {presented}", download_route("2")),
                format!("GET {} {presented}", download_route("3")),
                format!("GET {} {presented}", download_route("4")),
                format!("GET {} {presented}", stored(CLOUD_ID, "4")),
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
    let found = |id: &str| {
        ResponseTemplate::new(302).insert_header(
            "Location",
            format!("{}{}", server.uri(), stored(CLOUD_ID, id)),
        )
    };

    let lease = Lease::new(CLOUD_ID);
    Mock::given(path(download_route("1")))
        .respond_with(ThenRefreshed {
            lease: lease.clone(),
            response: found("1"),
        })
        .mount(&server)
        .await;
    serve(&server, &stored(CLOUD_ID, "1")).await;
    let credential = AtlassianCredential::delegated(
        delegated_credential(lease.clone()),
        Some(Arc::from(CLOUD_ID)),
    );
    let response = backend
        .attachment_content("55555", "1", &credential)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        requests(&server).await,
        [
            format!("GET {} Bearer oauth-1", download_route("1")),
            format!("GET {} Bearer oauth-2", stored(CLOUD_ID, "1")),
        ]
    );

    for (index, failure) in lease_failures().into_iter().enumerate() {
        let id = format!("lost-{index}");
        let lease = Lease::new(CLOUD_ID);
        Mock::given(path(download_route(&id)))
            .respond_with(ThenLeaseFails {
                lease: lease.clone(),
                failure: failure.clone(),
                response: found(&id),
            })
            .mount(&server)
            .await;
        serve(&server, &stored(CLOUD_ID, &id)).await;
        let credential = AtlassianCredential::delegated(
            delegated_credential(lease.clone()),
            Some(Arc::from(CLOUD_ID)),
        );
        let before = requests(&server).await.len();
        let error = backend
            .attachment_content("55555", &id, &credential)
            .await
            .err()
            .unwrap();
        assert_eq!(error, ConfluenceBackendError::Credential(failure));
        assert_eq!(
            requests(&server).await[before..],
            [format!("GET {} Bearer oauth-1", download_route(&id))]
        );
        assert!(lease.rejected().is_empty());
    }
}
