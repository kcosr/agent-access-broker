//! Confluence with delegated (OAuth) access: requests route through the
//! Atlassian gateway on the configured site, pinned to its cloud ID and the
//! gateway audience before each one, with one 401 recovery per operation
//! across lookups and execution, and receipts for writes whose read-back the
//! connection stopped. Static tokens keep their routes. Attachment
//! downloads present either only within the configured site, revalidating
//! delegated access before each authorized redirect hop. Personal spaces
//! (`~key`) and spaces with a URL alias read and search through the gateway
//! like any other, with browser links on the site. List pagination reads
//! Confluence's site-relative `next` links below the gateway's site path.
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
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
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
    let config = site_config(server);
    let backend = gateway_backend(server, config.clone());
    ConfluenceProvider::with_backend(config, ProviderLimits::default(), Arc::new(backend))
}

/// The configuration of Confluence on one site with the gateway enabled,
/// allowing `server` beside the gateway.
fn site_config(server: &MockServer) -> ConfluenceProviderConfig {
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
    config
}

/// Confluence's backend for `config`, its site route and gateway route both
/// served by `server`.
fn gateway_backend(server: &MockServer, config: ConfluenceProviderConfig) -> HttpConfluenceBackend {
    HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}{SITE}/rest/api/", server.uri())).unwrap(),
    )
    .with_gateway_origin(&server.uri(), &TestHost::default())
    .unwrap()
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
        SearchAuthorizationScope::from_exact_values(vec!["~alice".to_string()]),
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

/// OAuth access on the gateway route, pinned to the site's cloud ID.
fn gateway_access() -> AtlassianCredential {
    AtlassianCredential::delegated(
        delegated_credential(Lease::new(CLOUD_ID)),
        Some(Arc::from(CLOUD_ID)),
    )
}

/// A v2 list page of `results`, with its `next` link in the body's
/// `_links.next`, in a `Link` header, or both, as Confluence sends them.
fn list_page(
    results: Value,
    body_next: Option<&str>,
    header_next: Option<&str>,
) -> ResponseTemplate {
    let mut body = json!({ "results": results, "_links": {} });
    if let Some(next) = body_next {
        body["_links"]["next"] = json!(next);
    }
    let mut response = ResponseTemplate::new(200);
    if let Some(next) = header_next {
        response = response.insert_header("Link", format!("<{next}>; rel=\"next\""));
    }
    response.set_body_json(body)
}

/// Every comment collection a `next` link pages: a page's footer and inline
/// comments, and a footer and an inline comment's replies.
const COMMENT_COLLECTIONS: [&str; 4] = [
    "pages/123456/footer-comments",
    "pages/123456/inline-comments",
    "footer-comments/5001/children",
    "inline-comments/6001/children",
];

/// Reads the first page of comment `collection` and returns the cursor of
/// its `next` link.
async fn next_comment_cursor(
    backend: &HttpConfluenceBackend,
    collection: &str,
    credential: &AtlassianCredential,
) -> Result<Option<String>, ConfluenceBackendError> {
    let kind = if collection.contains("footer") {
        ConfluenceCommentKind::Footer
    } else {
        ConfluenceCommentKind::Inline
    };
    let response = match collection.split('/').collect::<Vec<_>>()[..] {
        ["pages", page_id, _] => {
            backend
                .comments_page(
                    ConfluenceCommentListRequest {
                        kind,
                        container_type: ConfluenceCommentContainerType::Page,
                        container_id: page_id.to_string(),
                        body_format: None,
                        resolution_status: None,
                        sort: None,
                        max_results: 2,
                        cursor: None,
                    },
                    credential,
                )
                .await
        }
        [_, comment_id, "children"] => {
            backend
                .comment_replies_page(kind, comment_id, None, 2, None, credential)
                .await
        }
        _ => unreachable!("{collection}"),
    }?;
    Ok(response.value.next_cursor)
}

/// Through the gateway, Confluence writes a list's `next` link from its site
/// root, `/wiki/api/v2/...`, in the body or a `Link` header. Comment and
/// reply lists read it as naming their collection below the route's
/// `/ex/confluence/<cloud_id>/` path, for OAuth access and bearer tokens.
#[tokio::test]
async fn comment_and_reply_lists_read_site_relative_next_links_on_the_gateway() {
    let server = MockServer::start().await;
    for (credential, presented) in [
        (gateway_access(), "Bearer oauth-1"),
        (
            AtlassianCredential::from_static(bearer_credential("service-token")),
            "Bearer service-token",
        ),
    ] {
        for collection in COMMENT_COLLECTIONS {
            let route = format!("{GATEWAY}/api/v2/{collection}");
            let next = format!("/wiki/api/v2/{collection}?cursor=abc&limit=2");
            for (body_next, header_next) in [
                (Some(next.as_str()), None),
                (None, Some(next.as_str())),
                (Some(next.as_str()), Some(next.as_str())),
            ] {
                server.reset().await;
                Mock::given(method("GET"))
                    .and(path(route.as_str()))
                    .respond_with(list_page(json!([]), body_next, header_next))
                    .mount(&server)
                    .await;
                let backend = gateway_backend(&server, site_config(&server));
                assert_eq!(
                    next_comment_cursor(&backend, collection, &credential)
                        .await
                        .unwrap()
                        .as_deref(),
                    Some("abc"),
                    "{collection}: body {body_next:?}, header {header_next:?}"
                );
                assert_eq!(
                    requests(&server).await,
                    [format!("GET {route} {presented}")]
                );
            }
        }
    }
}

/// A `next` link that names anything but the collection on this route fails
/// the list, from the body or a `Link` header: another resource, the
/// collection below another site's cloud ID, another origin, or the gateway
/// origin without the site's path.
#[tokio::test]
async fn gateway_next_links_naming_another_collection_fail_the_list() {
    let server = MockServer::start().await;
    let origin = server.uri();
    for collection in COMMENT_COLLECTIONS {
        for (link, failure) in [
            (
                "/wiki/api/v2/pages/999999/footer-comments?cursor=abc".to_string(),
                "changed resource",
            ),
            (
                format!("/ex/confluence/{OTHER_CLOUD_ID}/wiki/api/v2/{collection}?cursor=abc"),
                "changed resource",
            ),
            (
                format!(
                    "https://evil.example/ex/confluence/{CLOUD_ID}/wiki/api/v2/{collection}?cursor=abc"
                ),
                "changed origin",
            ),
            (
                format!("{origin}/wiki/api/v2/pages/999999/footer-comments?cursor=abc"),
                "changed resource",
            ),
        ] {
            for (body_next, header_next) in
                [(Some(link.as_str()), None), (None, Some(link.as_str()))]
            {
                server.reset().await;
                Mock::given(method("GET"))
                    .and(path(format!("{GATEWAY}/api/v2/{collection}")))
                    .respond_with(list_page(json!([]), body_next, header_next))
                    .mount(&server)
                    .await;
                let backend = gateway_backend(&server, site_config(&server));
                assert_eq!(
                    next_comment_cursor(&backend, collection, &gateway_access()).await,
                    Err(ConfluenceBackendError::Protocol(format!(
                        "Confluence comment pagination {failure}"
                    ))),
                    "{collection}: body {body_next:?}, header {header_next:?}"
                );
            }
        }
    }
}

/// The method, path and query of each request `server` got.
async fn request_urls(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| {
            format!(
                "{} {}?{}",
                request.method,
                request.url.path(),
                request.url.query().unwrap_or_default()
            )
        })
        .collect()
}

/// A page's ancestors and its direct children, the read-back `page.move`
/// checks its order with, page through site-relative `next` links on the
/// gateway; a link below another site's cloud ID fails the read.
#[tokio::test]
async fn ancestor_and_direct_child_reads_page_through_the_gateway() {
    let server = MockServer::start().await;
    let ancestors = format!("{GATEWAY}/api/v2/pages/200/ancestors");
    let children = format!("{GATEWAY}/api/v2/pages/55555/direct-children");
    for (route, first, second) in [
        (
            &ancestors,
            json!([{"id": "folder-abc", "type": "folder"}]),
            json!([{"id": "55555", "type": "page"}]),
        ),
        (
            &children,
            json!([{"id": "100", "type": "page", "status": "current", "childPosition": 0}]),
            json!([{"id": "200", "type": "page", "status": "current", "childPosition": 1}]),
        ),
    ] {
        let next = route.replacen(GATEWAY, "/wiki", 1) + "?cursor=page-2&limit=250";
        Mock::given(method("GET"))
            .and(path(route.as_str()))
            .and(query_param_is_missing("cursor"))
            .and(header("authorization", "Bearer oauth-1"))
            .respond_with(list_page(first, Some(&next), None))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(route.as_str()))
            .and(query_param("cursor", "page-2"))
            .and(header("authorization", "Bearer oauth-1"))
            .respond_with(list_page(second, None, None))
            .mount(&server)
            .await;
    }
    let backend = gateway_backend(&server, site_config(&server));
    let credential = gateway_access();

    let read = backend.page_ancestors("200", &credential).await.unwrap();
    assert_eq!(
        read.value
            .iter()
            .map(|ancestor| ancestor.id.as_str())
            .collect::<Vec<_>>(),
        ["folder-abc", "55555"]
    );
    let read = backend
        .page_direct_children("55555", &credential)
        .await
        .unwrap();
    assert_eq!(
        read.value
            .iter()
            .map(|child| (child.id.as_str(), child.child_position))
            .collect::<Vec<_>>(),
        [("100", 0), ("200", 1)]
    );
    assert_eq!(
        request_urls(&server).await,
        [
            format!("GET {ancestors}?limit=250"),
            format!("GET {ancestors}?limit=250&cursor=page-2"),
            format!("GET {children}?limit=250"),
            format!("GET {children}?limit=250&cursor=page-2"),
        ]
    );

    server.reset().await;
    for (route, resource) in [(&ancestors, "ancestor"), (&children, "direct-child")] {
        let elsewhere = route.replacen(CLOUD_ID, OTHER_CLOUD_ID, 1) + "?cursor=page-2";
        Mock::given(method("GET"))
            .and(path(route.as_str()))
            .respond_with(list_page(json!([]), Some(&elsewhere), None))
            .mount(&server)
            .await;
        let error = if resource == "ancestor" {
            backend.page_ancestors("200", &credential).await.err()
        } else {
            backend
                .page_direct_children("55555", &credential)
                .await
                .err()
        };
        assert_eq!(
            error,
            Some(ConfluenceBackendError::Protocol(format!(
                "Confluence {resource} pagination changed resource"
            )))
        );
    }
}

fn footer_comment(id: &str) -> Value {
    json!({
        "id": id,
        "pageId": "123456",
        "status": "current",
        "body": { "storage": { "value": "<p>comment</p>", "representation": "storage" } }
    })
}

/// End to end through the gateway: a footer comment list's site-relative
/// `next` link becomes a continuation, which reads the second page on the
/// same route with the connection's access.
#[tokio::test]
async fn oauth_comment_list_pages_through_the_gateway() {
    let server = MockServer::start().await;
    let page_route = format!("{GATEWAY}/rest/api/content/123456");
    answer(
        &server,
        "GET",
        &page_route,
        "Bearer oauth-1",
        200,
        page("ENG"),
    )
    .await;
    let route = format!("{GATEWAY}/api/v2/pages/123456/footer-comments");
    let next =
        "/wiki/api/v2/pages/123456/footer-comments?cursor=page-2&limit=1&body-format=storage";
    Mock::given(method("GET"))
        .and(path(route.as_str()))
        .and(query_param_is_missing("cursor"))
        .and(header("authorization", "Bearer oauth-1"))
        .respond_with(list_page(
            json!([footer_comment("5001")]),
            Some(next),
            Some(next),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(route.as_str()))
        .and(query_param("cursor", "page-2"))
        .and(header("authorization", "Bearer oauth-1"))
        .respond_with(list_page(json!([footer_comment("5002")]), None, None))
        .mount(&server)
        .await;
    let credential = delegated_credential(Lease::new(CLOUD_ID));
    let provider = provider(&server);
    let inputs = json!({ "pageId": "123456", "maxResults": 1 });

    let first = invoke(
        &provider,
        delegated_invocation(
            "page.footer_comment.list",
            inputs.clone(),
            "ENG",
            &credential,
        ),
    )
    .await
    .unwrap();
    assert_eq!(first.result["comments"][0]["commentId"], "5001");
    assert_eq!(first.result["hasMore"], true);
    let token = first.result["nextPageToken"].as_str().unwrap();
    assert!(!token.contains("page-2"));

    let mut inputs = inputs;
    inputs["nextPageToken"] = json!(token);
    let second = invoke(
        &provider,
        delegated_invocation("page.footer_comment.list", inputs, "ENG", &credential),
    )
    .await
    .unwrap();
    assert_eq!(second.result["comments"][0]["commentId"], "5002");
    assert_eq!(second.result["hasMore"], false);
    assert_eq!(second.result["nextPageToken"], Value::Null);
    assert_eq!(
        requests(&server).await,
        [
            format!("GET {page_route} Bearer oauth-1"),
            format!("GET {route} Bearer oauth-1"),
            format!("GET {page_route} Bearer oauth-1"),
            format!("GET {route} Bearer oauth-1"),
        ]
    );
}

const ALIASED_PAGE_ID: &str = "70000000046";
const ALIASED_PAGE_LINK: &str = "/spaces/VECTOR/pages/70000000046/Deployment+Notes";

/// Page `id` in space `ROCKET`, whose URL alias is `VECTOR`, as the v1 API
/// returns it through the gateway: browser links relative to the site and
/// REST `self` links naming `api.atlassian.com`.
fn aliased_page(id: &str, title: &str, link: &str) -> Value {
    json!({
        "id": id,
        "type": "page",
        "status": "current",
        "title": title,
        "space": {
            "key": "ROCKET",
            "_links": {
                "webui": "/spaces/VECTOR",
                "self": format!("https://api.atlassian.com/ex/confluence/{CLOUD_ID}/wiki/rest/api/space/ROCKET")
            }
        },
        "version": { "number": 3 },
        "body": { "storage": { "value": "<p>body</p>" } },
        "_links": {
            "webui": link,
            "self": format!("https://api.atlassian.com/ex/confluence/{CLOUD_ID}/wiki/rest/api/content/{id}")
        }
    })
}

/// A space whose URL alias differs from its key, read with OAuth: a site
/// link naming the alias resolves through the gateway to the space key,
/// which policy admits, and the view's links name the alias on the site,
/// never the gateway. A link naming another space fails closed.
#[tokio::test]
async fn oauth_reads_a_page_by_its_space_alias_through_the_gateway() {
    let server = MockServer::start().await;
    let route = format!("{GATEWAY}/rest/api/content/{ALIASED_PAGE_ID}");
    answer(
        &server,
        "GET",
        &route,
        "Bearer oauth-1",
        200,
        aliased_page(ALIASED_PAGE_ID, "Deployment Notes", ALIASED_PAGE_LINK),
    )
    .await;
    let credential = delegated_credential(Lease::new(CLOUD_ID));
    let provider = provider(&server);
    let aliased_url = format!("https://example.atlassian.net/wiki{ALIASED_PAGE_LINK}");
    let inputs = json!({ "url": aliased_url });

    let resolution = resolve(&provider, "page.view", inputs.clone(), &credential)
        .await
        .unwrap();
    assert_eq!(resolution.scopes(), &space_scopes("ROCKET"));
    let result = invoke(
        &provider,
        delegated_invocation("page.view", inputs, "ROCKET", &credential),
    )
    .await
    .unwrap();
    assert_eq!(result.result["space"], "ROCKET", "{}", result.result);
    assert_eq!(result.result["webUrl"], aliased_url);
    assert_eq!(
        result.result["spaceUrl"],
        "https://example.atlassian.net/wiki/spaces/VECTOR"
    );
    assert!(
        !result.result.to_string().contains("api.atlassian.com"),
        "{}",
        result.result
    );

    let foreign = json!({
        "url": format!("https://example.atlassian.net/wiki/spaces/OTHER/pages/{ALIASED_PAGE_ID}/Deployment+Notes")
    });
    let error = resolve(&provider, "page.view", foreign, &credential)
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(
        error.message,
        "Confluence page URL space is neither the page's space key nor its URL alias"
    );
    // The lookup before policy, the read at execution and the refused
    // lookup, each with the connection's access on the gateway.
    assert_eq!(
        requests(&server).await,
        vec![format!("GET {route} Bearer oauth-1"); 3]
    );
}

/// A search through the gateway with OAuth keeps an aliased page's browser
/// links on the site. A browser link naming the gateway instead is replaced
/// by one the Broker builds on the site, and audited by its shape only.
#[tokio::test]
async fn oauth_search_keeps_aliased_links_on_the_site_through_the_gateway() {
    let server = MockServer::start().await;
    let route = format!("{GATEWAY}/rest/api/content/search");
    let gateway_link = format!(
        "https://api.atlassian.com/ex/confluence/{CLOUD_ID}/wiki/spaces/VECTOR/pages/70000000047/Gateway+Notes"
    );
    answer(
        &server,
        "GET",
        &route,
        "Bearer oauth-1",
        200,
        json!({
            "results": [
                { "content": aliased_page(ALIASED_PAGE_ID, "Deployment Notes", ALIASED_PAGE_LINK) },
                { "content": aliased_page("70000000047", "Gateway Notes", &gateway_link) },
            ]
        }),
    )
    .await;
    let credential = delegated_credential(Lease::new(CLOUD_ID));
    let request = InvocationBuilder::from(delegated_invocation(
        "search",
        json!({ "query": { "type": "cql", "value": "text ~ \"launch\"" }, "maxResults": 2 }),
        "ROCKET",
        &credential,
    ))
    .search(SearchAuthorization::new(
        "space".to_string(),
        SearchAuthorizationScope::from_exact_values(vec!["ROCKET".to_string()]),
    ))
    .build();
    let result = invoke(&provider(&server), request).await.unwrap();

    let pages = &result.result["pages"];
    assert_eq!(pages[0]["space"], "ROCKET", "{}", result.result);
    assert_eq!(
        pages[0]["webUrl"],
        format!("https://example.atlassian.net/wiki{ALIASED_PAGE_LINK}")
    );
    assert_eq!(
        pages[0]["spaceUrl"],
        "https://example.atlassian.net/wiki/spaces/VECTOR"
    );
    assert_eq!(
        pages[1]["webUrl"],
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=70000000047"
    );
    assert!(
        !result.result.to_string().contains("api.atlassian.com"),
        "{}",
        result.result
    );
    let audit = result.audit.as_ref().unwrap();
    assert_eq!(audit["browserUrlFallbacks"]["count"], 1);
    assert_eq!(
        audit["browserUrlFallbacks"]["entries"][0]["rule"],
        "authority_mismatch"
    );
    assert!(!audit.to_string().contains("api.atlassian.com"));
    assert_eq!(
        requests(&server).await,
        [format!("GET {route} Bearer oauth-1")]
    );
}
