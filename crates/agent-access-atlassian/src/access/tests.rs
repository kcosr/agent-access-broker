//! The credential an Atlassian request presents: static tokens on the
//! route their token type selects, refused when it has none, delegated
//! access pinned to the gateway route's cloud ID and the gateway audience
//! before every request, one recovery per operation, attachment downloads
//! whose redirects present it only within the route's site, and the
//! receipts of writes whose verification the connection stopped.
use super::*;
use crate::{
    ATLASSIAN_API_TOKEN_PROFILE, ATLASSIAN_BEARER_TOKEN_PROFILE,
    ATLASSIAN_SCOPED_API_TOKEN_PROFILE, AtlassianProduct, AtlassianRoutes, AtlassianSite,
};
use agent_access_provider::host::{delegated_credential, port_failure};
use agent_access_provider::test_support::{
    TestHost, basic_credential, bearer_credential, credential_with_profile, delegated_binding_id,
};
use agent_access_provider::{DelegatedAccess, DelegatedBindingId, DelegatedLease};
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const CLOUD_ID: &str = "11111111-2222-4333-8444-555555555555";
const OTHER_CLOUD_ID: &str = "99999999-8888-4777-8666-555555555555";

/// A delegated lease with the host's contract: access `oauth-<n>` with
/// version `v<n>` for `target`, one recovery per operation, which renews the
/// access, and a record of the versions marked rejected.
struct Lease {
    target: &'static str,
    audience: &'static str,
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
            audience: ATLASSIAN_OAUTH_AUDIENCE,
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

/// The host's failure for a refresh already in progress elsewhere.
fn refresh_busy() -> ProviderError {
    port_failure(
        HostPort::DelegatedLease,
        ProviderError::error(ReasonCode::ConcurrencyLimited, "oauth_refresh_busy"),
    )
}

#[async_trait]
impl DelegatedLease for Lease {
    fn access(&self) -> DelegatedAccess {
        let n = self.current.load(Ordering::SeqCst);
        DelegatedAccess::new(
            format!("oauth-{n}"),
            self.target,
            self.audience,
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

fn delegated(lease: &Arc<Lease>, cloud_id: Option<&str>) -> AtlassianCredential {
    AtlassianCredential::delegated(delegated_credential(lease.clone()), cloud_id.map(Arc::from))
}

fn credential_error(error: AtlassianAccessError) -> ProviderError {
    match error {
        AtlassianAccessError::Credential(error) => error,
        other => panic!("expected a credential failure, got {other:?}"),
    }
}

/// A static token lent as `profile`.
fn profiled(credential: ExecutionCredential, profile: &str) -> AtlassianCredential {
    AtlassianCredential::from_static(credential_with_profile(credential, profile))
}

#[tokio::test]
async fn static_tokens_present_their_own_authorization_without_revealing_it() {
    for credential in [
        AtlassianCredential::from_static(basic_credential("agent@example.com", "site-secret")),
        AtlassianCredential::from_static(bearer_credential("gateway-secret")),
        profiled(
            basic_credential("agent@example.com", "site-secret"),
            ATLASSIAN_API_TOKEN_PROFILE,
        ),
        profiled(
            basic_credential("agent@example.com", "scoped-secret"),
            ATLASSIAN_SCOPED_API_TOKEN_PROFILE,
        ),
        profiled(
            bearer_credential("gateway-secret"),
            ATLASSIAN_BEARER_TOKEN_PROFILE,
        ),
    ] {
        assert!(!credential.is_delegated());
        let presented = credential.present().await.unwrap();
        assert!(!presented.is_delegated());
        let rendered = format!("{:?} {credential:?}", presented.authorization());
        assert!(
            !rendered.contains("secret") && !rendered.contains("agent@"),
            "{rendered}"
        );
    }
}

/// A static token Atlassian providers cannot route is never presented:
/// neither for a request nor for a download, whose first hop is not sent.
#[tokio::test]
async fn unroutable_static_tokens_are_never_presented() {
    let server = MockServer::start().await;
    let media = MockServer::start().await;
    let clients = gateway_clients(&server, &media);
    for (credential, reason) in [
        (
            profiled(
                basic_credential("agent@example.com", "token"),
                "gitlab-access-token",
            ),
            AtlassianRouteError::UnknownProfile,
        ),
        (
            profiled(
                bearer_credential("token"),
                ATLASSIAN_SCOPED_API_TOKEN_PROFILE,
            ),
            AtlassianRouteError::ProfileKindMismatch,
        ),
        (
            profiled(
                basic_credential("agent@example.com", "token"),
                ATLASSIAN_BEARER_TOKEN_PROFILE,
            ),
            AtlassianRouteError::ProfileKindMismatch,
        ),
    ] {
        assert_eq!(credential.route(), Err(reason));
        assert_eq!(
            credential.present().await.err(),
            Some(AtlassianAccessError::Unroutable(reason))
        );
        assert_eq!(
            download(
                &credential,
                &clients,
                &on_site(CLOUD_ID, "rest/api/3/attachment/content/1")
            )
            .await
            .unwrap_err(),
            AtlassianDownloadError::Access(AtlassianAccessError::Unroutable(reason))
        );
    }
    assert!(hops(&server).await.is_empty());
}

/// Delegated access is revalidated and pinned to the gateway route's cloud
/// ID and the gateway audience before every request; access for another
/// site, or a site without a gateway route, fails before anything is sent,
/// and the lease's own failure passes through unchanged.
#[tokio::test]
async fn delegated_access_is_pinned_to_the_gateway_site_and_audience() {
    let lease = Lease::new(CLOUD_ID);
    let credential = delegated(&lease, Some(CLOUD_ID));
    assert!(credential.is_delegated());
    assert_eq!(credential.route(), Ok(AtlassianRoute::Gateway));
    assert!(credential.static_credential().is_none());
    let presented = credential.present().await.unwrap();
    assert!(presented.is_delegated());
    assert_eq!(presented.version.as_deref(), Some("v1"));

    for cloud_id in [Some(OTHER_CLOUD_ID), None] {
        let error = credential_error(delegated(&lease, cloud_id).present().await.err().unwrap());
        assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
        assert_eq!(
            error.message,
            "the Atlassian OAuth connection does not grant access to this site through the Atlassian gateway"
        );
    }
    let mut other_audience = Lease::new(CLOUD_ID);
    Arc::get_mut(&mut other_audience).unwrap().audience = "jira";
    let error = credential_error(
        delegated(&other_audience, Some(CLOUD_ID))
            .present()
            .await
            .err()
            .unwrap(),
    );
    assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);

    *lease.revalidation_failure.lock().unwrap() = Some(refresh_busy());
    assert_eq!(
        credential.present().await.err(),
        Some(AtlassianAccessError::Credential(refresh_busy()))
    );
}

/// A 401 marks exactly the presented version rejected; the first attempt
/// recovers once and repeats with renewed access. Clones share the lease, so
/// a second recovery in the same operation, for a lookup or execution,
/// fails with the lease's own failure, and a repeated request's 401 fails as
/// `credential_invalid` asking for reconnection.
#[tokio::test]
async fn one_recovery_per_operation_and_a_second_rejection_is_credential_invalid() {
    let lease = Lease::new(CLOUD_ID);
    let lookup = delegated(&lease, Some(CLOUD_ID));
    let execution = lookup.clone();

    let first = lookup.present().await.unwrap();
    let replay = lookup
        .rejected(&first, Some("replay"), "Jira")
        .await
        .unwrap();
    assert_eq!(replay, "replay");
    assert_eq!(lease.rejected(), ["v1"]);
    let renewed = execution.present().await.unwrap();
    assert_eq!(renewed.version.as_deref(), Some("v2"));

    assert_eq!(
        execution.rejected(&renewed, Some(()), "Jira").await.err(),
        Some(AtlassianAccessError::Credential(already_recovered()))
    );
    let error = credential_error(
        execution
            .rejected(&renewed, None::<()>, "Confluence")
            .await
            .err()
            .unwrap(),
    );
    assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
    assert_eq!(
        error.message,
        "Confluence rejected the connected Atlassian account's access again; reconnect Atlassian in the Broker portal if this repeats"
    );
    assert_eq!(lease.rejected(), ["v1", "v2", "v2"]);
    assert_eq!(lease.recoveries.load(Ordering::SeqCst), 1);
}

#[test]
fn execution_and_lookup_access_fail_closed_without_atlassian_material() {
    let lease = Lease::new(CLOUD_ID);
    let cloud_id: Arc<str> = Arc::from(CLOUD_ID);
    let error =
        AtlassianCredential::from_execution(&ExecutionAccess::None, Some(&cloud_id)).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::CredentialNotProvisioned);
    assert!(
        AtlassianCredential::from_execution(
            &ExecutionAccess::Delegated(delegated_credential(lease.clone())),
            Some(&cloud_id)
        )
        .unwrap()
        .is_delegated()
    );
    assert!(
        AtlassianCredential::from_lookup(None, Some(&cloud_id))
            .unwrap()
            .is_none()
    );
    for access in [
        LookupAccess::Static(bearer_credential("token")),
        LookupAccess::Delegated(delegated_credential(lease)),
    ] {
        let credential = AtlassianCredential::from_lookup(Some(&access), Some(&cloud_id))
            .unwrap()
            .unwrap();
        assert_eq!(credential.route(), Ok(AtlassianRoute::Gateway));
    }
}

/// Delegated access routes through the gateway whatever else the site
/// allows, as bearer and scoped API tokens do, and is pinned to the cloud
/// ID the gateway route names.
#[test]
fn delegated_access_routes_through_the_gateway_on_its_cloud_id() {
    const PRODUCT: AtlassianProduct = JIRA;
    let hosts = [
        "https://example.atlassian.net/rest/api/3/**".to_owned(),
        "https://api.atlassian.com/ex/jira/**".to_owned(),
    ];
    let upper = CLOUD_ID.to_uppercase();
    let site = AtlassianSite {
        tenant_host: "example.atlassian.net",
        cloud_id: Some(&upper),
        egress_proxy: None,
        allowed_upstream_hosts: &hosts,
    };
    assert_eq!(site.gateway_cloud_id().as_deref(), Some(CLOUD_ID));
    let routes = AtlassianRoutes::new(PRODUCT, &site, &TestHost::default()).unwrap();
    let lease = Lease::new(CLOUD_ID);
    assert_eq!(
        routes
            .for_credential(&delegated(&lease, site.gateway_cloud_id().as_deref()))
            .unwrap()
            .api_base
            .as_str(),
        format!("https://api.atlassian.com/ex/jira/{CLOUD_ID}/rest/api/3/")
    );
    assert_eq!(
        routes
            .for_credential(&AtlassianCredential::from_static(basic_credential(
                "agent@example.com",
                "token"
            )))
            .unwrap()
            .api_base
            .as_str(),
        "https://example.atlassian.net/rest/api/3/"
    );
    // Without a cloud ID, delegated access has no route and no pin.
    let site = AtlassianSite {
        cloud_id: None,
        ..site
    };
    assert_eq!(site.gateway_cloud_id(), None);
    let routes = AtlassianRoutes::new(PRODUCT, &site, &TestHost::default()).unwrap();
    assert_eq!(
        routes
            .for_credential(&delegated(&lease, None))
            .err()
            .unwrap()
            .to_string(),
        "Jira OAuth connections, scoped API tokens and bearer tokens take the Atlassian gateway route, which requires providers.jira.cloud_id"
    );
}

/// After an accepted write, delegated access failing stops only the
/// verification: it reports `mutation_verification_failed` with an
/// `applied_unverified` receipt, keeping audit and upstream facts; other
/// failures keep their reason with the receipt, and an existing receipt
/// stands.
#[test]
fn delegated_failures_after_an_accepted_write_report_unverified_writes() {
    let locators = json!({ "issueKey": "ENG-1" });
    let delegated_failures = [
        refresh_busy(),
        already_recovered(),
        ProviderError::deny(
            ReasonCode::CredentialInvalid,
            "Jira rejected the connected Atlassian account's access again; reconnect Atlassian in the Broker portal if this repeats",
        ),
    ];
    for failure in delegated_failures {
        let unverified = failure
            .with_audit(json!({ "operation": "issue.create" }))
            .with_upstream(Some(201), Some(12))
            .unverified_after_atlassian_write("post_create_readback", locators.clone());
        assert_eq!(
            unverified.reason_code(),
            ReasonCode::MutationVerificationFailed
        );
        assert_eq!(unverified.reason_code().host_port(), None);
        assert_eq!(
            unverified.result.as_deref(),
            Some(&json!({
                "mutationStatus": "applied_unverified",
                "retrySafe": false,
                "verificationStage": "post_create_readback",
                "safeLocators": locators,
            }))
        );
        assert_eq!(
            unverified.audit.as_deref(),
            Some(&json!({ "operation": "issue.create" }))
        );
        assert_eq!(
            (unverified.upstream_status, unverified.upstream_duration_ms),
            (Some(201), Some(12))
        );
    }

    let timeout = ProviderError::error(ReasonCode::UpstreamTimeout, "Jira request timed out")
        .unverified_after_atlassian_write("post_create_readback", locators.clone());
    assert_eq!(timeout.reason_code(), ReasonCode::UpstreamTimeout);
    assert_eq!(
        timeout.result.as_deref().unwrap()["mutationStatus"],
        "applied_unverified"
    );

    let receipted = refresh_busy()
        .with_mutation_receipt(MutationReceipt::unknown())
        .unverified_after_atlassian_write("post_create_readback", locators);
    assert_eq!(receipted.reason_code(), ReasonCode::ConcurrencyLimited);
    assert_eq!(
        receipted.result.as_deref().unwrap()["mutationStatus"],
        "unknown"
    );
}

const JIRA: AtlassianProduct = AtlassianProduct {
    provider: "jira",
    name: "Jira",
    api_path: "rest/api/3/",
    other_api_paths: &[],
    status_reasons: &[],
};

/// Jira's gateway clients for the configured site, with the gateway served
/// by `gateway` and `media` allowed as an Atlassian media host.
fn gateway_clients(gateway: &MockServer, media: &MockServer) -> AtlassianClients {
    let hosts = [
        format!("{}/**", gateway.uri()),
        format!("{}/**", media.uri()),
    ];
    let site = AtlassianSite {
        tenant_host: "example.atlassian.net",
        cloud_id: Some(CLOUD_ID),
        egress_proxy: None,
        allowed_upstream_hosts: &hosts,
    };
    let base = format!("{}/ex/jira/{CLOUD_ID}/rest/api/3/", gateway.uri());
    AtlassianClients::new(
        JIRA,
        &site,
        Url::parse(&base).unwrap(),
        &TestHost::default(),
    )
    .unwrap()
}

/// The path of `site`'s gateway route below `rest`.
fn on_site(site: &str, rest: &str) -> String {
    format!("/ex/jira/{site}/{rest}")
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
        .respond_with(ResponseTemplate::new(200).set_body_string("evidence"))
        .mount(server)
        .await;
}

/// The path and presented authorization of each request `server` got.
async fn hops(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| {
            let authorization = request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("-");
            format!("{} {authorization}", request.url.path())
        })
        .collect()
}

async fn download(
    credential: &AtlassianCredential,
    clients: &AtlassianClients,
    route: &str,
) -> Result<Response, AtlassianDownloadError> {
    let url = Url::parse(&format!(
        "{}{route}",
        clients.site_base.origin().ascii_serialization()
    ));
    credential
        .download(
            clients,
            url.unwrap(),
            5,
            Duration::from_secs(5),
            "attachment.download",
            "Jira",
        )
        .await
}

/// On the gateway, which serves every Atlassian site from one origin, a
/// download presents the credential (OAuth, a service account's bearer
/// token or a scoped API token's Basic authorization) only within the
/// configured site's path, including its paths outside the API. A redirect
/// to another cloud ID or another product, directly or back from a media
/// host, fails before it is sent; plain media redirects keep working
/// without the credential.
#[tokio::test]
async fn downloads_present_credentials_only_within_the_configured_site() {
    let lease = Lease::new(CLOUD_ID);
    let credentials = [
        (delegated(&lease, Some(CLOUD_ID)), "Bearer oauth-1"),
        (
            AtlassianCredential::from_static(bearer_credential("service-token")),
            "Bearer service-token",
        ),
        (
            profiled(
                bearer_credential("service-token"),
                ATLASSIAN_BEARER_TOKEN_PROFILE,
            ),
            "Bearer service-token",
        ),
        (
            profiled(
                basic_credential("agent@example.com", "scoped-token"),
                ATLASSIAN_SCOPED_API_TOKEN_PROFILE,
            ),
            "Basic YWdlbnRAZXhhbXBsZS5jb206c2NvcGVkLXRva2Vu",
        ),
    ];
    for (credential, presented) in credentials {
        let gateway = MockServer::start().await;
        let media = MockServer::start().await;
        let content = |id: &str| on_site(CLOUD_ID, &format!("rest/api/3/attachment/content/{id}"));
        let elsewhere = |id: &str| {
            format!(
                "{}{}",
                gateway.uri(),
                on_site(
                    OTHER_CLOUD_ID,
                    &format!("rest/api/3/attachment/content/{id}")
                )
            )
        };
        redirect(&gateway, &content("1"), elsewhere("1")).await;
        redirect(&gateway, &content("2"), format!("{}/file/2", media.uri())).await;
        redirect(&media, "/file/2", elsewhere("2")).await;
        redirect(&gateway, &content("3"), format!("{}/file/3", media.uri())).await;
        serve(&media, "/file/3").await;
        let attachment = on_site(CLOUD_ID, "secure/attachment/4/evidence.txt");
        redirect(
            &gateway,
            &content("4"),
            format!("{}{attachment}", gateway.uri()),
        )
        .await;
        serve(&gateway, &attachment).await;
        let product = format!("/ex/confluence/{CLOUD_ID}/wiki/download/attachments/5/a.txt");
        redirect(
            &gateway,
            &content("5"),
            format!("{}{product}", gateway.uri()),
        )
        .await;
        // Anything another site serves would be found here.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("another site"))
            .with_priority(10)
            .mount(&gateway)
            .await;
        let clients = gateway_clients(&gateway, &media);

        for id in ["1", "2", "5"] {
            let error = download(&credential, &clients, &content(id))
                .await
                .unwrap_err();
            assert_eq!(
                error,
                AtlassianDownloadError::Upstream(UpstreamError::Redirect),
                "{id}"
            );
        }
        for id in ["3", "4"] {
            let response = download(&credential, &clients, &content(id)).await.unwrap();
            assert_eq!(response.text().await.unwrap(), "evidence", "{id}");
        }
        assert_eq!(
            hops(&gateway).await,
            [
                format!("{} {presented}", content("1")),
                format!("{} {presented}", content("2")),
                format!("{} {presented}", content("5")),
                format!("{} {presented}", content("3")),
                format!("{} {presented}", content("4")),
                format!("{attachment} {presented}"),
            ]
        );
        assert_eq!(hops(&media).await, ["/file/2 -", "/file/3 -"]);
    }
    assert!(lease.rejected().is_empty());
}

/// Answers with `response` after running `then`, such as a refresh or a
/// lost connection between two hops.
struct Then<F> {
    then: F,
    response: ResponseTemplate,
}

impl<F: Fn() + Send + Sync + 'static> Respond for Then<F> {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        (self.then)();
        self.response.clone()
    }
}

/// Every authorized hop presents delegated access revalidated immediately
/// before it: a refresh between hops is picked up, and a lease lost between
/// hops stops the download before the next one with the lease's own failure.
/// A 401 marks the version that hop presented rejected and starts over once;
/// a 401 from a media host, which got no credential, rejects nothing.
#[tokio::test]
async fn each_authorized_hop_presents_freshly_revalidated_access() {
    let gateway = MockServer::start().await;
    let media = MockServer::start().await;
    let clients = gateway_clients(&gateway, &media);
    let content = |id: &str| on_site(CLOUD_ID, &format!("rest/api/3/attachment/content/{id}"));
    let attachment = |id: &str| on_site(CLOUD_ID, &format!("secure/attachment/{id}/a.txt"));
    let found = |id: &str| {
        ResponseTemplate::new(302)
            .insert_header("Location", format!("{}{}", gateway.uri(), attachment(id)))
    };

    // Another operation refreshes the connection between the two hops.
    let lease = Lease::new(CLOUD_ID);
    let refreshed = lease.clone();
    Mock::given(path(content("1")))
        .respond_with(Then {
            then: move || {
                refreshed.current.fetch_add(1, Ordering::SeqCst);
            },
            response: found("1"),
        })
        .mount(&gateway)
        .await;
    serve(&gateway, &attachment("1")).await;
    let credential = delegated(&lease, Some(CLOUD_ID));
    let response = download(&credential, &clients, &content("1"))
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "evidence");
    assert_eq!(
        hops(&gateway).await,
        [
            format!("{} Bearer oauth-1", content("1")),
            format!("{} Bearer oauth-2", attachment("1")),
        ]
    );
    assert!(lease.rejected().is_empty());

    // The connection is lost between the two hops.
    let lost = [
        refresh_busy(),
        port_failure(
            HostPort::DelegatedLease,
            ProviderError::deny(ReasonCode::CredentialInvalid, "oauth_reconnect_required"),
        ),
    ];
    for (index, failure) in lost.into_iter().enumerate() {
        let id = format!("lost-{index}");
        let lease = Lease::new(CLOUD_ID);
        let failing = lease.clone();
        let lease_failure = failure.clone();
        Mock::given(path(content(&id)))
            .respond_with(Then {
                then: move || {
                    *failing.revalidation_failure.lock().unwrap() = Some(lease_failure.clone());
                },
                response: found(&id),
            })
            .mount(&gateway)
            .await;
        let before = hops(&gateway).await.len();
        let error = download(&delegated(&lease, Some(CLOUD_ID)), &clients, &content(&id))
            .await
            .unwrap_err();
        assert_eq!(
            error,
            AtlassianDownloadError::Access(AtlassianAccessError::Credential(failure))
        );
        // The second hop was never sent.
        assert_eq!(
            hops(&gateway).await[before..],
            [format!("{} Bearer oauth-1", content(&id))]
        );
        assert!(lease.rejected().is_empty());
    }

    // The site rejects the access the second hop presented: that version
    // is rejected, and the download starts over once with renewed access.
    redirect(
        &gateway,
        &content("2"),
        format!("{}{}", gateway.uri(), attachment("2")),
    )
    .await;
    Mock::given(path(attachment("2")))
        .and(header("authorization", "Bearer oauth-1"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&gateway)
        .await;
    serve(&gateway, &attachment("2")).await;
    let lease = Lease::new(CLOUD_ID);
    let before = hops(&gateway).await.len();
    let response = download(&delegated(&lease, Some(CLOUD_ID)), &clients, &content("2"))
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "evidence");
    assert_eq!(
        hops(&gateway).await[before..],
        [
            format!("{} Bearer oauth-1", content("2")),
            format!("{} Bearer oauth-1", attachment("2")),
            format!("{} Bearer oauth-2", content("2")),
            format!("{} Bearer oauth-2", attachment("2")),
        ]
    );
    assert_eq!(lease.rejected(), ["v1"]);

    // A media host's 401 answered no credential.
    redirect(&gateway, &content("3"), format!("{}/file/3", media.uri())).await;
    Mock::given(path("/file/3"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&media)
        .await;
    let lease = Lease::new(CLOUD_ID);
    let response = download(&delegated(&lease, Some(CLOUD_ID)), &clients, &content("3"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(lease.rejected().is_empty());
    assert_eq!(lease.recoveries.load(Ordering::SeqCst), 0);
}

/// A scoped API token is Basic on the gateway site and a classic one Basic
/// on the tenant: neither is presented across the tenant, media, product
/// or cloud boundary. Hops off the route's origin, to the tenant from the
/// gateway or to the gateway from the tenant, and to media hosts, carry no
/// credential; hops on the gateway outside the configured site fail before
/// they are sent.
#[tokio::test]
async fn basic_tokens_never_leave_their_route_site() {
    let gateway = MockServer::start().await;
    let tenant = MockServer::start().await;
    let media = MockServer::start().await;
    let hosts = [
        format!("{}/**", gateway.uri()),
        format!("{}/**", tenant.uri()),
        format!("{}/**", media.uri()),
    ];
    let site = AtlassianSite {
        tenant_host: "example.atlassian.net",
        cloud_id: Some(CLOUD_ID),
        egress_proxy: None,
        allowed_upstream_hosts: &hosts,
    };
    let clients = |origin: &MockServer, base: String| {
        AtlassianClients::new(
            JIRA,
            &site,
            Url::parse(&format!("{}{base}", origin.uri())).unwrap(),
            &TestHost::default(),
        )
        .unwrap()
    };
    let gateway_clients = clients(&gateway, format!("/ex/jira/{CLOUD_ID}/rest/api/3/"));
    let tenant_clients = clients(&tenant, "/rest/api/3/".to_string());
    let content = |id: &str| on_site(CLOUD_ID, &format!("rest/api/3/attachment/content/{id}"));
    let tenant_content = |id: &str| format!("/rest/api/3/attachment/content/{id}");
    let scoped = profiled(
        basic_credential("agent@example.com", "scoped-token"),
        ATLASSIAN_SCOPED_API_TOKEN_PROFILE,
    );
    let scoped_basic = "Basic YWdlbnRAZXhhbXBsZS5jb206c2NvcGVkLXRva2Vu";
    let classic = profiled(
        basic_credential("agent@example.com", "classic-token"),
        ATLASSIAN_API_TOKEN_PROFILE,
    );
    let classic_basic = "Basic YWdlbnRAZXhhbXBsZS5jb206Y2xhc3NpYy10b2tlbg==";

    // From the gateway site: to the tenant, to a media host, back to the
    // configured site, to another cloud ID and to another product.
    redirect(
        &gateway,
        &content("1"),
        format!("{}{}", tenant.uri(), tenant_content("1")),
    )
    .await;
    serve(&tenant, &tenant_content("1")).await;
    redirect(&gateway, &content("2"), format!("{}/file/2", media.uri())).await;
    redirect(
        &media,
        "/file/2",
        format!("{}{}", gateway.uri(), content("2b")),
    )
    .await;
    serve(&gateway, &content("2b")).await;
    redirect(
        &gateway,
        &content("3"),
        format!(
            "{}{}",
            gateway.uri(),
            on_site(OTHER_CLOUD_ID, "rest/api/3/attachment/content/3")
        ),
    )
    .await;
    redirect(
        &gateway,
        &content("4"),
        format!(
            "{}/ex/confluence/{CLOUD_ID}/wiki/download/attachments/4/a.txt",
            gateway.uri()
        ),
    )
    .await;
    redirect(&gateway, &content("5"), format!("{}/file/5", media.uri())).await;
    redirect(
        &media,
        "/file/5",
        format!(
            "{}{}",
            gateway.uri(),
            on_site(OTHER_CLOUD_ID, "secure/attachment/5/a.txt")
        ),
    )
    .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("another site"))
        .with_priority(10)
        .mount(&gateway)
        .await;

    let response = download(&scoped, &gateway_clients, &content("1"))
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "evidence");
    let response = download(&scoped, &gateway_clients, &content("2"))
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "evidence");
    for id in ["3", "4", "5"] {
        assert_eq!(
            download(&scoped, &gateway_clients, &content(id))
                .await
                .unwrap_err(),
            AtlassianDownloadError::Upstream(UpstreamError::Redirect),
            "{id}"
        );
    }
    assert_eq!(
        hops(&gateway).await,
        [
            format!("{} {scoped_basic}", content("1")),
            format!("{} {scoped_basic}", content("2")),
            format!("{} {scoped_basic}", content("2b")),
            format!("{} {scoped_basic}", content("3")),
            format!("{} {scoped_basic}", content("4")),
            format!("{} {scoped_basic}", content("5")),
        ]
    );
    assert_eq!(hops(&tenant).await, [format!("{} -", tenant_content("1"))]);
    assert_eq!(hops(&media).await, ["/file/2 -", "/file/5 -"]);

    // From the tenant: a classic token is presented on the tenant only,
    // never on the gateway or a media host.
    redirect(
        &tenant,
        &tenant_content("6"),
        format!("{}{}", gateway.uri(), content("6")),
    )
    .await;
    serve(&gateway, &content("6")).await;
    redirect(
        &tenant,
        &tenant_content("7"),
        format!("{}/file/7", media.uri()),
    )
    .await;
    serve(&media, "/file/7").await;
    redirect(
        &tenant,
        &tenant_content("8"),
        format!("{}/secure/attachment/8/a.txt", tenant.uri()),
    )
    .await;
    serve(&tenant, "/secure/attachment/8/a.txt").await;
    for id in ["6", "7", "8"] {
        let response = download(&classic, &tenant_clients, &tenant_content(id))
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "evidence", "{id}");
    }
    assert_eq!(
        hops(&tenant).await[1..],
        [
            format!("{} {classic_basic}", tenant_content("6")),
            format!("{} {classic_basic}", tenant_content("7")),
            format!("{} {classic_basic}", tenant_content("8")),
            format!("/secure/attachment/8/a.txt {classic_basic}"),
        ]
    );
    assert_eq!(hops(&gateway).await[6..], [format!("{} -", content("6"))]);
    assert_eq!(hops(&media).await[2..], ["/file/7 -"]);
}
