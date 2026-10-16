//! The credential an Atlassian request presents: static tokens as before,
//! delegated access pinned to the gateway route's cloud ID and the gateway
//! audience before every request, one recovery per operation, and the
//! receipts of writes whose verification the connection stopped.
use super::*;
use crate::{AtlassianProduct, AtlassianRoutes, AtlassianSite};
use agent_access_provider::deps::async_trait;
use agent_access_provider::host::{delegated_credential, port_failure};
use agent_access_provider::test_support::{
    TestHost, basic_credential, bearer_credential, delegated_binding_id,
};
use agent_access_provider::{DelegatedAccess, DelegatedBindingId, DelegatedLease};
use serde_json::json;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

#[tokio::test]
async fn static_tokens_present_their_own_authorization_without_revealing_it() {
    for credential in [
        basic_credential("agent@example.com", "api-token"),
        bearer_credential("gateway-token"),
    ] {
        let credential = AtlassianCredential::from_static(credential);
        assert!(!credential.is_delegated());
        let presented = credential.present().await.unwrap();
        assert!(!presented.is_delegated());
        let rendered = format!("{:?} {credential:?}", presented.authorization());
        assert!(
            !rendered.contains("api-token")
                && !rendered.contains("gateway-token")
                && !rendered.contains("agent@"),
            "{rendered}"
        );
    }
}

/// Delegated access is revalidated and pinned to the gateway route's cloud
/// ID and the gateway audience before every request; access for another
/// site, or a site without a gateway route, fails before anything is sent,
/// and the lease's own failure passes through unchanged.
#[tokio::test]
async fn delegated_access_is_pinned_to_the_gateway_site_and_audience() {
    let lease = Lease::new(CLOUD_ID);
    let credential = delegated(&lease, Some(CLOUD_ID));
    assert!(credential.is_delegated() && credential.routes_through_gateway());
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
        assert!(credential.routes_through_gateway());
    }
}

/// Delegated access routes through the gateway whatever else the site
/// allows, as bearer tokens do, and is pinned to the cloud ID the gateway
/// route names.
#[test]
fn delegated_access_routes_through_the_gateway_on_its_cloud_id() {
    const PRODUCT: AtlassianProduct = AtlassianProduct {
        provider: "jira",
        name: "Jira",
        api_path: "rest/api/3/",
        status_reasons: &[],
    };
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
    // Without the gateway, delegated access has no route and no pin.
    let site_only = &hosts[..1];
    let site = AtlassianSite {
        allowed_upstream_hosts: site_only,
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
        "Jira bearer tokens and OAuth connections require providers.jira.cloud_id and api.atlassian.com in allowed_upstream_hosts"
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
