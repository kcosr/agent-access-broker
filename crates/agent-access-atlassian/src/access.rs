//! The credential each Jira or Confluence request presents: a static token,
//! or the operation's delegated (OAuth) credential pinned to the site's
//! gateway route.
//!
//! Delegated access is never held across requests. Immediately before each
//! request the lease is revalidated and its access pinned to the cloud ID of
//! the gateway route and the `api.atlassian.com` audience, so a refresh
//! between requests (by this operation or another) is picked up, and access
//! for another site or audience is refused before anything is sent.
//! Atlassian answering a request with 401 authenticated nothing, so applied
//! nothing: exactly the access version that request presented is marked
//! rejected, and its first attempt may ask the lease to recover and repeat
//! once. The lease holds the operation's one recovery budget, shared by its
//! lookups and its execution, and decides whether recovery is still
//! possible. A static token's 401 is reported as before and never repeated.
//!
//! An attachment download follows Atlassian's redirects, presenting the
//! credential only on hops within the route's site
//! ([`AtlassianClients::site_base`]): on the gateway, which serves every
//! site from one origin, a hop to another cloud ID is never sent. Each
//! authorized hop presents freshly revalidated access.
use crate::{ATLASSIAN_OAUTH_AUDIENCE, AtlassianClients};
use agent_access_provider::host::HostPort;
use agent_access_provider::{
    DelegatedAccessError, DelegatedCredential, ExecutionAccess, ExecutionCredential, LookupAccess,
    MutationReceipt, ProviderError, ReasonCode, RedirectAuthorizer, RedirectRules,
    StaticCredentialKind, UpstreamAuthorization, UpstreamError, complete_upstream_trace,
};
use async_trait::async_trait;
use reqwest::{Response, StatusCode};
use serde_json::Value;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use url::Url;

/// The credential one Jira or Confluence request presents. Clones share a
/// delegated credential's lease and its one recovery budget.
#[derive(Clone, Debug)]
pub struct AtlassianCredential(Material);

#[derive(Clone, Debug)]
enum Material {
    Static(ExecutionCredential),
    /// The operation's delegated credential and the cloud ID of the site's
    /// gateway route, or `None` when the site does not use the gateway.
    Delegated {
        credential: DelegatedCredential,
        cloud_id: Option<Arc<str>>,
    },
}

/// The authorization one attempt presents, and the delegated access version
/// it carries.
pub struct PresentedAccess {
    authorization: UpstreamAuthorization,
    version: Option<String>,
}

impl PresentedAccess {
    /// The authorization to send with this attempt.
    pub fn authorization(&self) -> &UpstreamAuthorization {
        &self.authorization
    }

    /// Whether the authorization carries delegated (OAuth) access.
    pub fn is_delegated(&self) -> bool {
        self.version.is_some()
    }
}

/// Why an attachment download ([`AtlassianCredential::download`]) returned
/// no response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtlassianDownloadError {
    /// The redirect chain failed, including a redirect to a URL outside the
    /// allowlist or, on the route's origin, outside its site.
    Upstream(UpstreamError),
    /// The credential could not be presented on the next authorized hop,
    /// which was not sent, or the upstream rejected delegated access again.
    Access(AtlassianAccessError),
}

/// Why a request's credential could not be presented. Nothing was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtlassianAccessError {
    /// A static credential kind Atlassian providers do not accept.
    UnsupportedKind,
    /// Delegated access that could not be presented: the lease's own
    /// failure (a refresh busy, throttled or uncertain, consent pending, a
    /// reconnect required, or an operation that already recovered), passed
    /// on unchanged; access for another site or audience; or access the
    /// upstream rejected again. Each is `credential_invalid` unless the
    /// lease reports otherwise.
    Credential(ProviderError),
}

impl AtlassianCredential {
    /// A static token: the service's shared credential or the caller's
    /// stored token. Basic API tokens reach the site; bearer tokens reach
    /// the gateway.
    pub fn from_static(credential: ExecutionCredential) -> Self {
        Self(Material::Static(credential))
    }

    /// The operation's delegated credential, pinned to `cloud_id`, the
    /// cloud ID of the site's gateway route ([`crate::AtlassianSite::gateway_cloud_id`]).
    pub fn delegated(credential: DelegatedCredential, cloud_id: Option<Arc<str>>) -> Self {
        Self(Material::Delegated {
            credential,
            cloud_id,
        })
    }

    /// The execution material the host selected. No material, or material
    /// Atlassian providers do not know, fails closed.
    pub fn from_execution(
        access: &ExecutionAccess,
        cloud_id: Option<&Arc<str>>,
    ) -> Result<Self, ProviderError> {
        match access {
            ExecutionAccess::Static(credential) => Ok(Self::from_static(credential.clone())),
            ExecutionAccess::Delegated(credential) => {
                Ok(Self::delegated(credential.clone(), cloud_id.cloned()))
            }
            _ => Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "selected credential material is unavailable",
            )),
        }
    }

    /// The lookup access the host selected, if any: a static token, or the
    /// operation's delegated credential, whose lease and recovery budget
    /// execution shares. Access of a kind Atlassian providers do not know
    /// fails closed.
    pub fn from_lookup(
        access: Option<&LookupAccess>,
        cloud_id: Option<&Arc<str>>,
    ) -> Result<Option<Self>, ProviderError> {
        match access {
            None => Ok(None),
            Some(LookupAccess::Static(credential)) => {
                Ok(Some(Self::from_static(credential.clone())))
            }
            Some(LookupAccess::Delegated(credential)) => {
                Ok(Some(Self::delegated(credential.clone(), cloud_id.cloned())))
            }
            Some(_) => Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "selected lookup credential is unavailable",
            )),
        }
    }

    /// The static token this credential presents, or `None` for delegated
    /// access. A backend reads its kind or, in tests, compares it; it never
    /// reads the material.
    pub fn static_credential(&self) -> Option<&ExecutionCredential> {
        match &self.0 {
            Material::Static(credential) => Some(credential),
            Material::Delegated { .. } => None,
        }
    }

    /// Whether this is delegated (OAuth) access.
    pub fn is_delegated(&self) -> bool {
        matches!(self.0, Material::Delegated { .. })
    }

    /// Whether requests go through the Atlassian gateway: delegated access
    /// always does, as does a bearer token; a Basic API token reaches the
    /// site.
    pub fn routes_through_gateway(&self) -> bool {
        match &self.0 {
            Material::Static(credential) => credential.kind() == StaticCredentialKind::BearerToken,
            Material::Delegated { .. } => true,
        }
    }

    /// The authorization for the next request. Delegated access is
    /// revalidated and pinned to the gateway route's cloud ID and the
    /// `api.atlassian.com` audience now; a lease failure passes through
    /// unchanged, and access for another site or audience fails before
    /// anything is sent.
    pub async fn present(&self) -> Result<PresentedAccess, AtlassianAccessError> {
        match &self.0 {
            Material::Static(credential) => {
                if !presentable_kind(credential.kind()) {
                    return Err(AtlassianAccessError::UnsupportedKind);
                }
                Ok(PresentedAccess {
                    authorization: credential.authorization(),
                    version: None,
                })
            }
            Material::Delegated {
                credential,
                cloud_id,
            } => {
                let cloud_id = cloud_id.as_deref().ok_or_else(site_mismatch)?;
                let access = credential
                    .revalidated_access_for(cloud_id, ATLASSIAN_OAUTH_AUDIENCE)
                    .await
                    .map_err(|error| match error {
                        DelegatedAccessError::Revalidation(failure) => {
                            AtlassianAccessError::Credential(failure)
                        }
                        _ => site_mismatch(),
                    })?;
                Ok(PresentedAccess {
                    authorization: access.authorization(),
                    version: Some(access.version().to_owned()),
                })
            }
        }
    }

    /// Handles a 401 answer to delegated `presented` access: marks exactly
    /// the presented version rejected, so no later request presents it.
    /// With a `replay` of the request (its first attempt, which can be sent
    /// again) it asks the lease to recover and returns the replay to send
    /// once with renewed access. The lease's own failure, including an
    /// operation that already recovered, passes through unchanged. A 401
    /// that cannot be repeated requires reconnecting if it recurs. `product`
    /// names the product in that failure.
    pub async fn rejected<T>(
        &self,
        presented: &PresentedAccess,
        replay: Option<T>,
        product: &str,
    ) -> Result<T, AtlassianAccessError> {
        let (Material::Delegated { credential, .. }, Some(version)) =
            (&self.0, presented.version.as_deref())
        else {
            return Err(AtlassianAccessError::Credential(ProviderError::error(
                ReasonCode::UpstreamUnauthorized,
                format!("{product} rejected the selected credential"),
            )));
        };
        credential
            .mark_rejected(version)
            .map_err(AtlassianAccessError::Credential)?;
        let Some(replay) = replay else {
            return Err(AtlassianAccessError::Credential(ProviderError::deny(
                ReasonCode::CredentialInvalid,
                format!(
                    "{product} rejected the connected Atlassian account's access again; reconnect Atlassian in the Broker portal if this repeats"
                ),
            )));
        };
        credential
            .recover_after_unauthorized()
            .await
            .map_err(AtlassianAccessError::Credential)?;
        Ok(replay)
    }

    /// GETs `url` through `clients`' stream client, following at most
    /// `max_redirects` redirects, such as Atlassian's media redirects, and
    /// waiting at most `deadline` for each hop's response headers.
    ///
    /// Only hops within the route's site ([`AtlassianClients::site_base`])
    /// present the credential, each with delegated access revalidated and
    /// pinned immediately before it is sent ([`Self::present`]); a lease
    /// failure stops the download before that hop. A hop on the route's
    /// origin outside its site, such as another cloud ID on the gateway,
    /// fails the download before it is sent. Hops to other allowlisted
    /// origins, such as Atlassian's media hosts, carry the correlation
    /// headers but no credential.
    ///
    /// A 401 answering delegated access marks the version that hop
    /// presented rejected, recovers once and starts the download over
    /// ([`Self::rejected`]); a 401 from a hop that presented nothing is
    /// returned like any other status.
    pub async fn download(
        &self,
        clients: &AtlassianClients,
        url: Url,
        max_redirects: u32,
        deadline: Duration,
        operation: &str,
        product: &str,
    ) -> Result<Response, AtlassianDownloadError> {
        if let Material::Static(credential) = &self.0
            && !presentable_kind(credential.kind())
        {
            return Err(AtlassianDownloadError::Access(
                AtlassianAccessError::UnsupportedKind,
            ));
        }
        let mut attempt = 1;
        loop {
            let hops = HopPresenter {
                credential: self,
                last: Mutex::default(),
            };
            let rules = RedirectRules::new(max_redirects, deadline)
                .with_authorizer(&hops)
                .with_authorized_prefix(&clients.site_base)
                // Atlassian media hosts join broker logs by these headers.
                .correlating_other_origins();
            let mut response = clients
                .stream_client
                .get_following_redirects(url.clone(), rules, operation)
                .await
                .map_err(|error| match error {
                    UpstreamError::Authorization(failure) => {
                        AtlassianDownloadError::Access(AtlassianAccessError::Credential(*failure))
                    }
                    other => AtlassianDownloadError::Upstream(other),
                })?;
            if response.status() == StatusCode::UNAUTHORIZED
                && let Some(presented) = hops
                    .presented_for(&response)
                    .filter(PresentedAccess::is_delegated)
            {
                complete_upstream_trace(&mut response, Some(ReasonCode::CredentialInvalid.into()));
                self.rejected(&presented, (attempt == 1).then_some(()), product)
                    .await
                    .map_err(AtlassianDownloadError::Access)?;
                attempt += 1;
                continue;
            }
            return Ok(response);
        }
    }
}

/// The static credential kinds Atlassian providers present.
fn presentable_kind(kind: StaticCredentialKind) -> bool {
    matches!(
        kind,
        StaticCredentialKind::BasicApiToken | StaticCredentialKind::BearerToken
    )
}

/// Presents a download's credential on each authorized hop, revalidating
/// delegated access immediately before each one, and remembers what the last
/// one presented.
struct HopPresenter<'a> {
    credential: &'a AtlassianCredential,
    last: Mutex<Option<(Url, PresentedAccess)>>,
}

impl HopPresenter<'_> {
    /// What the hop that answered `response` presented, if that hop was
    /// authorized: the last authorized hop, when it was also the last hop.
    fn presented_for(&self, response: &Response) -> Option<PresentedAccess> {
        let last = self
            .last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        last.filter(|(url, _)| url == response.url())
            .map(|(_, presented)| presented)
    }
}

#[async_trait]
impl RedirectAuthorizer for HopPresenter<'_> {
    async fn authorize(&self, url: &Url) -> Result<UpstreamAuthorization, ProviderError> {
        let presented = self
            .credential
            .present()
            .await
            .map_err(|error| match error {
                AtlassianAccessError::Credential(failure) => failure,
                // `download` refuses an unsupported static kind before the chain.
                _ => ProviderError::deny(
                    ReasonCode::CredentialNotProvisioned,
                    "selected credential material is unavailable",
                ),
            })?;
        let authorization = presented.authorization().clone();
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some((url.clone(), presented));
        Ok(authorization)
    }
}

/// The lease's access is not for the site this provider acts on, or the
/// site has no gateway route.
fn site_mismatch() -> AtlassianAccessError {
    AtlassianAccessError::Credential(ProviderError::deny(
        ReasonCode::CredentialInvalid,
        "the Atlassian OAuth connection does not grant access to this site through the Atlassian gateway",
    ))
}

/// Whether `error` is delegated access failing: the lease's own failure, or
/// the `credential_invalid` an [`AtlassianCredential`] reports for access
/// for another site or access the upstream rejected again. Atlassian
/// providers report `credential_invalid` for nothing else.
pub fn is_delegated_access_failure(error: &ProviderError) -> bool {
    error.reason_code().host_port() == Some(HostPort::DelegatedLease)
        || error.reason_code() == ReasonCode::CredentialInvalid
}

/// Reports the failure of what follows a write the upstream accepted.
pub trait AtlassianWriteVerification {
    /// For an error that stopped a read-back or verification after a write
    /// was applied. Delegated access that could not be presented, or that
    /// the upstream rejected, stopped the verification, not the write: like
    /// throttling, it becomes `mutation_verification_failed`, so a caller
    /// waiting for the connection is never invited to repeat the write. Any
    /// other failure keeps its reason, throttling as
    /// [`ProviderError::unverified_after_mutation`] reports it. Both report
    /// [`MutationReceipt::applied_unverified`] at `verification_stage` with
    /// `safe_locators` unless the error already reports a receipt; audit,
    /// upstream facts and object IDs are kept.
    fn unverified_after_atlassian_write(
        self,
        verification_stage: &str,
        safe_locators: Value,
    ) -> Self;
}

impl AtlassianWriteVerification for ProviderError {
    fn unverified_after_atlassian_write(
        self,
        verification_stage: &str,
        safe_locators: Value,
    ) -> Self {
        let receipted = self
            .result
            .as_deref()
            .is_some_and(|result| result.get("mutationStatus").is_some());
        if receipted || !is_delegated_access_failure(&self) {
            return self.unverified_after_mutation(verification_stage, safe_locators);
        }
        let mut unverified = ProviderError::error(
            ReasonCode::MutationVerificationFailed,
            "the write was applied, but the connected Atlassian account's access failed before the Broker could verify it",
        );
        unverified.audit = self.audit;
        unverified.upstream_status = self.upstream_status;
        unverified.upstream_duration_ms = self.upstream_duration_ms;
        unverified.object_ids = self.object_ids;
        unverified.with_mutation_receipt(MutationReceipt::applied_unverified(
            verification_stage,
            safe_locators,
        ))
    }
}

#[cfg(test)]
mod tests;
