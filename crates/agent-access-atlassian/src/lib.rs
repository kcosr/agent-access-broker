//! The `atlassian` OAuth dialect ([`ATLASSIAN_OAUTH_DIALECT`]) and the
//! helpers the Jira and Confluence backends share: configuration
//! validation, the credential each request presents ([`AtlassianCredential`],
//! with delegated access pinned per request and one 401 recovery, and
//! attachment downloads whose redirects keep it on the route's site), the
//! tenant/gateway client routes, the credential binding of their
//! continuations and the receipts of writes whose verification failed.
mod access;
mod oauth;

pub use access::{
    AtlassianAccessError, AtlassianCredential, AtlassianDownloadError, AtlassianWriteVerification,
    PresentedAccess, is_delegated_access_failure,
};
pub use oauth::{ATLASSIAN_OAUTH_AUDIENCE, ATLASSIAN_OAUTH_DIALECT};

use agent_access_provider::host::UpstreamClientFactory;
use agent_access_provider::{
    ClientProfile, ContinuationBinding, ContinuationStage, CredentialDescriptor, EgressDeclaration,
    EgressProxyConfig, ExecutionAccess, ProviderBuildError, ProviderError, ReasonCode,
    ServiceCredentialKinds, StaticCredentialKind, UpstreamAuthority, UpstreamClient,
    UpstreamClientSpec,
};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;
use url::Url;

/// Checks an Atlassian provider's execution credentials against its route.
///
/// The site route takes Basic API tokens; the Atlassian gateway, enabled by
/// `api.atlassian.com` in the allowlist, takes bearer tokens and delegated
/// (OAuth) access, and then every credential must use it:
///
/// | Per-user connection | Gateway | Result |
/// | --- | --- | --- |
/// | `basic_api_token` profile only | off | valid: site route |
/// | `bearer_token` profile only | on | valid: gateway |
/// | OAuth only | on (required) | valid: gateway |
/// | `bearer_token` profile and OAuth | on | valid: OAuth for people, bearer tokens for service accounts, both through the gateway |
/// | `basic_api_token` profile and OAuth | either | rejected: site tokens would mix with gateway OAuth |
///
/// A `credentials.service` credential must be a bearer token when the
/// gateway is on, and a bearer credential requires the gateway.
pub fn validate_atlassian_gateway_credential(
    service: &str,
    patterns: &[String],
    cloud_id: Option<&str>,
    credentials: ServiceCredentialKinds<'_>,
    errors: &mut Vec<String>,
) {
    let uses_gateway = uses_atlassian_gateway_host(patterns);
    let delegated = credentials.per_user_delegated;
    if delegated {
        if credentials.per_user == Some("basic_api_token") {
            errors.push(format!(
                "credentials.per_user.{service} combines OAuth with a basic_api_token profile; OAuth acts through the Atlassian gateway, so the connection's token_profile must be atlassian-bearer-token or absent"
            ));
        }
        if !uses_gateway {
            errors.push(format!(
                "credentials.per_user.{service} offers delegated (OAuth) access, which requires providers.{service}.allowed_upstream_hosts to include api.atlassian.com"
            ));
        }
    }
    // Beside OAuth, the per-user kind is `oauth` for a connection without a
    // token profile, whose access is the delegated credential checked above,
    // or a basic profile, already rejected above.
    let per_user_static = credentials
        .per_user
        .filter(|kind| !(delegated && matches!(*kind, "oauth" | "basic_api_token")));
    let execution_credentials = [
        ("credentials.service", credentials.service),
        ("credentials.per_user", per_user_static),
    ];
    let mut has_gateway_execution_credential = delegated;
    let mut bearer_mode = None;

    for (mode, credential) in execution_credentials {
        if let Some(kind) = credential {
            if kind == "bearer_token" {
                has_gateway_execution_credential = true;
                bearer_mode.get_or_insert(mode);
            } else if uses_gateway {
                errors.push(format!(
                    "providers.{service}.allowed_upstream_hosts includes api.atlassian.com but {mode}.{service} does not resolve to a bearer_token credential"
                ));
            }
        }
    }

    if let Some(mode) = bearer_mode.filter(|_| !uses_gateway) {
        errors.push(format!(
            "{mode}.{service}.type bearer_token requires providers.{service}.allowed_upstream_hosts to include api.atlassian.com"
        ));
    }

    if !uses_gateway {
        return;
    }

    match cloud_id {
        Some(value) if uuid::Uuid::parse_str(value).is_ok() => {}
        Some(_) => errors.push(format!(
            "providers.{service}.cloud_id must be a valid Atlassian cloud UUID when api.atlassian.com is allowed"
        )),
        None => errors.push(format!(
            "providers.{service}.cloud_id is required when api.atlassian.com is allowed"
        )),
    }

    if !has_gateway_execution_credential {
        errors.push(format!(
            "providers.{service}.allowed_upstream_hosts includes api.atlassian.com but no bearer_token or OAuth execution credential is configured"
        ));
    }
}

/// The Atlassian API gateway's origin.
pub const ATLASSIAN_GATEWAY_ORIGIN: &str = "https://api.atlassian.com";

/// A configured cloud ID in the one form the site declares, routes and
/// binds: Atlassian's own, a lowercase hyphenated UUID. Configuration
/// accepts a UUID in any form [`uuid::Uuid::parse_str`] does, such as
/// uppercase or braced, so an OAuth registration's `target` matches it
/// however it is written. A value that is not a UUID, which validation
/// rejects whenever the gateway is on, is kept as written.
fn canonical_cloud_id(cloud_id: &str) -> Cow<'_, str> {
    match uuid::Uuid::parse_str(cloud_id) {
        Ok(id) => Cow::Owned(id.hyphenated().to_string()),
        Err(_) => Cow::Borrowed(cloud_id),
    }
}

/// The stored token profile for an Atlassian account's email address and
/// classic API token, presented as HTTP Basic on the site route. Classic
/// tokens are account-wide, so one credential connection with this profile
/// can serve Jira and Confluence on one site.
pub const ATLASSIAN_API_TOKEN_PROFILE: &str = "atlassian-api-token";

/// The stored token profile for an Atlassian service account's scoped API
/// token, presented as a bearer token through the Atlassian gateway.
pub const ATLASSIAN_BEARER_TOKEN_PROFILE: &str = "atlassian-bearer-token";

/// Whether an Atlassian provider allowlist routes through the Atlassian API
/// gateway. Only an exact `api.atlassian.com` host counts.
pub fn uses_atlassian_gateway_host(allowed_upstream_hosts: &[String]) -> bool {
    allowed_upstream_hosts.iter().any(|pattern| {
        Url::parse(pattern)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .is_some_and(|host| host == "api.atlassian.com")
    })
}

/// Binds a continuation or handle to the execution material that reaches an
/// Atlassian site, after the configuration and resource fields the provider
/// binds:
///
/// - the credential method: a static credential (a stored or service token)
///   or delegated (OAuth) access;
/// - for a static credential, its kind, which selects the route: a Basic API
///   token reaches the tenant host and a bearer token the gateway;
/// - for delegated access, the lease's delegated binding (the OAuth
///   connection and its generation, never the access version), target and
///   audience. Routine refresh keeps them; reconnecting, replacing the
///   account or new consent changes the binding;
/// - for a route through the Atlassian gateway (a bearer token or delegated
///   access), the configured `cloud_id`, the site the gateway reaches, in its
///   lowercase hyphenated form, however the configuration writes it.
///
/// A token sealed under one method, account, connection generation or
/// gateway site therefore never opens under another. Every input is fixed by
/// configuration or the host's selection, so a token survives a restart
/// whenever its family's key does. Execution material Atlassian providers do
/// not accept, including none, fails closed.
pub fn bind_atlassian_access<Stage: ContinuationStage>(
    binding: ContinuationBinding<Stage>,
    access: &ExecutionAccess,
    cloud_id: Option<&str>,
) -> Result<ContinuationBinding<Stage>, ProviderError> {
    let (binding, through_gateway) = match access {
        ExecutionAccess::Static(credential) => {
            let through_gateway = match credential.kind() {
                StaticCredentialKind::BasicApiToken => false,
                StaticCredentialKind::BearerToken => true,
                _ => return Err(atlassian_access_unavailable()),
            };
            (
                binding
                    .text("credentialMethod", "static")
                    .text("credentialKind", credential.kind().as_str()),
                through_gateway,
            )
        }
        ExecutionAccess::Delegated(credential) => (
            binding
                .text("credentialMethod", "delegated")
                .delegated(credential),
            true,
        ),
        _ => return Err(atlassian_access_unavailable()),
    };
    let gateway_cloud_id = cloud_id.filter(|_| through_gateway).map(canonical_cloud_id);
    Ok(binding.optional_text("gatewayCloudId", gateway_cloud_id.as_deref()))
}

fn atlassian_access_unavailable() -> ProviderError {
    ProviderError::deny(
        ReasonCode::CredentialNotProvisioned,
        "selected credential material is unavailable",
    )
}

/// Deterministic wire fixtures. No production configuration can move the
/// dialect's endpoints.
#[cfg(feature = "test-support")]
pub mod test_support {
    use agent_access_provider::OAuthDialectRegistration;

    /// The `atlassian` dialect with its authorization, token, identity and
    /// site endpoints below `base`, as a development fixture.
    pub fn dialect(base: &str) -> &'static OAuthDialectRegistration {
        crate::oauth::test_dialect(base)
    }
}

/// One Atlassian product's REST API: its provider name, which also names its
/// configuration section and gateway product, its display name, the API path
/// below the tenant host and the gateway site, and statuses with
/// product-specific reasons.
#[derive(Debug, Clone, Copy)]
pub struct AtlassianProduct {
    pub provider: &'static str,
    pub name: &'static str,
    pub api_path: &'static str,
    pub status_reasons: &'static [(u16, ReasonCode)],
}

/// The site configuration an Atlassian provider routes by.
#[derive(Debug, Clone, Copy)]
pub struct AtlassianSite<'a> {
    pub tenant_host: &'a str,
    /// The cloud ID as configured. The site declares, routes, fingerprints
    /// and binds its lowercase hyphenated form.
    pub cloud_id: Option<&'a str>,
    pub egress_proxy: Option<&'a EgressProxyConfig>,
    pub allowed_upstream_hosts: &'a [String],
}

impl AtlassianSite<'_> {
    /// Whether bearer credentials and delegated access route through the
    /// Atlassian gateway: a cloud ID is configured and `api.atlassian.com`
    /// is allowed.
    pub fn uses_gateway(&self) -> bool {
        self.cloud_id.is_some() && uses_atlassian_gateway_host(self.allowed_upstream_hosts)
    }

    /// The cloud ID of the site's gateway route as the route names it, a
    /// lowercase hyphenated UUID: what delegated access is pinned to before
    /// each request. `None` when the site does not use the gateway or its
    /// cloud ID is not a UUID, which validation rejects.
    pub fn gateway_cloud_id(&self) -> Option<Arc<str>> {
        self.cloud_id
            .filter(|_| self.uses_gateway())
            .and_then(|cloud_id| uuid::Uuid::parse_str(cloud_id).ok())
            .map(|cloud_id| Arc::from(cloud_id.hyphenated().to_string()))
    }

    /// The credentials Jira and Confluence declare for this site: the
    /// vendor-level [`ATLASSIAN_API_TOKEN_PROFILE`] (`basic_api_token`,
    /// site route) and, when the site uses the gateway,
    /// [`ATLASSIAN_BEARER_TOKEN_PROFILE`] (`bearer_token`, gateway route).
    /// Both products declare the same profiles, so one credential connection
    /// can serve both.
    pub fn credential_descriptor(&self) -> CredentialDescriptor {
        let credentials =
            CredentialDescriptor::default().profile(ATLASSIAN_API_TOKEN_PROFILE, "basic_api_token");
        if self.uses_gateway() {
            credentials.profile(ATLASSIAN_BEARER_TOKEN_PROFILE, "bearer_token")
        } else {
            credentials
        }
    }

    /// The site's upstream authority: the tenant host's origin, the cloud
    /// ID when configured, in its lowercase hyphenated form, and the
    /// Atlassian gateway when it routes through it. Jira and Confluence on
    /// one site therefore act on the same instance. `None` for a tenant host
    /// that is not a valid host.
    pub fn upstream_authority(&self) -> Option<UpstreamAuthority> {
        let mut authority =
            UpstreamAuthority::from_base_url(&format!("https://{}", self.tenant_host)).ok()?;
        if let Some(cloud_id) = self.cloud_id {
            authority = authority.with_tenant(canonical_cloud_id(cloud_id));
        }
        if self.uses_gateway() {
            authority = authority
                .with_tenant_gateway(ATLASSIAN_GATEWAY_ORIGIN)
                .ok()?;
        }
        Some(authority)
    }

    /// A digest of the configuration an upstream cursor's route depends on:
    /// the tenant host, the cloud ID in its lowercase hyphenated form and
    /// whether `api.atlassian.com` is allowed. Continuations relaying a
    /// cursor bind it, beside the execution material [`bind_atlassian_access`]
    /// binds, whose method and kind select the route.
    pub fn route_fingerprint(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"agent-access/atlassian-route/v1\0");
        let cloud_id = self.cloud_id.map(canonical_cloud_id);
        for field in [Some(self.tenant_host), cloud_id.as_deref()] {
            match field {
                Some(value) => {
                    digest.update([1]);
                    digest.update((value.len() as u64).to_be_bytes());
                    digest.update(value.as_bytes());
                }
                None => digest.update([0]),
            }
        }
        digest.update([u8::from(uses_atlassian_gateway_host(
            self.allowed_upstream_hosts,
        ))]);
        digest.finalize().into()
    }
}

/// The request and stream clients for one API base.
#[derive(Clone)]
pub struct AtlassianClients {
    pub api_base: Url,
    /// The root of the route's site, which `api_base` extends with the
    /// product's API path: `https://<tenant_host>/` on the tenant route, or
    /// `https://api.atlassian.com/ex/<provider>/<cloud_id>/` on the gateway,
    /// whose one origin serves every site. Attachment download redirects
    /// present the credential only within it.
    pub site_base: Url,
    pub client: UpstreamClient,
    pub stream_client: UpstreamClient,
}

impl AtlassianClients {
    /// Clients for `api_base`, which must end with the product's API path,
    /// with the site's egress declaration and allowlist, labelled
    /// `providers.<provider>.egress_proxy`.
    pub fn new(
        product: AtlassianProduct,
        site: &AtlassianSite<'_>,
        api_base: Url,
        factory: &dyn UpstreamClientFactory,
    ) -> Result<Self, ProviderBuildError> {
        let site_root = api_base
            .path()
            .strip_suffix(product.api_path)
            .filter(|root| root.ends_with('/'))
            .ok_or_else(|| {
                ProviderBuildError::invalid(format!(
                    "providers.{}: the API base {api_base} does not end with {}",
                    product.provider, product.api_path
                ))
            })?
            .to_owned();
        let mut site_base = api_base.clone();
        site_base.set_path(&site_root);
        site_base.set_query(None);
        site_base.set_fragment(None);
        let label = format!("providers.{}.egress_proxy", product.provider);
        let client = |profile| {
            UpstreamClient::build(
                UpstreamClientSpec::new(
                    &label,
                    product.provider,
                    &api_base,
                    EgressDeclaration::Ordinary(site.egress_proxy),
                    site.allowed_upstream_hosts,
                    profile,
                )
                .with_status_reasons(product.status_reasons),
                factory,
            )
        };
        Ok(Self {
            client: client(ClientProfile::Request)?,
            stream_client: client(ClientProfile::Stream)?,
            api_base,
            site_base,
        })
    }
}

/// An Atlassian provider's routes: Basic API-token credentials use the
/// tenant host; bearer credentials and delegated (OAuth) access use the
/// Atlassian gateway when the site enables it.
#[derive(Clone)]
pub struct AtlassianRoutes {
    product: AtlassianProduct,
    tenant: AtlassianClients,
    gateway: Option<AtlassianClients>,
}

impl AtlassianRoutes {
    /// The tenant route `https://<tenant_host>/<api_path>` and, when the
    /// site uses the gateway, `https://api.atlassian.com/ex/<provider>/<cloud_id>/<api_path>`.
    pub fn new(
        product: AtlassianProduct,
        site: &AtlassianSite<'_>,
        factory: &dyn UpstreamClientFactory,
    ) -> Result<Self, ProviderBuildError> {
        let provider = product.provider;
        let tenant_base = Url::parse(&format!(
            "https://{}/{}",
            site.tenant_host, product.api_path
        ))
        .map_err(|error| {
            ProviderBuildError::invalid(format!(
                "providers.{provider}.tenant_host is invalid: {error}"
            ))
        })?;
        let tenant = AtlassianClients::new(product, site, tenant_base, factory)?;
        let gateway = match site.cloud_id.filter(|_| site.uses_gateway()) {
            Some(cloud_id) => {
                let cloud_id = uuid::Uuid::parse_str(cloud_id).map_err(|error| {
                    ProviderBuildError::invalid(format!(
                        "providers.{provider}.cloud_id is invalid: {error}"
                    ))
                })?;
                let gateway_base = Url::parse(&format!(
                    "https://api.atlassian.com/ex/{provider}/{}/{}",
                    cloud_id.hyphenated(),
                    product.api_path
                ))
                .map_err(|error| ProviderBuildError::invalid(error.to_string()))?;
                Some(AtlassianClients::new(product, site, gateway_base, factory)?)
            }
            None => None,
        };
        Ok(Self {
            product,
            tenant,
            gateway,
        })
    }

    /// Routes over already built clients, such as one test server serving
    /// both routes.
    pub fn from_clients(
        product: AtlassianProduct,
        tenant: AtlassianClients,
        gateway: Option<AtlassianClients>,
    ) -> Self {
        Self {
            product,
            tenant,
            gateway,
        }
    }

    /// The clients for `credential`'s route: the gateway for delegated
    /// access and bearer tokens, whatever else the site allows, and the
    /// tenant host otherwise.
    pub fn for_credential(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<&AtlassianClients, AtlassianRouteUnavailable> {
        if credential.routes_through_gateway() {
            self.gateway.as_ref().ok_or(AtlassianRouteUnavailable {
                product: self.product,
            })
        } else {
            Ok(&self.tenant)
        }
    }

    /// The gateway clients, for tests that redirect the gateway route.
    pub fn gateway_mut(&mut self) -> Option<&mut AtlassianClients> {
        self.gateway.as_mut()
    }
}

/// A bearer credential or delegated access with no gateway route
/// configured.
#[derive(Debug, Clone, Copy)]
pub struct AtlassianRouteUnavailable {
    product: AtlassianProduct,
}

impl fmt::Display for AtlassianRouteUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let AtlassianProduct { provider, name, .. } = self.product;
        write!(
            formatter,
            "{name} bearer tokens and OAuth connections require providers.{provider}.cloud_id and api.atlassian.com in allowed_upstream_hosts"
        )
    }
}

impl std::error::Error for AtlassianRouteUnavailable {}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::test_support::{TestHost, basic_credential, bearer_credential};

    const PRODUCT: AtlassianProduct = AtlassianProduct {
        provider: "confluence",
        name: "Confluence",
        api_path: "wiki/rest/api/",
        status_reasons: &[(409, ReasonCode::VersionConflict)],
    };
    const CLOUD_ID: &str = "00000000-0000-0000-0000-000000000001";

    fn hosts(gateway: bool) -> Vec<String> {
        let mut hosts = vec!["https://example.atlassian.net/wiki/**".to_string()];
        if gateway {
            hosts.push("https://api.atlassian.com/ex/confluence/**".to_string());
        }
        hosts
    }

    fn site<'a>(cloud_id: Option<&'a str>, hosts: &'a [String]) -> AtlassianSite<'a> {
        AtlassianSite {
            tenant_host: "example.atlassian.net",
            cloud_id,
            egress_proxy: None,
            allowed_upstream_hosts: hosts,
        }
    }

    #[test]
    fn a_site_declares_its_host_cloud_id_and_gateway_route() {
        let site_only = hosts(false);
        let authority = site(None, &site_only).upstream_authority().unwrap();
        assert_eq!(authority.origin(), "https://example.atlassian.net");
        assert_eq!(
            (authority.tenant(), authority.tenant_gateway()),
            (None, None)
        );
        let routed_hosts = hosts(true);
        let routed = site(Some(CLOUD_ID), &routed_hosts)
            .upstream_authority()
            .unwrap();
        assert_eq!(routed.tenant(), Some(CLOUD_ID));
        assert_eq!(routed.tenant_gateway(), Some(ATLASSIAN_GATEWAY_ORIGIN));
        // Jira and Confluence on one site act on the same instance.
        assert!(authority.same_instance(&routed));
        assert!(site(None, &site_only).upstream_authority().is_some());
        let invalid = AtlassianSite {
            tenant_host: "not a host",
            ..site(None, &site_only)
        };
        assert!(invalid.upstream_authority().is_none());
    }

    /// Configuration may write a cloud ID in any UUID form; the site
    /// declares, routes and fingerprints its lowercase hyphenated form, so an
    /// OAuth registration's target matches it however it is written.
    #[test]
    fn cloud_ids_in_any_uuid_form_are_declared_and_routed_canonically() {
        const CANONICAL: &str = "abcdef01-2345-4678-9abc-def012345678";
        let gateway = hosts(true);
        let canonical = site(Some(CANONICAL), &gateway);
        for written in [
            "ABCDEF01-2345-4678-9ABC-DEF012345678",
            "{abcdef01-2345-4678-9abc-def012345678}",
            "urn:uuid:ABCDEF01-2345-4678-9ABC-DEF012345678",
            "ABCDEF01234546789ABCDEF012345678",
        ] {
            let written_site = site(Some(written), &gateway);
            let authority = written_site.upstream_authority().unwrap();
            assert_eq!(authority.tenant(), Some(CANONICAL), "{written}");
            assert_eq!(authority, canonical.upstream_authority().unwrap());
            assert_eq!(
                written_site.gateway_cloud_id().as_deref(),
                Some(CANONICAL),
                "{written}"
            );
            assert_eq!(
                written_site.route_fingerprint(),
                canonical.route_fingerprint(),
                "{written}"
            );
            let routes =
                AtlassianRoutes::new(PRODUCT, &written_site, &TestHost::default()).unwrap();
            assert_eq!(
                routes
                    .for_credential(&AtlassianCredential::from_static(bearer_credential(
                        "token"
                    )))
                    .unwrap()
                    .api_base
                    .as_str(),
                format!("https://api.atlassian.com/ex/confluence/{CANONICAL}/wiki/rest/api/")
            );
        }
        // A value that is not a UUID is invalid with the gateway; without it,
        // it is kept as written.
        let tenant_only = hosts(false);
        let unvalidated = site(Some("not-a-uuid"), &tenant_only);
        assert_eq!(
            unvalidated.upstream_authority().unwrap().tenant(),
            Some("not-a-uuid")
        );
        assert_ne!(
            unvalidated.route_fingerprint(),
            site(None, &tenant_only).route_fingerprint()
        );
    }

    /// Every site declares the classic API token profile for the site route;
    /// only a site that uses the gateway adds the bearer profile, whose kind
    /// routes through it.
    #[test]
    fn sites_declare_vendor_profiles_whose_kinds_select_the_route() {
        let site_only = hosts(false);
        assert_eq!(
            site(Some(CLOUD_ID), &site_only).credential_descriptor(),
            CredentialDescriptor::default().profile("atlassian-api-token", "basic_api_token")
        );
        let gateway = hosts(true);
        assert_eq!(
            site(None, &gateway).credential_descriptor(),
            CredentialDescriptor::default().profile("atlassian-api-token", "basic_api_token")
        );
        let routed = site(Some(CLOUD_ID), &gateway);
        let credentials = routed.credential_descriptor();
        assert_eq!(
            credentials,
            CredentialDescriptor::default()
                .profile("atlassian-api-token", "basic_api_token")
                .profile("atlassian-bearer-token", "bearer_token")
        );
        let routes = AtlassianRoutes::new(PRODUCT, &routed, &TestHost::default()).unwrap();
        for (profile, credential, base) in [
            (
                ATLASSIAN_API_TOKEN_PROFILE,
                basic_credential("agent@example.com", "token"),
                "https://example.atlassian.net/wiki/rest/api/".to_string(),
            ),
            (
                ATLASSIAN_BEARER_TOKEN_PROFILE,
                bearer_credential("token"),
                format!("https://api.atlassian.com/ex/confluence/{CLOUD_ID}/wiki/rest/api/"),
            ),
        ] {
            let declared = credentials
                .profiles
                .iter()
                .find(|candidate| candidate.name == profile)
                .unwrap();
            assert_eq!(declared.kind, credential.kind().as_str(), "{profile}");
            assert_eq!(
                routes
                    .for_credential(&AtlassianCredential::from_static(credential.clone()))
                    .unwrap()
                    .api_base
                    .as_str(),
                base,
                "{profile}"
            );
        }
    }

    /// Every row of the Atlassian validation and routing table, with and
    /// without simultaneous service credentials: the gateway takes bearer
    /// tokens and OAuth, the site takes Basic tokens, and a connection never
    /// mixes Basic site tokens with gateway OAuth.
    #[test]
    fn gateway_validation_follows_the_connection_table() {
        const SITE_BEARER: &str = "credentials.per_user.jira.type bearer_token requires providers.jira.allowed_upstream_hosts to include api.atlassian.com";
        const SERVICE_SITE_BEARER: &str = "credentials.service.jira.type bearer_token requires providers.jira.allowed_upstream_hosts to include api.atlassian.com";
        const OAUTH_SITE: &str = "credentials.per_user.jira offers delegated (OAuth) access, which requires providers.jira.allowed_upstream_hosts to include api.atlassian.com";
        const BASIC_WITH_OAUTH: &str = "credentials.per_user.jira combines OAuth with a basic_api_token profile; OAuth acts through the Atlassian gateway, so the connection's token_profile must be atlassian-bearer-token or absent";
        const GATEWAY_PER_USER_BASIC: &str = "providers.jira.allowed_upstream_hosts includes api.atlassian.com but credentials.per_user.jira does not resolve to a bearer_token credential";
        const GATEWAY_SERVICE_BASIC: &str = "providers.jira.allowed_upstream_hosts includes api.atlassian.com but credentials.service.jira does not resolve to a bearer_token credential";
        const GATEWAY_NONE: &str = "providers.jira.allowed_upstream_hosts includes api.atlassian.com but no bearer_token or OAuth execution credential is configured";

        let validate = |gateway: bool, credentials: ServiceCredentialKinds<'_>| {
            let mut errors = Vec::new();
            validate_atlassian_gateway_credential(
                "jira",
                &hosts(gateway),
                Some(CLOUD_ID),
                credentials,
                &mut errors,
            );
            errors
        };
        let kinds = |service, per_user, delegated| {
            ServiceCredentialKinds::new(service, per_user).with_per_user_delegated(delegated)
        };
        let none: [&str; 0] = [];
        let basic = Some("basic_api_token");
        let bearer = Some("bearer_token");
        let oauth = Some("oauth");
        for (gateway, service, per_user, delegated, expected) in [
            // atlassian-api-token only: the site route.
            (false, None, basic, false, &none[..]),
            (false, basic, basic, false, &none[..]),
            (
                true,
                None,
                basic,
                false,
                &[GATEWAY_PER_USER_BASIC, GATEWAY_NONE][..],
            ),
            // atlassian-bearer-token only: the gateway.
            (true, None, bearer, false, &none[..]),
            (true, bearer, bearer, false, &none[..]),
            (false, None, bearer, false, &[SITE_BEARER][..]),
            // OAuth only: the gateway, which it requires.
            (true, None, oauth, true, &none[..]),
            (true, bearer, oauth, true, &none[..]),
            (true, basic, oauth, true, &[GATEWAY_SERVICE_BASIC][..]),
            (false, None, oauth, true, &[OAUTH_SITE][..]),
            (
                false,
                bearer,
                oauth,
                true,
                &[OAUTH_SITE, SERVICE_SITE_BEARER][..],
            ),
            // atlassian-bearer-token and OAuth: people use OAuth and
            // service accounts bearer tokens, both through the gateway.
            (true, None, bearer, true, &none[..]),
            (true, bearer, bearer, true, &none[..]),
            (true, basic, bearer, true, &[GATEWAY_SERVICE_BASIC][..]),
            // atlassian-api-token and OAuth: rejected either way.
            (true, None, basic, true, &[BASIC_WITH_OAUTH][..]),
            (true, bearer, basic, true, &[BASIC_WITH_OAUTH][..]),
            (
                false,
                None,
                basic,
                true,
                &[BASIC_WITH_OAUTH, OAUTH_SITE][..],
            ),
            (
                false,
                basic,
                basic,
                true,
                &[BASIC_WITH_OAUTH, OAUTH_SITE][..],
            ),
            // Service credentials alone keep their rules.
            (true, bearer, None, false, &none[..]),
            (
                true,
                basic,
                None,
                false,
                &[GATEWAY_SERVICE_BASIC, GATEWAY_NONE][..],
            ),
            (true, None, None, false, &[GATEWAY_NONE][..]),
            (false, bearer, None, false, &[SERVICE_SITE_BEARER][..]),
            // A secret store's records carry their own kinds.
            (
                true,
                None,
                Some("secret_store"),
                false,
                &[GATEWAY_PER_USER_BASIC, GATEWAY_NONE][..],
            ),
        ] {
            assert_eq!(
                validate(gateway, kinds(service, per_user, delegated)),
                expected,
                "gateway {gateway}, service {service:?}, per-user {per_user:?}, delegated {delegated}"
            );
        }
    }

    /// Each route's API base extends its site's root, the scope its
    /// download redirects present the credential in: the tenant host, or
    /// the configured cloud ID's path on the gateway shared by every site.
    #[test]
    fn credentials_route_to_the_tenant_or_the_gateway() {
        let host = TestHost::default();
        let allowed = hosts(true);
        let routes = AtlassianRoutes::new(PRODUCT, &site(Some(CLOUD_ID), &allowed), &host).unwrap();
        let tenant = routes
            .for_credential(&AtlassianCredential::from_static(basic_credential(
                "agent@example.com",
                "token",
            )))
            .unwrap();
        assert_eq!(
            tenant.api_base.as_str(),
            "https://example.atlassian.net/wiki/rest/api/"
        );
        assert_eq!(tenant.site_base.as_str(), "https://example.atlassian.net/");
        let gateway = routes
            .for_credential(&AtlassianCredential::from_static(bearer_credential(
                "token",
            )))
            .unwrap();
        assert_eq!(
            gateway.api_base.as_str(),
            format!("https://api.atlassian.com/ex/confluence/{CLOUD_ID}/wiki/rest/api/")
        );
        assert_eq!(
            gateway.site_base.as_str(),
            format!("https://api.atlassian.com/ex/confluence/{CLOUD_ID}/")
        );
        let built = host.built_clients();
        assert_eq!(built.len(), 4);
        assert!(built.iter().all(|client| client.provider == "confluence"
            && client.label == "providers.confluence.egress_proxy"));

        // Without a cloud ID or the gateway host, bearer credentials have no
        // route.
        for (cloud_id, gateway) in [(None, true), (Some(CLOUD_ID), false)] {
            let allowed = hosts(gateway);
            let routes =
                AtlassianRoutes::new(PRODUCT, &site(cloud_id, &allowed), &TestHost::default())
                    .unwrap();
            assert_eq!(
                routes
                    .for_credential(&AtlassianCredential::from_static(bearer_credential(
                        "token"
                    )))
                    .err()
                    .unwrap()
                    .to_string(),
                "Confluence bearer tokens and OAuth connections require providers.confluence.cloud_id and api.atlassian.com in allowed_upstream_hosts"
            );
        }
    }

    #[test]
    fn clients_need_an_api_base_ending_with_the_product_api_path() {
        let allowed = hosts(true);
        for base in [
            "https://example.atlassian.net/rest/api/",
            "https://example.atlassian.net/xwiki/rest/api/",
        ] {
            let error = AtlassianClients::new(
                PRODUCT,
                &site(None, &allowed),
                Url::parse(base).unwrap(),
                &TestHost::default(),
            )
            .err()
            .unwrap();
            assert!(
                error
                    .to_string()
                    .contains("does not end with wiki/rest/api/"),
                "{error}"
            );
        }
    }

    #[test]
    fn invalid_sites_fail_to_build() {
        let allowed = hosts(true);
        let error = AtlassianRoutes::new(
            PRODUCT,
            &site(Some("not-a-uuid"), &allowed),
            &TestHost::default(),
        )
        .err()
        .unwrap();
        assert!(
            error
                .to_string()
                .contains("providers.confluence.cloud_id is invalid"),
            "{error}"
        );
        let mut bad_tenant = site(None, &allowed);
        bad_tenant.tenant_host = "exa mple";
        let error = AtlassianRoutes::new(PRODUCT, &bad_tenant, &TestHost::default())
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("providers.confluence.tenant_host is invalid"),
            "{error}"
        );
    }

    #[test]
    fn route_fingerprints_follow_tenant_cloud_id_and_gateway_use() {
        let gateway = hosts(true);
        let tenant_only = hosts(false);
        let base = site(Some(CLOUD_ID), &gateway).route_fingerprint();
        assert_eq!(base, site(Some(CLOUD_ID), &gateway).route_fingerprint());
        let mut other_tenant = site(Some(CLOUD_ID), &gateway);
        other_tenant.tenant_host = "other.atlassian.net";
        for changed in [
            other_tenant,
            site(None, &gateway),
            site(Some("00000000-0000-0000-0000-000000000002"), &gateway),
            site(Some(CLOUD_ID), &tenant_only),
        ] {
            assert_ne!(changed.route_fingerprint(), base);
        }
        // An egress proxy does not change the route a cursor belongs to.
        let proxy = EgressProxyConfig {
            url: "http://192.0.2.10:3128".to_string(),
            username_ref: None,
            password_ref: None,
        };
        let mut proxied = site(Some(CLOUD_ID), &gateway);
        proxied.egress_proxy = Some(&proxy);
        assert_eq!(proxied.route_fingerprint(), base);
    }

    mod access_binding {
        use super::*;
        use agent_access_provider::deps::async_trait;
        use agent_access_provider::test_support::{
            InvocationBuilder, delegated_binding_id, test_signing_key,
        };
        use agent_access_provider::{
            ContinuationError, ContinuationFamily, ContinuationLifetime, ContinuationSigner,
            CredentialMode, DelegatedAccess, DelegatedBindingId, DelegatedCredential,
            DelegatedLease, ProviderInvocation,
        };
        use std::sync::Arc;

        const PAGES: ContinuationFamily = ContinuationFamily::new(
            "confluence",
            "list-page",
            1,
            ContinuationLifetime::StableWhenConfigured,
            16,
        );
        const OTHER_CLOUD_ID: &str = "00000000-0000-0000-0000-000000000002";

        /// A lease on the OAuth connection `binding` (the connection and its
        /// generation) holding access `version` for the gateway site
        /// `target`.
        struct Lease {
            binding: &'static str,
            version: &'static str,
            target: &'static str,
        }

        #[async_trait]
        impl DelegatedLease for Lease {
            fn access(&self) -> DelegatedAccess {
                DelegatedAccess::new(
                    format!("token-{}", self.version),
                    self.target,
                    "api.atlassian.com",
                    self.version,
                    i64::MAX,
                )
            }
            fn binding_identity(&self) -> DelegatedBindingId {
                delegated_binding_id(self.binding)
            }
            async fn revalidate(&self) -> Result<(), ProviderError> {
                Ok(())
            }
            fn mark_rejected(&self, _: &str) -> Result<(), ProviderError> {
                Ok(())
            }
            async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
                Err(ProviderError::deny(
                    ReasonCode::CredentialInvalid,
                    "not recoverable",
                ))
            }
        }

        fn delegated(binding: &'static str, version: &'static str) -> ExecutionAccess {
            ExecutionAccess::Delegated(lease(binding, version, CLOUD_ID))
        }

        fn lease(
            binding: &'static str,
            version: &'static str,
            target: &'static str,
        ) -> DelegatedCredential {
            agent_access_provider::host::delegated_credential(Arc::new(Lease {
                binding,
                version,
                target,
            }))
        }

        fn request(principal: &str) -> ProviderInvocation {
            InvocationBuilder::new("confluence", "attachment.list")
                .principal(principal)
                .credential_mode(CredentialMode::PerUser)
                .build()
        }

        fn seal(
            signer: &ContinuationSigner,
            request: &ProviderInvocation,
            access: &ExecutionAccess,
            cloud_id: Option<&str>,
        ) -> String {
            let binding =
                bind_atlassian_access(PAGES.bind(request.context(), "route"), access, cloud_id)
                    .unwrap();
            signer.seal(&binding, b"next").unwrap()
        }

        fn open(
            signer: &ContinuationSigner,
            request: &ProviderInvocation,
            access: &ExecutionAccess,
            cloud_id: Option<&str>,
            token: &str,
        ) -> Result<Vec<u8>, ContinuationError> {
            let binding =
                bind_atlassian_access(PAGES.bind(request.context(), "route"), access, cloud_id)
                    .unwrap();
            signer.open(&binding, token)
        }

        /// A token opens only under the method, account, connection
        /// generation and gateway site it was sealed under; routine refresh
        /// keeps it.
        #[test]
        fn delegated_tokens_survive_refresh_and_reject_other_bindings() {
            let signer = ContinuationSigner::new(None);
            let alice = request("alice");
            let token = seal(
                &signer,
                &alice,
                &delegated("alice-oauth-1", "v1"),
                Some(CLOUD_ID),
            );
            // Routine refresh advances only the access version.
            for refreshed in [
                delegated("alice-oauth-1", "v1"),
                delegated("alice-oauth-1", "v2"),
            ] {
                assert_eq!(
                    open(&signer, &alice, &refreshed, Some(CLOUD_ID), &token).unwrap(),
                    b"next"
                );
            }
            let rejected = [
                // Disconnect and reconnect (a new generation), or another
                // upstream account on the same principal.
                (
                    alice.clone(),
                    delegated("alice-oauth-2", "v1"),
                    Some(CLOUD_ID),
                ),
                (
                    alice.clone(),
                    delegated("mallory-oauth-1", "v1"),
                    Some(CLOUD_ID),
                ),
                // Another principal holding its own connection.
                (
                    request("bob"),
                    delegated("bob-oauth-1", "v1"),
                    Some(CLOUD_ID),
                ),
                // Another principal replaying under the same binding.
                (
                    request("bob"),
                    delegated("alice-oauth-1", "v1"),
                    Some(CLOUD_ID),
                ),
                // A switch to a stored token of either kind.
                (
                    alice.clone(),
                    ExecutionAccess::Static(bearer_credential("token")),
                    Some(CLOUD_ID),
                ),
                (
                    alice.clone(),
                    ExecutionAccess::Static(basic_credential("alice@example.com", "token")),
                    Some(CLOUD_ID),
                ),
                // Another gateway site, configured or granted.
                (
                    alice.clone(),
                    delegated("alice-oauth-1", "v1"),
                    Some(OTHER_CLOUD_ID),
                ),
                (
                    alice.clone(),
                    ExecutionAccess::Delegated(lease("alice-oauth-1", "v1", OTHER_CLOUD_ID)),
                    Some(CLOUD_ID),
                ),
                // Credential mode.
                (
                    InvocationBuilder::from(alice.clone())
                        .credential_mode(CredentialMode::Service)
                        .build(),
                    delegated("alice-oauth-1", "v1"),
                    Some(CLOUD_ID),
                ),
            ];
            for (index, (request, access, cloud_id)) in rejected.into_iter().enumerate() {
                assert_eq!(
                    open(&signer, &request, &access, cloud_id, &token),
                    Err(ContinuationError::Invalid),
                    "case {index}"
                );
            }
        }

        #[test]
        fn static_tokens_bind_their_kind_and_only_gateway_routes_bind_the_cloud_id() {
            let signer = ContinuationSigner::new(None);
            let alice = request("alice");
            let basic = ExecutionAccess::Static(basic_credential("alice@example.com", "token"));
            let bearer = ExecutionAccess::Static(bearer_credential("token"));
            let token = seal(&signer, &alice, &basic, Some(CLOUD_ID));
            // The site route does not depend on the gateway's site, and the
            // stored token is not bound: the principal owns the token.
            for (cloud_id, access) in [
                (Some(CLOUD_ID), basic.clone()),
                (Some(OTHER_CLOUD_ID), basic.clone()),
                (None, basic.clone()),
                (
                    Some(CLOUD_ID),
                    ExecutionAccess::Static(basic_credential("alice@example.com", "rotated")),
                ),
            ] {
                assert_eq!(
                    open(&signer, &alice, &access, cloud_id, &token).unwrap(),
                    b"next"
                );
            }
            for (request, access) in [
                (alice.clone(), bearer.clone()),
                (alice.clone(), delegated("alice-oauth-1", "v1")),
                (request("bob"), basic.clone()),
            ] {
                assert_eq!(
                    open(&signer, &request, &access, Some(CLOUD_ID), &token),
                    Err(ContinuationError::Invalid)
                );
            }
            // A bearer token routes through the gateway, so its site is bound.
            let token = seal(&signer, &alice, &bearer, Some(CLOUD_ID));
            assert_eq!(
                open(&signer, &alice, &bearer, Some(CLOUD_ID), &token).unwrap(),
                b"next"
            );
            for (access, cloud_id) in [
                (bearer.clone(), Some(OTHER_CLOUD_ID)),
                (bearer.clone(), None),
                (basic, Some(CLOUD_ID)),
                (delegated("alice-oauth-1", "v1"), Some(CLOUD_ID)),
            ] {
                assert_eq!(
                    open(&signer, &alice, &access, cloud_id, &token),
                    Err(ContinuationError::Invalid)
                );
            }
        }

        /// The gateway's site is bound in its lowercase hyphenated form, so
        /// a configured cloud ID written in another UUID form binds the same
        /// site, and another site still never opens the token.
        #[test]
        fn gateway_sites_bind_the_canonical_cloud_id() {
            let signer = ContinuationSigner::new(None);
            let alice = request("alice");
            let braced = format!("{{{CLOUD_ID}}}");
            let simple = CLOUD_ID.replace('-', "");
            for access in [
                ExecutionAccess::Static(bearer_credential("token")),
                delegated("alice-oauth-1", "v1"),
            ] {
                let token = seal(&signer, &alice, &access, Some(CLOUD_ID));
                for written in [braced.as_str(), simple.as_str()] {
                    assert_eq!(
                        open(&signer, &alice, &access, Some(written), &token).unwrap(),
                        b"next"
                    );
                    let sealed = seal(&signer, &alice, &access, Some(written));
                    assert_eq!(
                        open(&signer, &alice, &access, Some(CLOUD_ID), &sealed).unwrap(),
                        b"next"
                    );
                }
                assert_eq!(
                    open(
                        &signer,
                        &alice,
                        &access,
                        Some(&format!("{{{OTHER_CLOUD_ID}}}")),
                        &token
                    ),
                    Err(ContinuationError::Invalid)
                );
            }
        }

        /// A restart builds a new signer over the same stable key; the
        /// binding comes only from configuration and the host's selection,
        /// so a token sealed before it opens after it, including after a
        /// refresh.
        #[test]
        fn tokens_survive_a_restart_with_the_stable_key() {
            let before = ContinuationSigner::new(Some(test_signing_key(9)));
            let after = ContinuationSigner::new(Some(test_signing_key(9)));
            let alice = request("alice");
            for (sealed, opened) in [
                (
                    delegated("alice-oauth-1", "v1"),
                    delegated("alice-oauth-1", "v2"),
                ),
                (
                    ExecutionAccess::Static(bearer_credential("token")),
                    ExecutionAccess::Static(bearer_credential("token")),
                ),
            ] {
                let token = seal(&before, &alice, &sealed, Some(CLOUD_ID));
                assert_eq!(
                    open(&after, &alice, &opened, Some(CLOUD_ID), &token).unwrap(),
                    b"next"
                );
            }
        }

        #[test]
        fn access_without_atlassian_material_fails_closed() {
            let error = bind_atlassian_access(
                PAGES.bind(request("alice").context(), "route"),
                &ExecutionAccess::None,
                Some(CLOUD_ID),
            )
            .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::CredentialNotProvisioned);
            assert_eq!(error.message, "selected credential material is unavailable");
        }
    }
}
