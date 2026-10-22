//! The `atlassian` OAuth dialect ([`ATLASSIAN_OAUTH_DIALECT`]) and the
//! helpers the Jira and Confluence backends share: the vendor-level token
//! profiles and the route each credential's token type takes, the
//! tenant/gateway client routes, route-coverage validation per credential
//! source, the credential each request presents ([`AtlassianCredential`],
//! with delegated access pinned per request and one 401 recovery, and
//! attachment downloads whose redirects keep it on the route's site), the
//! credential binding of their continuations and the receipts of writes
//! whose verification failed.
mod access;
mod oauth;

pub use access::{
    AtlassianAccessError, AtlassianCredential, AtlassianDownloadError, AtlassianWriteVerification,
    PresentedAccess, is_delegated_access_failure,
};
pub use oauth::{ATLASSIAN_OAUTH_AUDIENCE, ATLASSIAN_OAUTH_DIALECT};

use agent_access_provider::host::UpstreamClientFactory;
use agent_access_provider::{
    ClientProfile, ContinuationBinding, ContinuationStage, CredentialDescriptor, CredentialProfile,
    CredentialSource, EgressDeclaration, EgressProxyConfig, ExecutionAccess, ExecutionCredential,
    ProviderBuildError, ProviderError, ReasonCode, ServiceCredentialKinds, StaticCredentialKind,
    UpstreamAuthority, UpstreamClient, UpstreamClientSpec, base_covered_by_patterns,
};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;
use url::Url;

/// The Atlassian API gateway's origin.
pub const ATLASSIAN_GATEWAY_ORIGIN: &str = "https://api.atlassian.com";

/// The stored token profile for an Atlassian account's email address and
/// classic API token, presented as HTTP Basic on the site route. Classic
/// tokens are account-wide, so one credential connection with this profile
/// can serve Jira and Confluence on one site.
pub const ATLASSIAN_API_TOKEN_PROFILE: &str = "atlassian-api-token";

/// The stored token profile for an Atlassian account's email address and
/// scoped API token, presented as HTTP Basic through the Atlassian gateway:
/// a person's scoped token, or a service account's token used with its
/// email address.
pub const ATLASSIAN_SCOPED_API_TOKEN_PROFILE: &str = "atlassian-scoped-api-token";

/// The stored token profile for a bearer token, such as an Atlassian
/// service account's token, presented as a bearer token through the
/// Atlassian gateway.
pub const ATLASSIAN_BEARER_TOKEN_PROFILE: &str = "atlassian-bearer-token";

/// The route an Atlassian credential takes, decided by its token type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtlassianRoute {
    /// The tenant host: `https://<tenant_host>/`.
    Site,
    /// The Atlassian gateway on the configured cloud ID:
    /// `https://api.atlassian.com/ex/<product>/<cloud_id>/`.
    Gateway,
}

impl AtlassianRoute {
    fn name(self) -> &'static str {
        match self {
            Self::Site => "site route",
            Self::Gateway => "Atlassian gateway route",
        }
    }
}

/// Why a credential has no Atlassian route. Nothing is presented on any
/// route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtlassianRouteError {
    /// A static credential kind Atlassian providers do not present.
    UnsupportedKind,
    /// A token profile Atlassian providers do not declare.
    UnknownProfile,
    /// A token profile declared with another kind than the credential's.
    ProfileKindMismatch,
    /// The gateway route, which needs a configured cloud ID that is a valid
    /// UUID, is not available.
    GatewayUnavailable,
}

/// One vendor-level token profile: its kind, the route it takes and the
/// label people choose it by.
struct AtlassianProfile {
    name: &'static str,
    kind: StaticCredentialKind,
    route: AtlassianRoute,
    label: &'static str,
}

/// Every token profile Atlassian providers declare, in picker order.
const ATLASSIAN_PROFILES: [AtlassianProfile; 3] = [
    AtlassianProfile {
        name: ATLASSIAN_API_TOKEN_PROFILE,
        kind: StaticCredentialKind::BasicApiToken,
        route: AtlassianRoute::Site,
        label: "Classic API token (site)",
    },
    AtlassianProfile {
        name: ATLASSIAN_SCOPED_API_TOKEN_PROFILE,
        kind: StaticCredentialKind::BasicApiToken,
        route: AtlassianRoute::Gateway,
        label: "Scoped API token (gateway)",
    },
    AtlassianProfile {
        name: ATLASSIAN_BEARER_TOKEN_PROFILE,
        kind: StaticCredentialKind::BearerToken,
        route: AtlassianRoute::Gateway,
        label: "Service account token (gateway)",
    },
];

/// The one route classifier every Atlassian decision uses: requests and
/// verification ([`AtlassianRoutes::for_credential`]), presentation,
/// continuation binding ([`bind_atlassian_access`]) and validation. A static
/// credential of `kind` lent as `profile`:
///
/// - without a profile takes its kind's route: a Basic API token the site, a
///   bearer token the gateway;
/// - with a vendor-level profile takes that profile's route, provided the
///   profile is declared with the credential's kind;
/// - with any other profile, or of any other kind, has no route.
fn static_route(kind: &str, profile: Option<&str>) -> Result<AtlassianRoute, AtlassianRouteError> {
    let Some(profile) = profile else {
        return match kind {
            "basic_api_token" => Ok(AtlassianRoute::Site),
            "bearer_token" => Ok(AtlassianRoute::Gateway),
            _ => Err(AtlassianRouteError::UnsupportedKind),
        };
    };
    let declared = ATLASSIAN_PROFILES
        .iter()
        .find(|declared| declared.name == profile)
        .ok_or(AtlassianRouteError::UnknownProfile)?;
    if declared.kind.as_str() != kind {
        return Err(AtlassianRouteError::ProfileKindMismatch);
    }
    Ok(declared.route)
}

/// [`static_route`] for a static credential the host lent.
pub(crate) fn credential_route(
    credential: &ExecutionCredential,
) -> Result<AtlassianRoute, AtlassianRouteError> {
    static_route(credential.kind().as_str(), credential.profile())
}

/// `cloud_id` in the one form the site declares, routes and binds:
/// Atlassian's own, a lowercase hyphenated UUID. Configuration accepts a
/// UUID in any form [`uuid::Uuid::parse_str`] does, such as uppercase or
/// braced, so an OAuth registration's `target` matches it however it is
/// written. `None` for a value that is not a UUID, which validation rejects.
fn canonical_cloud_id(cloud_id: &str) -> Option<String> {
    uuid::Uuid::parse_str(cloud_id)
        .ok()
        .map(|id| id.hyphenated().to_string())
}

/// Checks that every configured credential source of an Atlassian provider
/// reaches the route its token type takes:
///
/// - `providers.<p>.cloud_id`, when set, is a valid UUID; the gateway route
///   exists only then;
/// - each source's route is covered by `allowed_upstream_hosts` for every
///   API base the product uses on it ([`AtlassianProduct::api_paths`]), as
///   [`base_covered_by_patterns`] decides; a gateway source also requires
///   the cloud ID.
///
/// The sources are the `credentials.service` and `credentials.lookup`
/// credentials (by profile when they name one, else by kind), each token
/// profile the per-user connection accepts, its OAuth (always the gateway)
/// and a per-user secret store, whose records route by their own kind at
/// run time and are checked offline on the site route only. A shared
/// credential naming a profile the service does not declare with its kind
/// is reported by credential validation, not here. Errors name the source,
/// its type, the route and the uncovered bases.
pub fn validate_atlassian_routes(
    product: AtlassianProduct,
    site: &AtlassianSite<'_>,
    credentials: ServiceCredentialKinds<'_>,
    errors: &mut Vec<String>,
) {
    let service = product.provider;
    let gateway_cloud_id = match site.cloud_id {
        Some(cloud_id) => {
            let canonical = canonical_cloud_id(cloud_id);
            if canonical.is_none() {
                errors.push(format!(
                    "providers.{service}.cloud_id must be a valid Atlassian cloud UUID"
                ));
            }
            canonical
        }
        None => None,
    };
    // Each source: its configuration key, its type and its route; `None`
    // for a secret store, whose records' kinds are known only at run time.
    let mut sources = Vec::<(String, String, Option<AtlassianRoute>)>::new();
    let mut shared = |mode: &str, source: Option<CredentialSource<'_>>| {
        let label = format!("{mode}.{service}");
        match source {
            None => {}
            Some(CredentialSource::Static { kind, profile, .. }) => {
                if let Ok(route) = static_route(kind, profile) {
                    let kind = match profile {
                        Some(profile) => format!("profile {profile}"),
                        None => format!("type {kind}"),
                    };
                    sources.push((label, kind, Some(route)));
                }
            }
            Some(CredentialSource::SecretStore) => {
                sources.push((label, "secret_store".to_string(), None));
            }
            Some(_) => errors.push(format!(
                "{label} is a credential source Atlassian providers do not support"
            )),
        }
    };
    shared("credentials.service", credentials.service);
    shared("credentials.lookup", credentials.lookup);
    let per_user = format!("credentials.per_user.{service}");
    for profile in credentials.per_user_profiles {
        if let Ok(route) = static_route(profile.kind, Some(&profile.name)) {
            sources.push((
                per_user.clone(),
                format!("profile {}", profile.name),
                Some(route),
            ));
        }
    }
    if credentials.per_user_secret_store {
        sources.push((per_user.clone(), "secret_store".to_string(), None));
    }
    if credentials.per_user_delegated {
        sources.push((per_user, "OAuth".to_string(), Some(AtlassianRoute::Gateway)));
    }

    for (source, kind, route) in sources {
        let (route, bases) = match route {
            Some(AtlassianRoute::Gateway) => match &gateway_cloud_id {
                Some(cloud_id) => (AtlassianRoute::Gateway, product.gateway_api_bases(cloud_id)),
                None => {
                    if site.cloud_id.is_none() {
                        errors.push(format!(
                            "{source} ({kind}) takes the Atlassian gateway route, which requires providers.{service}.cloud_id"
                        ));
                    }
                    continue;
                }
            },
            Some(AtlassianRoute::Site) | None => (
                AtlassianRoute::Site,
                product.site_api_bases(site.tenant_host),
            ),
        };
        let uncovered = bases
            .iter()
            .filter(|base| !base_covered_by_patterns(base, site.allowed_upstream_hosts))
            .map(Url::as_str)
            .collect::<Vec<_>>();
        if !uncovered.is_empty() {
            let records = if kind == "secret_store" {
                " its basic_api_token records take"
            } else {
                ""
            };
            errors.push(format!(
                "{source} ({kind}) takes the {}{records}, but providers.{service}.allowed_upstream_hosts does not cover {}",
                route.name(),
                uncovered.join(" and ")
            ));
        }
    }
}

/// Binds a continuation or handle to the execution material that reaches an
/// Atlassian site, after the configuration and resource fields the provider
/// binds:
///
/// - the credential method: a static credential (a stored or service token)
///   or delegated (OAuth) access;
/// - for a static credential, its kind;
/// - for delegated access, the lease's delegated binding (the OAuth
///   connection and its generation, never the access version), target and
///   audience. Routine refresh keeps them; reconnecting, replacing the
///   account or new consent changes the binding;
/// - for a credential whose token type takes the Atlassian gateway route
///   (delegated access, a bearer token or a scoped API token), the
///   configured `cloud_id`, the site the gateway reaches, in its lowercase
///   hyphenated form, however the configuration writes it. Its absence is
///   bound too, so a scoped API token (Basic on the gateway) never opens what
///   a classic one (Basic on the site) sealed, or the reverse.
///
/// A token sealed under one method, account, connection generation, route or
/// gateway site therefore never opens under another. Every input is fixed by
/// configuration or the host's selection, so a token survives a restart
/// whenever its family's key does. Execution material Atlassian providers do
/// not accept, including none, material with no route, and a gateway route
/// without a valid `cloud_id`, fail closed.
pub fn bind_atlassian_access<Stage: ContinuationStage>(
    binding: ContinuationBinding<Stage>,
    access: &ExecutionAccess,
    cloud_id: Option<&str>,
) -> Result<ContinuationBinding<Stage>, ProviderError> {
    let (binding, route) = match access {
        ExecutionAccess::Static(credential) => (
            binding
                .text("credentialMethod", "static")
                .text("credentialKind", credential.kind().as_str()),
            credential_route(credential),
        ),
        ExecutionAccess::Delegated(credential) => (
            binding
                .text("credentialMethod", "delegated")
                .delegated(credential),
            Ok(AtlassianRoute::Gateway),
        ),
        _ => return Err(atlassian_access_unavailable()),
    };
    let gateway_cloud_id = match route.map_err(|_| atlassian_access_unavailable())? {
        AtlassianRoute::Site => None,
        AtlassianRoute::Gateway => Some(
            cloud_id
                .and_then(canonical_cloud_id)
                .ok_or_else(atlassian_access_unavailable)?,
        ),
    };
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
/// below the tenant host and the gateway site, the other API paths its
/// requests use there, and statuses with product-specific reasons.
#[derive(Debug, Clone, Copy)]
pub struct AtlassianProduct {
    pub provider: &'static str,
    pub name: &'static str,
    pub api_path: &'static str,
    /// API paths below the site root that requests use besides
    /// `api_path`, such as Confluence's `wiki/api/v2/`. Route coverage
    /// requires each of them.
    pub other_api_paths: &'static [&'static str],
    pub status_reasons: &'static [(u16, ReasonCode)],
}

impl AtlassianProduct {
    /// Every API path below the site root: `api_path`, then the others.
    pub fn api_paths(&self) -> impl Iterator<Item = &'static str> {
        std::iter::once(self.api_path).chain(self.other_api_paths.iter().copied())
    }

    /// The API bases on the site route: `https://<tenant_host>/<path>`.
    /// Empty for a tenant host that is not a valid host.
    fn site_api_bases(&self, tenant_host: &str) -> Vec<Url> {
        self.api_paths()
            .filter_map(|path| Url::parse(&format!("https://{tenant_host}/{path}")).ok())
            .collect()
    }

    /// The API bases on the gateway route for `cloud_id`:
    /// `https://api.atlassian.com/ex/<provider>/<cloud_id>/<path>`.
    fn gateway_api_bases(&self, cloud_id: &str) -> Vec<Url> {
        self.api_paths()
            .filter_map(|path| {
                Url::parse(&format!(
                    "{ATLASSIAN_GATEWAY_ORIGIN}/ex/{}/{cloud_id}/{path}",
                    self.provider
                ))
                .ok()
            })
            .collect()
    }
}

/// The site configuration an Atlassian provider routes by.
#[derive(Debug, Clone, Copy)]
pub struct AtlassianSite<'a> {
    pub tenant_host: &'a str,
    /// The cloud ID as configured. The site declares, routes, fingerprints
    /// and binds its lowercase hyphenated form; the gateway route exists
    /// only when it is a valid UUID.
    pub cloud_id: Option<&'a str>,
    pub egress_proxy: Option<&'a EgressProxyConfig>,
    pub allowed_upstream_hosts: &'a [String],
}

impl AtlassianSite<'_> {
    /// The cloud ID of the site's gateway route as the route names it, a
    /// lowercase hyphenated UUID: what delegated access is pinned to before
    /// each request and what gateway routes bind. The gateway route is
    /// available exactly when this is set: `None` without a cloud ID or
    /// with one that is not a UUID, which validation rejects.
    pub fn gateway_cloud_id(&self) -> Option<Arc<str>> {
        self.cloud_id.and_then(canonical_cloud_id).map(Arc::from)
    }

    /// The credentials Jira and Confluence declare for this site, each
    /// route-bound (only the declaring provider presents it, because the
    /// token type decides where it goes) and labeled for pickers:
    /// [`ATLASSIAN_API_TOKEN_PROFILE`] (`basic_api_token`, site route)
    /// always, and with the gateway route available,
    /// [`ATLASSIAN_SCOPED_API_TOKEN_PROFILE`] (`basic_api_token`) and
    /// [`ATLASSIAN_BEARER_TOKEN_PROFILE`] (`bearer_token`) through it. Both
    /// products declare the same profiles, so one credential connection can
    /// serve both.
    pub fn credential_descriptor(&self) -> CredentialDescriptor {
        let gateway = self.gateway_cloud_id().is_some();
        ATLASSIAN_PROFILES
            .iter()
            .filter(|profile| gateway || profile.route == AtlassianRoute::Site)
            .fold(CredentialDescriptor::default(), |credentials, profile| {
                credentials.with_profile(
                    CredentialProfile::new(profile.name, profile.kind.as_str())
                        .with_label(profile.label)
                        .route_bound(),
                )
            })
    }

    /// The site's upstream authority: the tenant host's origin, the cloud
    /// ID when configured, in its lowercase hyphenated form, and the
    /// Atlassian gateway when the gateway route is available. Jira and
    /// Confluence on one site with one cloud ID therefore act on the same
    /// instance, and with different cloud IDs on different ones. `None` for
    /// a tenant host that is not a valid host.
    pub fn upstream_authority(&self) -> Option<UpstreamAuthority> {
        let mut authority =
            UpstreamAuthority::from_base_url(&format!("https://{}", self.tenant_host)).ok()?;
        if let Some(cloud_id) = self.cloud_id {
            authority = authority
                .with_tenant(canonical_cloud_id(cloud_id).unwrap_or_else(|| cloud_id.to_owned()));
        }
        if self.gateway_cloud_id().is_some() {
            authority = authority
                .with_tenant_gateway(ATLASSIAN_GATEWAY_ORIGIN)
                .ok()?;
        }
        Some(authority)
    }

    /// A digest of the configuration an upstream cursor's route depends on:
    /// the tenant host and the cloud ID in its lowercase hyphenated form.
    /// Continuations relaying a cursor bind it, beside the execution
    /// material [`bind_atlassian_access`] binds, whose method and token type
    /// select the route.
    pub fn route_fingerprint(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"agent-access/atlassian-route/v2\0");
        let cloud_id = self.cloud_id.map(|cloud_id| {
            canonical_cloud_id(cloud_id).map_or(Cow::Borrowed(cloud_id), Cow::Owned)
        });
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

/// An Atlassian provider's routes: the tenant host, and the Atlassian
/// gateway when the site configures a valid cloud ID. Each credential takes
/// the route its token type selects ([`AtlassianCredential::route`]).
#[derive(Clone)]
pub struct AtlassianRoutes {
    product: AtlassianProduct,
    tenant: AtlassianClients,
    gateway: Option<AtlassianClients>,
}

impl AtlassianRoutes {
    /// The tenant route `https://<tenant_host>/<api_path>` and, when the
    /// site sets a cloud ID, `https://api.atlassian.com/ex/<provider>/<cloud_id>/<api_path>`.
    /// A cloud ID that is not a UUID fails the build.
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
        let gateway = match site.cloud_id {
            Some(cloud_id) => {
                let cloud_id = uuid::Uuid::parse_str(cloud_id).map_err(|error| {
                    ProviderBuildError::invalid(format!(
                        "providers.{provider}.cloud_id is invalid: {error}"
                    ))
                })?;
                let gateway_base = Url::parse(&format!(
                    "{ATLASSIAN_GATEWAY_ORIGIN}/ex/{provider}/{}/{}",
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

    /// The clients for `credential`'s route ([`AtlassianCredential::route`]):
    /// the tenant host for a classic API token or an unprofiled Basic
    /// token, the gateway for delegated access, a scoped API token or a
    /// bearer token. A credential without a route, or one for the gateway
    /// when the site has none, is refused, so nothing is sent.
    pub fn for_credential(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<&AtlassianClients, AtlassianRouteUnavailable> {
        let unavailable = |reason| AtlassianRouteUnavailable {
            product: self.product,
            reason,
        };
        match credential.route().map_err(unavailable)? {
            AtlassianRoute::Site => Ok(&self.tenant),
            AtlassianRoute::Gateway => self
                .gateway
                .as_ref()
                .ok_or_else(|| unavailable(AtlassianRouteError::GatewayUnavailable)),
        }
    }

    /// The gateway clients, for tests that redirect the gateway route.
    pub fn gateway_mut(&mut self) -> Option<&mut AtlassianClients> {
        self.gateway.as_mut()
    }
}

/// A credential [`AtlassianRoutes::for_credential`] refused: one without a
/// route, or one for the gateway when the site has no gateway route.
#[derive(Debug, Clone, Copy)]
pub struct AtlassianRouteUnavailable {
    product: AtlassianProduct,
    reason: AtlassianRouteError,
}

impl AtlassianRouteUnavailable {
    /// `product`'s refusal of a credential without a route, such as one
    /// [`AtlassianCredential::present`] reports.
    pub fn new(product: AtlassianProduct, reason: AtlassianRouteError) -> Self {
        Self { product, reason }
    }

    /// Why the credential has no route.
    pub fn reason(&self) -> AtlassianRouteError {
        self.reason
    }

    /// The refusal as the provider reports it: a `credential_not_provisioned`
    /// denial, as continuation binding reports the same credential, naming
    /// why. Nothing was sent.
    pub fn provider_error(&self) -> ProviderError {
        ProviderError::deny(ReasonCode::CredentialNotProvisioned, self.to_string())
    }
}

impl fmt::Display for AtlassianRouteUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let AtlassianProduct { provider, name, .. } = self.product;
        match self.reason {
            AtlassianRouteError::GatewayUnavailable => write!(
                formatter,
                "{name} OAuth connections, scoped API tokens and bearer tokens take the Atlassian gateway route, which requires providers.{provider}.cloud_id"
            ),
            AtlassianRouteError::UnsupportedKind => {
                write!(
                    formatter,
                    "{name} does not present the selected credential's kind"
                )
            }
            AtlassianRouteError::UnknownProfile => write!(
                formatter,
                "{name} does not present the selected credential's token profile"
            ),
            AtlassianRouteError::ProfileKindMismatch => write!(
                formatter,
                "the selected credential's kind does not match its {name} token profile"
            ),
        }
    }
}

impl std::error::Error for AtlassianRouteUnavailable {}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::CredentialProfile;
    use agent_access_provider::test_support::{
        TestHost, basic_credential, bearer_credential, credential_with_profile,
    };

    const PRODUCT: AtlassianProduct = AtlassianProduct {
        provider: "confluence",
        name: "Confluence",
        api_path: "wiki/rest/api/",
        other_api_paths: &["wiki/api/v2/"],
        status_reasons: &[(409, ReasonCode::VersionConflict)],
    };
    const JIRA: AtlassianProduct = AtlassianProduct {
        provider: "jira",
        name: "Jira",
        api_path: "rest/api/3/",
        other_api_paths: &[],
        status_reasons: &[],
    };
    const CLOUD_ID: &str = "00000000-0000-0000-0000-000000000001";
    const OTHER_CLOUD_ID: &str = "00000000-0000-0000-0000-000000000002";

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

    /// A static token lent as `profile`, as the host lends a stored row or
    /// a configured shared credential that names one.
    fn profiled(credential: ExecutionCredential, profile: &str) -> AtlassianCredential {
        AtlassianCredential::from_static(credential_with_profile(credential, profile))
    }

    /// A site declares its tenant host, its cloud ID in canonical form and,
    /// whenever that cloud ID is a valid UUID, the gateway, whatever the
    /// allowlist says. Jira and Confluence on one site act on the same
    /// instance exactly when they agree on the cloud ID.
    #[test]
    fn a_site_declares_its_host_cloud_id_and_gateway_route() {
        let site_only = hosts(false);
        let gateway = hosts(true);
        let authority = site(None, &site_only).upstream_authority().unwrap();
        assert_eq!(authority.origin(), "https://example.atlassian.net");
        assert_eq!(
            (authority.tenant(), authority.tenant_gateway()),
            (None, None)
        );
        for allowed in [&site_only, &gateway] {
            let routed = site(Some(CLOUD_ID), allowed).upstream_authority().unwrap();
            assert_eq!(routed.tenant(), Some(CLOUD_ID));
            assert_eq!(routed.tenant_gateway(), Some(ATLASSIAN_GATEWAY_ORIGIN));
        }
        let routed = site(Some(CLOUD_ID), &gateway).upstream_authority().unwrap();
        let braced = format!("{{{CLOUD_ID}}}");
        assert!(
            routed.same_instance(
                &site(Some(&braced), &site_only)
                    .upstream_authority()
                    .unwrap()
            )
        );
        for other in [site(None, &gateway), site(Some(OTHER_CLOUD_ID), &gateway)] {
            assert!(!routed.same_instance(&other.upstream_authority().unwrap()));
        }
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
        // A value that is not a UUID, which validation rejects, has no
        // gateway route, whatever the allowlist says; it is declared as
        // written, so it never matches another site's cloud ID.
        for allowed in [hosts(false), hosts(true)] {
            let unvalidated = site(Some("not-a-uuid"), &allowed);
            let authority = unvalidated.upstream_authority().unwrap();
            assert_eq!(authority.tenant(), Some("not-a-uuid"));
            assert_eq!(authority.tenant_gateway(), None);
            assert_eq!(unvalidated.gateway_cloud_id(), None);
            assert_eq!(
                unvalidated.credential_descriptor(),
                site(None, &allowed).credential_descriptor()
            );
        }
    }

    /// Every site declares the classic API token profile for the site route;
    /// a site with a cloud ID, and so a gateway route, also declares the
    /// scoped API token and bearer profiles through it, whatever its
    /// allowlist says. Each is labeled for pickers and route-bound, and its
    /// stored profile, not its kind, selects the route.
    #[test]
    fn sites_declare_route_bound_profiles_whose_types_select_the_route() {
        let classic = CredentialProfile::new("atlassian-api-token", "basic_api_token")
            .with_label("Classic API token (site)")
            .route_bound();
        let scoped = CredentialProfile::new("atlassian-scoped-api-token", "basic_api_token")
            .with_label("Scoped API token (gateway)")
            .route_bound();
        let bearer = CredentialProfile::new("atlassian-bearer-token", "bearer_token")
            .with_label("Service account token (gateway)")
            .route_bound();
        for allowed in [hosts(false), hosts(true)] {
            assert_eq!(
                site(None, &allowed).credential_descriptor(),
                CredentialDescriptor::default().with_profile(classic.clone())
            );
            assert_eq!(
                site(Some(CLOUD_ID), &allowed).credential_descriptor(),
                CredentialDescriptor::default()
                    .with_profile(classic.clone())
                    .with_profile(scoped.clone())
                    .with_profile(bearer.clone())
            );
        }
        let gateway = hosts(true);
        let routed = site(Some(CLOUD_ID), &gateway);
        let credentials = routed.credential_descriptor();
        let routes = AtlassianRoutes::new(PRODUCT, &routed, &TestHost::default()).unwrap();
        let site_base = "https://example.atlassian.net/wiki/rest/api/".to_string();
        let gateway_base =
            format!("https://api.atlassian.com/ex/confluence/{CLOUD_ID}/wiki/rest/api/");
        for (profile, credential, base) in [
            (
                ATLASSIAN_API_TOKEN_PROFILE,
                basic_credential("agent@example.com", "token"),
                &site_base,
            ),
            (
                ATLASSIAN_SCOPED_API_TOKEN_PROFILE,
                basic_credential("agent@example.com", "token"),
                &gateway_base,
            ),
            (
                ATLASSIAN_BEARER_TOKEN_PROFILE,
                bearer_credential("token"),
                &gateway_base,
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
                    .for_credential(&profiled(credential, profile))
                    .unwrap()
                    .api_base
                    .as_str(),
                base.as_str(),
                "{profile}"
            );
        }
    }

    /// The one route classifier: a static token without a profile takes its
    /// kind's route, one with a vendor profile that profile's route when the
    /// kinds agree, and anything else has no route; delegated access takes
    /// the gateway. A gateway credential on a site without a gateway route
    /// is refused too. Nothing is sent on a guessed route.
    #[test]
    fn credentials_route_by_token_type_and_fail_closed() {
        use AtlassianRoute::{Gateway, Site};
        use AtlassianRouteError::{GatewayUnavailable, ProfileKindMismatch, UnknownProfile};
        let basic = || basic_credential("agent@example.com", "token");
        let bearer = || bearer_credential("token");
        let allowed = hosts(true);
        let with_gateway = AtlassianRoutes::new(
            PRODUCT,
            &site(Some(CLOUD_ID), &allowed),
            &TestHost::default(),
        )
        .unwrap();
        let without_gateway =
            AtlassianRoutes::new(PRODUCT, &site(None, &allowed), &TestHost::default()).unwrap();
        let site_base = "https://example.atlassian.net/wiki/rest/api/";
        let gateway_base =
            format!("https://api.atlassian.com/ex/confluence/{CLOUD_ID}/wiki/rest/api/");
        for (credential, expected) in [
            (AtlassianCredential::from_static(basic()), Ok(Site)),
            (AtlassianCredential::from_static(bearer()), Ok(Gateway)),
            (profiled(basic(), ATLASSIAN_API_TOKEN_PROFILE), Ok(Site)),
            (
                profiled(basic(), ATLASSIAN_SCOPED_API_TOKEN_PROFILE),
                Ok(Gateway),
            ),
            (
                profiled(bearer(), ATLASSIAN_BEARER_TOKEN_PROFILE),
                Ok(Gateway),
            ),
            (
                profiled(bearer(), ATLASSIAN_API_TOKEN_PROFILE),
                Err(ProfileKindMismatch),
            ),
            (
                profiled(bearer(), ATLASSIAN_SCOPED_API_TOKEN_PROFILE),
                Err(ProfileKindMismatch),
            ),
            (
                profiled(basic(), ATLASSIAN_BEARER_TOKEN_PROFILE),
                Err(ProfileKindMismatch),
            ),
            (
                profiled(basic(), "gitlab-access-token"),
                Err(UnknownProfile),
            ),
            (
                profiled(bearer(), "atlassian-bearer-token-v2"),
                Err(UnknownProfile),
            ),
            (
                profiled(basic(), "Atlassian-API-Token"),
                Err(UnknownProfile),
            ),
            (profiled(basic(), ""), Err(UnknownProfile)),
        ] {
            assert_eq!(credential.route(), expected, "{credential:?}");
            let route = |routes: &AtlassianRoutes| {
                routes
                    .for_credential(&credential)
                    .map(|clients| clients.api_base.to_string())
                    .map_err(|error| error.reason())
            };
            match expected {
                Ok(Site) => {
                    assert_eq!(route(&with_gateway).unwrap(), site_base);
                    assert_eq!(route(&without_gateway).unwrap(), site_base);
                }
                Ok(Gateway) => {
                    assert_eq!(route(&with_gateway).unwrap(), gateway_base);
                    assert_eq!(route(&without_gateway), Err(GatewayUnavailable));
                }
                Err(reason) => {
                    assert_eq!(route(&with_gateway), Err(reason));
                    assert_eq!(route(&without_gateway), Err(reason));
                }
            }
        }
        let messages = [
            (
                profiled(basic(), ATLASSIAN_SCOPED_API_TOKEN_PROFILE),
                &without_gateway,
                "Confluence OAuth connections, scoped API tokens and bearer tokens take the Atlassian gateway route, which requires providers.confluence.cloud_id",
            ),
            (
                profiled(basic(), "gitlab-access-token"),
                &with_gateway,
                "Confluence does not present the selected credential's token profile",
            ),
            (
                profiled(bearer(), ATLASSIAN_API_TOKEN_PROFILE),
                &with_gateway,
                "the selected credential's kind does not match its Confluence token profile",
            ),
        ];
        // Each refusal is reported as the credential denial continuation
        // binding reports for the same credential.
        for (credential, routes, message) in messages {
            let refusal = routes.for_credential(&credential).err().unwrap();
            assert_eq!(refusal.to_string(), message);
            assert_eq!(
                refusal.provider_error(),
                ProviderError::deny(ReasonCode::CredentialNotProvisioned, message)
            );
            assert_eq!(
                AtlassianRouteUnavailable::new(PRODUCT, refusal.reason()).provider_error(),
                refusal.provider_error()
            );
        }
    }

    /// Validates `credentials` for Confluence on `site(cloud_id, allowed)`.
    fn validate(
        product: AtlassianProduct,
        cloud_id: Option<&str>,
        allowed: &[String],
        credentials: ServiceCredentialKinds<'_>,
    ) -> Vec<String> {
        let mut errors = Vec::new();
        validate_atlassian_routes(product, &site(cloud_id, allowed), credentials, &mut errors);
        errors
    }

    fn declared(names: &[&str]) -> Vec<CredentialProfile> {
        let descriptor = site(Some(CLOUD_ID), &[]).credential_descriptor();
        names
            .iter()
            .map(|name| {
                descriptor
                    .profiles
                    .iter()
                    .find(|profile| profile.name == *name)
                    .unwrap()
                    .clone()
            })
            .collect()
    }

    /// Each configured source must reach the route its token type takes,
    /// for every API base the product uses on it: people on OAuth and
    /// service accounts on classic and service-account tokens coexist when
    /// the allowlist covers both routes, and an uncovered base is reported
    /// for the source, its type and its route. The removed all-or-nothing
    /// rules do not return: classic tokens beside OAuth, the gateway
    /// allowed without a gateway credential and a classic lookup credential
    /// beside gateway credentials are all valid.
    #[test]
    fn route_coverage_holds_each_credential_source_to_its_route() {
        let site_v1 = "https://example.atlassian.net/wiki/rest/api/";
        let site_v2 = "https://example.atlassian.net/wiki/api/v2/";
        let gateway_v1 =
            format!("https://api.atlassian.com/ex/confluence/{CLOUD_ID}/wiki/rest/api/");
        let gateway_v2 = format!("https://api.atlassian.com/ex/confluence/{CLOUD_ID}/wiki/api/v2/");
        let site_patterns = hosts(false);
        let gateway_patterns = vec!["https://api.atlassian.com/ex/confluence/**".to_string()];
        let both = hosts(true);
        let site_gap = format!(
            "providers.confluence.allowed_upstream_hosts does not cover {site_v1} and {site_v2}"
        );
        let gateway_gap = format!(
            "providers.confluence.allowed_upstream_hosts does not cover {gateway_v1} and {gateway_v2}"
        );
        let none: Vec<String> = Vec::new();

        // The motivating deployment: people on OAuth, service accounts on
        // classic and service-account tokens, a classic service credential
        // and a service-account lookup credential.
        let accepted = declared(&[ATLASSIAN_API_TOKEN_PROFILE, ATLASSIAN_BEARER_TOKEN_PROFILE]);
        let mixed = ServiceCredentialKinds::default()
            .with_service(Some(CredentialSource::static_kind("basic_api_token")))
            .with_lookup(Some(CredentialSource::static_profile(
                "bearer_token",
                ATLASSIAN_BEARER_TOKEN_PROFILE,
            )))
            .with_per_user_profiles(&accepted)
            .with_per_user_delegated(true);
        assert_eq!(validate(PRODUCT, Some(CLOUD_ID), &both, mixed), none);
        assert_eq!(
            validate(PRODUCT, Some(CLOUD_ID), &site_patterns, mixed),
            [
                format!(
                    "credentials.lookup.confluence (profile atlassian-bearer-token) takes the Atlassian gateway route, but {gateway_gap}"
                ),
                format!(
                    "credentials.per_user.confluence (profile atlassian-bearer-token) takes the Atlassian gateway route, but {gateway_gap}"
                ),
                format!(
                    "credentials.per_user.confluence (OAuth) takes the Atlassian gateway route, but {gateway_gap}"
                ),
            ]
        );
        assert_eq!(
            validate(PRODUCT, Some(CLOUD_ID), &gateway_patterns, mixed),
            [
                format!(
                    "credentials.service.confluence (type basic_api_token) takes the site route, but {site_gap}"
                ),
                format!(
                    "credentials.per_user.confluence (profile atlassian-api-token) takes the site route, but {site_gap}"
                ),
            ]
        );

        // A scoped API token is Basic on the gateway: per user, or as a
        // shared credential naming its profile.
        let scoped = declared(&[ATLASSIAN_SCOPED_API_TOKEN_PROFILE]);
        let scoped_sources = ServiceCredentialKinds::default()
            .with_service(Some(CredentialSource::static_profile(
                "basic_api_token",
                ATLASSIAN_SCOPED_API_TOKEN_PROFILE,
            )))
            .with_per_user_profiles(&scoped);
        assert_eq!(
            validate(PRODUCT, Some(CLOUD_ID), &gateway_patterns, scoped_sources),
            none
        );
        assert_eq!(
            validate(PRODUCT, Some(CLOUD_ID), &site_patterns, scoped_sources),
            [
                format!(
                    "credentials.service.confluence (profile atlassian-scoped-api-token) takes the Atlassian gateway route, but {gateway_gap}"
                ),
                format!(
                    "credentials.per_user.confluence (profile atlassian-scoped-api-token) takes the Atlassian gateway route, but {gateway_gap}"
                ),
            ]
        );

        // Without a cloud ID there is no gateway route: gateway sources
        // name the missing cloud ID, and site sources still validate.
        let classic = declared(&[ATLASSIAN_API_TOKEN_PROFILE]);
        let without_cloud_id = ServiceCredentialKinds::default()
            .with_service(Some(CredentialSource::static_kind("bearer_token")))
            .with_per_user_profiles(&classic)
            .with_per_user_delegated(true);
        assert_eq!(
            validate(PRODUCT, None, &both, without_cloud_id),
            [
                "credentials.service.confluence (type bearer_token) takes the Atlassian gateway route, which requires providers.confluence.cloud_id",
                "credentials.per_user.confluence (OAuth) takes the Atlassian gateway route, which requires providers.confluence.cloud_id",
            ]
        );

        // A cloud ID must be a UUID whenever it is set; its gateway sources
        // are not reported again.
        assert_eq!(
            validate(PRODUCT, Some("not-a-uuid"), &both, without_cloud_id),
            ["providers.confluence.cloud_id must be a valid Atlassian cloud UUID"]
        );
        assert_eq!(
            validate(
                PRODUCT,
                Some("not-a-uuid"),
                &site_patterns,
                ServiceCredentialKinds::default()
            ),
            ["providers.confluence.cloud_id must be a valid Atlassian cloud UUID"]
        );

        // Removed rules: classic tokens beside OAuth, the gateway allowed
        // without any gateway credential, and a classic lookup credential
        // beside gateway execution credentials.
        let classic_with_oauth = ServiceCredentialKinds::default()
            .with_per_user_profiles(&classic)
            .with_per_user_delegated(true);
        assert_eq!(
            validate(PRODUCT, Some(CLOUD_ID), &both, classic_with_oauth),
            none
        );
        let classic_only = ServiceCredentialKinds::default()
            .with_service(Some(CredentialSource::static_kind("basic_api_token")));
        assert_eq!(validate(PRODUCT, Some(CLOUD_ID), &both, classic_only), none);
        let bearer = declared(&[ATLASSIAN_BEARER_TOKEN_PROFILE]);
        let classic_lookup = ServiceCredentialKinds::default()
            .with_lookup(Some(CredentialSource::static_kind("basic_api_token")))
            .with_per_user_profiles(&bearer)
            .with_per_user_delegated(true);
        assert_eq!(
            validate(PRODUCT, Some(CLOUD_ID), &both, classic_lookup),
            none
        );

        // A shared credential naming a profile Atlassian does not declare
        // with its kind has no route; credential validation reports it.
        let undeclared = ServiceCredentialKinds::default()
            .with_service(Some(CredentialSource::static_profile(
                "bearer_token",
                ATLASSIAN_API_TOKEN_PROFILE,
            )))
            .with_lookup(Some(CredentialSource::static_profile(
                "basic_api_token",
                "gitlab-access-token",
            )));
        assert_eq!(validate(PRODUCT, Some(CLOUD_ID), &none, undeclared), none);

        // No credential source, no route to cover.
        assert_eq!(
            validate(
                PRODUCT,
                Some(CLOUD_ID),
                &none,
                ServiceCredentialKinds::default()
            ),
            none
        );
    }

    /// A secret store's records each carry their own kind, known only at
    /// run time, and no profile: offline validation checks the site route,
    /// which the common Basic record takes. A bearer record whose gateway
    /// route is unavailable or uncovered is refused at run time, before
    /// anything is sent.
    #[test]
    fn secret_store_records_are_checked_offline_on_the_site_route() {
        let secret_store = ServiceCredentialKinds::default().with_per_user_secret_store(true);
        let none: Vec<String> = Vec::new();
        assert_eq!(validate(PRODUCT, None, &hosts(false), secret_store), none);
        assert_eq!(
            validate(PRODUCT, Some(CLOUD_ID), &hosts(true), secret_store),
            none
        );
        let gateway_only = vec!["https://api.atlassian.com/ex/confluence/**".to_string()];
        assert_eq!(
            validate(PRODUCT, Some(CLOUD_ID), &gateway_only, secret_store),
            [
                "credentials.per_user.confluence (secret_store) takes the site route its basic_api_token records take, but providers.confluence.allowed_upstream_hosts does not cover https://example.atlassian.net/wiki/rest/api/ and https://example.atlassian.net/wiki/api/v2/"
            ]
        );
        let shared = ServiceCredentialKinds::default()
            .with_service(Some(CredentialSource::SecretStore))
            .with_lookup(Some(CredentialSource::SecretStore));
        assert_eq!(
            validate(PRODUCT, Some(CLOUD_ID), &gateway_only, shared).len(),
            2
        );

        // At run time a bearer record without a gateway route is refused
        // before anything is sent; a Basic record takes the site.
        let allowed = hosts(false);
        let routes =
            AtlassianRoutes::new(PRODUCT, &site(None, &allowed), &TestHost::default()).unwrap();
        assert_eq!(
            routes
                .for_credential(&AtlassianCredential::from_static(bearer_credential(
                    "record"
                )))
                .err()
                .unwrap()
                .reason(),
            AtlassianRouteError::GatewayUnavailable
        );
        assert_eq!(
            routes
                .for_credential(&AtlassianCredential::from_static(basic_credential(
                    "agent@example.com",
                    "record"
                )))
                .unwrap()
                .api_base
                .as_str(),
            "https://example.atlassian.net/wiki/rest/api/"
        );
    }

    /// Coverage uses the runtime allowlist grammar: wildcards before and
    /// after the product, cloud ID and API-base segments are accepted when
    /// they can match some request below the base, and query constraints
    /// are ignored. A pattern for another product, another cloud ID,
    /// another port or an unrelated path covers nothing, and the error
    /// names the source.
    #[test]
    fn route_coverage_accepts_narrow_and_wildcard_patterns() {
        let oauth = ServiceCredentialKinds::default().with_per_user_delegated(true);
        let classic = ServiceCredentialKinds::default()
            .with_service(Some(CredentialSource::static_kind("basic_api_token")));
        let check = |credentials: ServiceCredentialKinds<'_>, pattern: String| {
            validate(JIRA, Some(CLOUD_ID), &[pattern], credentials)
        };
        for pattern in [
            format!("https://api.atlassian.com/ex/jira/{CLOUD_ID}/rest/api/3/**"),
            format!("https://api.atlassian.com/ex/jira/{CLOUD_ID}/rest/api/3/issue/**"),
            format!("https://api.atlassian.com/ex/*/{CLOUD_ID}/rest/api/3/issue/**"),
            "https://api.atlassian.com/ex/jira/*/rest/api/3/**".to_string(),
            format!("https://api.atlassian.com/ex/jira/{CLOUD_ID}/*/api/3/search/**"),
            format!("https://api.atlassian.com/ex/jira/{CLOUD_ID}/rest/api/3/*"),
            "https://api.atlassian.com/ex/**/issue".to_string(),
            "https://api.atlassian.com/**".to_string(),
            "https://api.atlassian.com:443/ex/jira/**".to_string(),
            format!(
                "https://api.atlassian.com/ex/jira/{CLOUD_ID}/rest/api/3/search/jql?maxResults=50"
            ),
        ] {
            assert_eq!(
                check(oauth, pattern.clone()),
                Vec::<String>::new(),
                "{pattern}"
            );
        }
        let gateway_base = format!("https://api.atlassian.com/ex/jira/{CLOUD_ID}/rest/api/3/");
        for pattern in [
            "https://api.atlassian.com/ex/confluence/**".to_string(),
            format!("https://api.atlassian.com/ex/*/{OTHER_CLOUD_ID}/**"),
            "https://api.atlassian.com:8443/ex/jira/**".to_string(),
            "http://api.atlassian.com/ex/jira/**".to_string(),
            "https://api.atlassian.com/admin/**".to_string(),
            format!("https://api.atlassian.com/ex/jira/{CLOUD_ID}/rest/api/2/**"),
            format!("https://api.atlassian.com/ex/jira/{CLOUD_ID}"),
            "https://example.atlassian.net/**".to_string(),
        ] {
            assert_eq!(
                check(oauth, pattern.clone()),
                [format!(
                    "credentials.per_user.jira (OAuth) takes the Atlassian gateway route, but providers.jira.allowed_upstream_hosts does not cover {gateway_base}"
                )],
                "{pattern}"
            );
        }
        for pattern in [
            "https://example.atlassian.net/rest/api/3/issue/**",
            "https://example.atlassian.net/*/api/3/**",
            "https://example.atlassian.net/**",
        ] {
            assert_eq!(
                check(classic, pattern.to_string()),
                Vec::<String>::new(),
                "{pattern}"
            );
        }
        for pattern in [
            "https://example.atlassian.net/wiki/**",
            "https://other.atlassian.net/rest/api/3/**",
            "https://example.atlassian.net:8443/rest/api/3/**",
            "https://api.atlassian.com/ex/jira/**",
        ] {
            assert_eq!(
                check(classic, pattern.to_string()),
                [
                    "credentials.service.jira (type basic_api_token) takes the site route, but providers.jira.allowed_upstream_hosts does not cover https://example.atlassian.net/rest/api/3/"
                ],
                "{pattern}"
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

        // A cloud ID alone builds the gateway route; the allowlist is
        // enforced on each request. Without one, gateway credentials have
        // no route.
        let site_only = hosts(false);
        let host = TestHost::default();
        let routes =
            AtlassianRoutes::new(PRODUCT, &site(Some(CLOUD_ID), &site_only), &host).unwrap();
        assert!(
            routes
                .for_credential(&AtlassianCredential::from_static(bearer_credential(
                    "token"
                )))
                .is_ok()
        );
        assert_eq!(host.built_clients().len(), 4);
        let routes =
            AtlassianRoutes::new(PRODUCT, &site(None, &allowed), &TestHost::default()).unwrap();
        assert_eq!(
            routes
                .for_credential(&AtlassianCredential::from_static(bearer_credential(
                    "token"
                )))
                .err()
                .unwrap()
                .to_string(),
            "Confluence OAuth connections, scoped API tokens and bearer tokens take the Atlassian gateway route, which requires providers.confluence.cloud_id"
        );
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

    /// A cloud ID that is not a UUID fails the build whatever the
    /// allowlist says, as does an invalid tenant host.
    #[test]
    fn invalid_sites_fail_to_build() {
        for allowed in [hosts(true), hosts(false)] {
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
        }
        let allowed = hosts(true);
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

    /// The fingerprint follows the tenant host and the canonical cloud ID,
    /// not the allowlist, which no longer selects a route. It differs from
    /// the earlier format, which also bound whether `api.atlassian.com` was
    /// allowed, so list and search continuations issued before are refused
    /// once.
    #[test]
    fn route_fingerprints_follow_the_tenant_and_cloud_id() {
        /// The fingerprint list and search continuations bound before.
        fn earlier(site: &AtlassianSite<'_>, gateway_allowed: bool) -> [u8; 32] {
            let mut digest = Sha256::new();
            digest.update(b"agent-access/atlassian-route/v1\0");
            let cloud_id = site.cloud_id.and_then(canonical_cloud_id);
            for field in [Some(site.tenant_host), cloud_id.as_deref()] {
                match field {
                    Some(value) => {
                        digest.update([1]);
                        digest.update((value.len() as u64).to_be_bytes());
                        digest.update(value.as_bytes());
                    }
                    None => digest.update([0]),
                }
            }
            digest.update([u8::from(gateway_allowed)]);
            digest.finalize().into()
        }

        let gateway = hosts(true);
        let tenant_only = hosts(false);
        let base = site(Some(CLOUD_ID), &gateway).route_fingerprint();
        assert_eq!(base, site(Some(CLOUD_ID), &tenant_only).route_fingerprint());
        let simple = CLOUD_ID.replace('-', "");
        assert_eq!(base, site(Some(&simple), &gateway).route_fingerprint());
        let mut other_tenant = site(Some(CLOUD_ID), &gateway);
        other_tenant.tenant_host = "other.atlassian.net";
        for changed in [
            other_tenant,
            site(None, &gateway),
            site(Some(OTHER_CLOUD_ID), &gateway),
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

        for configured in [
            site(Some(CLOUD_ID), &gateway),
            site(Some(CLOUD_ID), &tenant_only),
            site(None, &tenant_only),
        ] {
            for gateway_allowed in [false, true] {
                assert_ne!(
                    configured.route_fingerprint(),
                    earlier(&configured, gateway_allowed)
                );
            }
        }
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

        /// A stored or configured token, lent as `profile` when set.
        fn stored(credential: ExecutionCredential, profile: Option<&str>) -> ExecutionAccess {
            ExecutionAccess::Static(match profile {
                Some(profile) => credential_with_profile(credential, profile),
                None => credential,
            })
        }

        /// Static tokens bind their kind, and the gateway's site whenever
        /// their token type takes the gateway route. A classic token binds
        /// as an unprofiled Basic token did and a service-account token as
        /// an unprofiled bearer token did; a scoped API token binds Basic
        /// with the gateway's site, so a classic and a scoped token never
        /// open each other's continuations.
        #[test]
        fn static_tokens_bind_their_kind_and_only_gateway_routes_bind_the_cloud_id() {
            let signer = ContinuationSigner::new(None);
            let alice = request("alice");
            let basic = || basic_credential("alice@example.com", "token");
            let classic = stored(basic(), Some(ATLASSIAN_API_TOKEN_PROFILE));
            let scoped = stored(basic(), Some(ATLASSIAN_SCOPED_API_TOKEN_PROFILE));
            let unprofiled_bearer = stored(bearer_credential("token"), None);
            let bearer = stored(
                bearer_credential("token"),
                Some(ATLASSIAN_BEARER_TOKEN_PROFILE),
            );
            let token = seal(&signer, &alice, &stored(basic(), None), Some(CLOUD_ID));
            // The site route does not depend on the gateway's site, and the
            // stored token is not bound: the principal owns the token.
            for (cloud_id, access) in [
                (Some(CLOUD_ID), classic.clone()),
                (Some(OTHER_CLOUD_ID), classic.clone()),
                (None, classic.clone()),
                (Some("not-a-uuid"), classic.clone()),
                (
                    Some(CLOUD_ID),
                    stored(
                        basic_credential("alice@example.com", "rotated"),
                        Some(ATLASSIAN_API_TOKEN_PROFILE),
                    ),
                ),
            ] {
                assert_eq!(
                    open(&signer, &alice, &access, cloud_id, &token).unwrap(),
                    b"next"
                );
            }
            for (request, access) in [
                (alice.clone(), scoped.clone()),
                (alice.clone(), bearer.clone()),
                (alice.clone(), delegated("alice-oauth-1", "v1")),
                (request("bob"), classic.clone()),
            ] {
                assert_eq!(
                    open(&signer, &request, &access, Some(CLOUD_ID), &token),
                    Err(ContinuationError::Invalid)
                );
            }
            // Gateway tokens bind the gateway's site; a service-account
            // token binds as an unprofiled bearer token.
            for minted in [&scoped, &bearer, &unprofiled_bearer] {
                let token = seal(&signer, &alice, minted, Some(CLOUD_ID));
                assert_eq!(
                    open(&signer, &alice, minted, Some(CLOUD_ID), &token).unwrap(),
                    b"next"
                );
                for (access, cloud_id) in [
                    (minted.clone(), Some(OTHER_CLOUD_ID)),
                    (classic.clone(), Some(CLOUD_ID)),
                    (delegated("alice-oauth-1", "v1"), Some(CLOUD_ID)),
                ] {
                    assert_eq!(
                        open(&signer, &alice, &access, cloud_id, &token),
                        Err(ContinuationError::Invalid)
                    );
                }
            }
            let token = seal(&signer, &alice, &bearer, Some(CLOUD_ID));
            assert_eq!(
                open(&signer, &alice, &unprofiled_bearer, Some(CLOUD_ID), &token).unwrap(),
                b"next"
            );
            assert_eq!(
                open(&signer, &alice, &scoped, Some(CLOUD_ID), &token),
                Err(ContinuationError::Invalid)
            );
            let token = seal(&signer, &alice, &scoped, Some(CLOUD_ID));
            for other in [&bearer, &unprofiled_bearer, &stored(basic(), None)] {
                assert_eq!(
                    open(&signer, &alice, other, Some(CLOUD_ID), &token),
                    Err(ContinuationError::Invalid)
                );
            }
        }

        /// Binding uses the route classifier: material with no route, and a
        /// gateway route without a valid cloud ID, fail closed instead of
        /// binding a guessed route.
        #[test]
        fn access_without_a_route_fails_closed() {
            let bind = |access: &ExecutionAccess, cloud_id: Option<&str>| {
                bind_atlassian_access(
                    PAGES.bind(request("alice").context(), "route"),
                    access,
                    cloud_id,
                )
                .map(|_| ())
                .map_err(|error| (error.reason_code(), error.message))
            };
            let refused = Err((
                ReasonCode::CredentialNotProvisioned.into(),
                "selected credential material is unavailable".to_string(),
            ));
            let basic = || basic_credential("alice@example.com", "token");
            for access in [
                stored(basic(), Some("gitlab-access-token")),
                stored(basic(), Some(ATLASSIAN_BEARER_TOKEN_PROFILE)),
                stored(
                    bearer_credential("token"),
                    Some(ATLASSIAN_API_TOKEN_PROFILE),
                ),
                stored(
                    bearer_credential("token"),
                    Some(ATLASSIAN_SCOPED_API_TOKEN_PROFILE),
                ),
            ] {
                assert_eq!(bind(&access, Some(CLOUD_ID)), refused, "{access:?}");
            }
            for access in [
                stored(basic(), Some(ATLASSIAN_SCOPED_API_TOKEN_PROFILE)),
                stored(bearer_credential("token"), None),
                delegated("alice-oauth-1", "v1"),
            ] {
                assert_eq!(bind(&access, Some(CLOUD_ID)), Ok(()));
                for cloud_id in [None, Some("not-a-uuid")] {
                    assert_eq!(bind(&access, cloud_id), refused, "{access:?} {cloud_id:?}");
                }
            }
            assert_eq!(
                bind(&stored(basic(), Some(ATLASSIAN_API_TOKEN_PROFILE)), None),
                Ok(())
            );
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
                stored(
                    basic_credential("alice@example.com", "token"),
                    Some(ATLASSIAN_SCOPED_API_TOKEN_PROFILE),
                ),
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
                (
                    stored(
                        basic_credential("alice@example.com", "token"),
                        Some(ATLASSIAN_SCOPED_API_TOKEN_PROFILE),
                    ),
                    stored(
                        basic_credential("alice@example.com", "rotated"),
                        Some(ATLASSIAN_SCOPED_API_TOKEN_PROFILE),
                    ),
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
