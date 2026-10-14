//! Helpers shared by the Jira and Confluence backends: configuration
//! validation, credential authorization and the tenant/gateway client routes.
use agent_access_provider::host::UpstreamClientFactory;
use agent_access_provider::{
    ClientProfile, EgressDeclaration, EgressProxyConfig, ExecutionCredential, ProviderBuildError,
    ReasonCode, ServiceCredentialKinds, StaticCredentialKind, UpstreamAuthorization,
    UpstreamClient, UpstreamClientSpec,
};
use sha2::{Digest, Sha256};
use std::fmt;
use url::Url;

pub fn validate_atlassian_gateway_credential(
    service: &str,
    patterns: &[String],
    cloud_id: Option<&str>,
    credentials: ServiceCredentialKinds<'_>,
    errors: &mut Vec<String>,
) {
    let uses_gateway = uses_atlassian_gateway_host(patterns);
    let execution_credentials = [
        ("credentials.service", credentials.service),
        ("credentials.per_user", credentials.per_user),
    ];
    let mut has_bearer_execution_credential = false;

    for (mode, credential) in execution_credentials {
        if let Some(kind) = credential {
            if kind == "bearer_token" {
                has_bearer_execution_credential = true;
            } else if uses_gateway {
                errors.push(format!(
                    "providers.{service}.allowed_upstream_hosts includes api.atlassian.com but {mode}.{service}.type is not bearer_token"
                ));
            }
        }
    }

    if has_bearer_execution_credential && !uses_gateway {
        errors.push(format!(
            "{mode}.{service}.type bearer_token requires providers.{service}.allowed_upstream_hosts to include api.atlassian.com",
            mode = if credentials.service == Some("bearer_token") {
                "credentials.service"
            } else {
                "credentials.per_user"
            }
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

    if !has_bearer_execution_credential {
        errors.push(format!(
            "providers.{service}.allowed_upstream_hosts includes api.atlassian.com but no bearer_token execution credential is configured"
        ));
    }
}

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

/// How an Atlassian execution credential authenticates a request: HTTP
/// Basic for a tenant API token, a bearer token through the gateway. The SDK
/// presents the credential; this helper never reads its material.
#[derive(Debug, Clone)]
pub struct AtlassianAuthorization(UpstreamAuthorization);

impl AtlassianAuthorization {
    /// How `credential` authenticates, or `None` for a credential kind
    /// Atlassian providers do not support, which the caller must reject.
    pub fn new(credential: &ExecutionCredential) -> Option<Self> {
        match credential.kind() {
            StaticCredentialKind::BasicApiToken | StaticCredentialKind::BearerToken => {
                Some(Self(credential.authorization()))
            }
            _ => None,
        }
    }

    pub fn apply(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        self.0.apply(builder)
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
    pub cloud_id: Option<&'a str>,
    pub egress_proxy: Option<&'a EgressProxyConfig>,
    pub allowed_upstream_hosts: &'a [String],
}

impl AtlassianSite<'_> {
    /// Whether bearer credentials route through the Atlassian gateway: a
    /// cloud ID is configured and `api.atlassian.com` is allowed.
    pub fn uses_gateway(&self) -> bool {
        self.cloud_id.is_some() && uses_atlassian_gateway_host(self.allowed_upstream_hosts)
    }

    /// A digest of the configuration an upstream cursor's route depends on:
    /// the tenant host, the gateway cloud ID and whether `api.atlassian.com`
    /// is allowed. Continuations relaying a cursor bind it, beside the
    /// credential kind that selects the route.
    pub fn route_fingerprint(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"agent-access/atlassian-route/v1\0");
        for field in [Some(self.tenant_host), self.cloud_id] {
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
    pub client: UpstreamClient,
    pub stream_client: UpstreamClient,
}

impl AtlassianClients {
    /// Clients for `api_base` with the site's egress declaration and
    /// allowlist, labelled `providers.<provider>.egress_proxy`.
    pub fn new(
        product: AtlassianProduct,
        site: &AtlassianSite<'_>,
        api_base: Url,
        factory: &dyn UpstreamClientFactory,
    ) -> Result<Self, ProviderBuildError> {
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
        })
    }
}

/// An Atlassian provider's routes: Basic API-token credentials use the
/// tenant host, bearer credentials the Atlassian gateway when the site
/// enables it.
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
                    "https://api.atlassian.com/ex/{provider}/{cloud_id}/{}",
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

    /// The clients for `credential`'s route.
    pub fn for_credential(
        &self,
        credential: &ExecutionCredential,
    ) -> Result<&AtlassianClients, AtlassianRouteUnavailable> {
        if credential.kind() == StaticCredentialKind::BearerToken {
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

/// A bearer credential with no gateway route configured.
#[derive(Debug, Clone, Copy)]
pub struct AtlassianRouteUnavailable {
    product: AtlassianProduct,
}

impl fmt::Display for AtlassianRouteUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let AtlassianProduct { provider, name, .. } = self.product;
        write!(
            formatter,
            "bearer {name} credentials require providers.{provider}.cloud_id and api.atlassian.com in allowed_upstream_hosts"
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
    fn credentials_route_to_the_tenant_or_the_gateway() {
        let host = TestHost::default();
        let allowed = hosts(true);
        let routes = AtlassianRoutes::new(PRODUCT, &site(Some(CLOUD_ID), &allowed), &host).unwrap();
        assert_eq!(
            routes
                .for_credential(&basic_credential("agent@example.com", "token"))
                .unwrap()
                .api_base
                .as_str(),
            "https://example.atlassian.net/wiki/rest/api/"
        );
        assert_eq!(
            routes
                .for_credential(&bearer_credential("token"))
                .unwrap()
                .api_base
                .as_str(),
            format!("https://api.atlassian.com/ex/confluence/{CLOUD_ID}/wiki/rest/api/")
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
                    .for_credential(&bearer_credential("token"))
                    .err()
                    .unwrap()
                    .to_string(),
                "bearer Confluence credentials require providers.confluence.cloud_id and api.atlassian.com in allowed_upstream_hosts"
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

    /// Basic credentials authorize tenant requests and bearer credentials
    /// gateway requests, with the bytes reqwest's own helpers produce.
    #[test]
    fn authorization_presents_basic_and_bearer_credentials_unchanged() {
        let request = || reqwest::Client::new().get("https://example.atlassian.net/wiki/rest/api/");
        for (credential, expected) in [
            (
                basic_credential("agent@example.com", "api-token"),
                request().basic_auth("agent@example.com", Some("api-token")),
            ),
            (
                bearer_credential("gateway-token"),
                request().bearer_auth("gateway-token"),
            ),
        ] {
            let authorization = AtlassianAuthorization::new(&credential).unwrap();
            let sent = authorization.apply(request()).build().unwrap();
            let expected = expected.build().unwrap();
            let header = &sent.headers()[reqwest::header::AUTHORIZATION];
            assert_eq!(header, &expected.headers()[reqwest::header::AUTHORIZATION]);
            assert!(header.is_sensitive());
            assert!(!format!("{authorization:?}").contains("token"));
        }
    }
}
