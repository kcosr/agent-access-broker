//! The upstream authority a service's credentials act on.
//!
//! A credential connection lets several services consume one per-principal
//! credential, so the host checks offline that they act on the same
//! upstream: a backend declares its service's authority in its descriptor
//! (see [`crate::ServiceDescriptor::with_upstream_authority`]), and an OAuth
//! dialect checks a consumer's authority against a registration's resource
//! authority (see [`crate::OAuthDialect::check_consumer_authority`]).
use url::Url;

/// The upstream instance a service's credentials act on: a normalized
/// `http` or `https` origin and instance path, an optional tenant identity,
/// and an optional tenant gateway origin through which the same tenant is
/// also reachable.
///
/// Two services act on the same instance when they agree on all four: the
/// same origin and instance path, and the same tenant and tenant gateway,
/// or neither declares one. A provider declares its tenant in one canonical
/// spelling, so equivalent spellings compare equal. A dialect decides what
/// an OAuth grant additionally requires of a consumer.
///
/// ```
/// # use agent_access_provider::UpstreamAuthority;
/// let rest = UpstreamAuthority::from_base_url("https://GitLab.example.com:443/").unwrap();
/// let git = UpstreamAuthority::from_base_url("https://gitlab.example.com").unwrap();
/// assert_eq!(rest.origin(), "https://gitlab.example.com");
/// assert_eq!(rest.instance_path(), "");
/// assert!(rest.same_instance(&git));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamAuthority {
    origin: String,
    instance_path: String,
    tenant: Option<String>,
    tenant_gateway: Option<String>,
}

impl UpstreamAuthority {
    /// The authority of an absolute `http` or `https` base URL without
    /// credentials, query or fragment: its origin, with the scheme and host
    /// lowercased and a default port omitted, and its path without a
    /// trailing slash (empty at the root).
    pub fn from_base_url(base_url: &str) -> Result<Self, String> {
        let (origin, instance_path) = normalized(base_url)?;
        Ok(Self {
            origin,
            instance_path,
            tenant: None,
            tenant_gateway: None,
        })
    }

    /// Records the tenant identity the service is configured for, such as
    /// an Atlassian cloud ID, in the one canonical spelling the provider
    /// uses for it, since [`Self::same_instance`] compares it exactly.
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    /// Records the origin of a gateway through which the service also
    /// reaches its tenant, such as `https://api.atlassian.com`. Only the
    /// gateway's origin is kept.
    pub fn with_tenant_gateway(mut self, gateway_base_url: &str) -> Result<Self, String> {
        self.tenant_gateway = Some(normalized(gateway_base_url)?.0);
        Ok(self)
    }

    /// `scheme://host[:port]`, normalized.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The instance path below the origin, without a trailing slash; empty
    /// at the root.
    pub fn instance_path(&self) -> &str {
        &self.instance_path
    }

    pub fn tenant(&self) -> Option<&str> {
        self.tenant.as_deref()
    }

    /// The tenant gateway's normalized origin.
    pub fn tenant_gateway(&self) -> Option<&str> {
        self.tenant_gateway.as_deref()
    }

    /// Whether both act on the same upstream instance: the same origin and
    /// instance path, and the same tenant and tenant gateway. A tenant or
    /// gateway that only one declares, or that both declare differently,
    /// names another instance, so one credential never reaches two tenants
    /// through a shared connection.
    pub fn same_instance(&self, other: &Self) -> bool {
        self.origin == other.origin
            && self.instance_path == other.instance_path
            && self.tenant == other.tenant
            && self.tenant_gateway == other.tenant_gateway
    }
}

impl std::fmt::Display for UpstreamAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}{}", self.origin, self.instance_path)?;
        match (&self.tenant, &self.tenant_gateway) {
            (Some(tenant), Some(gateway)) => {
                write!(formatter, " (tenant {tenant}, gateway {gateway})")
            }
            (Some(tenant), None) => write!(formatter, " (tenant {tenant})"),
            (None, Some(gateway)) => write!(formatter, " (gateway {gateway})"),
            (None, None) => Ok(()),
        }
    }
}

fn normalized(base_url: &str) -> Result<(String, String), String> {
    let url = Url::parse(base_url).map_err(|_| "must be an absolute URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("must use http or https".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain credentials".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("must not contain a query or fragment".into());
    }
    let Some(host) = url.host_str() else {
        return Err("must name a host".into());
    };
    let origin = match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    };
    Ok((origin, url.path().trim_end_matches('/').to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_urls_normalize_to_an_origin_and_instance_path() {
        let authority =
            UpstreamAuthority::from_base_url("HTTPS://Git.Example.COM:443/Group/").unwrap();
        assert_eq!(authority.origin(), "https://git.example.com");
        assert_eq!(authority.instance_path(), "/Group");
        let ported = UpstreamAuthority::from_base_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(ported.origin(), "http://127.0.0.1:8080");
        assert_eq!(ported.instance_path(), "");
        for invalid in [
            "gitlab.example.com",
            "ftp://gitlab.example.com",
            "https://user:pass@gitlab.example.com",
            "https://gitlab.example.com/?a=b",
            "https://gitlab.example.com/#x",
        ] {
            assert!(
                UpstreamAuthority::from_base_url(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    /// Instances compare origin, instance path, tenant and tenant gateway;
    /// one declared by only one side differs too.
    #[test]
    fn instances_compare_origin_path_tenant_and_gateway() {
        let site = UpstreamAuthority::from_base_url("https://example.atlassian.net").unwrap();
        let routed = site
            .clone()
            .with_tenant("cloud-one")
            .with_tenant_gateway("https://api.atlassian.com/ex/jira/cloud-one")
            .unwrap();
        assert_eq!(routed.tenant(), Some("cloud-one"));
        assert_eq!(routed.tenant_gateway(), Some("https://api.atlassian.com"));
        let same = UpstreamAuthority::from_base_url("https://EXAMPLE.atlassian.net/")
            .unwrap()
            .with_tenant("cloud-one")
            .with_tenant_gateway("https://api.atlassian.com/ex/confluence/cloud-one")
            .unwrap();
        assert!(routed.same_instance(&same) && same.same_instance(&routed));
        assert!(site.same_instance(&site.clone()));
        let other_tenant = same.clone().with_tenant("cloud-two");
        let tenant_only = site.clone().with_tenant("cloud-one");
        let other_gateway = site
            .clone()
            .with_tenant("cloud-one")
            .with_tenant_gateway("https://gateway.example.com")
            .unwrap();
        let other_path =
            UpstreamAuthority::from_base_url("https://example.atlassian.net/wiki").unwrap();
        for (left, right) in [
            (&site, &routed),
            (&routed, &other_tenant),
            (&routed, &tenant_only),
            (&tenant_only, &site),
            (&routed, &other_gateway),
            (&site, &other_path),
        ] {
            assert!(!left.same_instance(right), "{left} and {right}");
            assert!(!right.same_instance(left), "{right} and {left}");
        }
        assert_eq!(
            routed.to_string(),
            "https://example.atlassian.net (tenant cloud-one, gateway https://api.atlassian.com)"
        );
        assert_eq!(
            tenant_only.to_string(),
            "https://example.atlassian.net (tenant cloud-one)"
        );
        assert_eq!(
            site.clone()
                .with_tenant_gateway("https://api.atlassian.com")
                .unwrap()
                .to_string(),
            "https://example.atlassian.net (gateway https://api.atlassian.com)"
        );
        assert_eq!(site.to_string(), "https://example.atlassian.net");
    }
}
