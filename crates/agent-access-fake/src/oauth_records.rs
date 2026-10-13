//! The development `oauth_stub` records backend: typed resources and
//! delegated OAuth reads against the independent OAuth test server.
use agent_access_provider::host::UpstreamClientFactory;
use agent_access_provider::{
    ActionDescriptor, BackendConfig, BackendRegistration, BuildContext, ClientProfile,
    CredentialDescriptor, DelegatedAccess, EgressDeclaration, EgressProxyConfig, Provider,
    ProviderBuildError, ProviderError, ProviderInvocation, ProviderLimits, ProviderResult,
    ReasonCode, ResourceScopeCapabilities, ResourceScopes, ResourceType, ResourceTypeDescriptor,
    ScopeRequest, ScopeResolution, ServiceDescriptor, ServiceSurface, UpstreamCall, UpstreamClient,
    UpstreamClientSpec, ValidationContext, complete_upstream_trace, is_literal_loopback,
    parse_backend_config, take_upstream_trace,
};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;
use url::Url;

/// The development OAuth test-records backend. Its per-user credential is
/// the caller's delegated OAuth connection, configured separately under
/// `[credentials.per_user.oauth_stub]` and `[oauth.registrations]`.
pub static OAUTH_STUB_BACKEND: BackendRegistration = BackendRegistration {
    kind: "oauth_stub",
    resource_types: &[&OAUTH_COLLECTION_RESOURCE],
    parse: parse_backend_config::<OAuthStubProviderConfig>,
    development_only: true,
};

/// Collections served by the development OAuth test provider.
pub static OAUTH_COLLECTION_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor {
    action_inputs: None,
    attributes: &[],
    id: ResourceType::from_static("oauth_collection"),
    label: "OAuth test collection",
    plural_label: "OAuth test collections",
    example: "alpha",
    canonical: is_oauth_collection,
    namespace: None,
};

fn is_oauth_collection(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// `[providers.oauth_stub]`: where the test server's records API listens.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthStubProviderConfig {
    /// The records API origin. It must be a literal-IP loopback URL, which
    /// the backend reaches directly rather than through an egress proxy.
    pub base_url: String,
}

impl OAuthStubProviderConfig {
    /// The records API origin, with a trailing slash so routes join below it.
    fn base(&self) -> Result<Url, String> {
        let base = Url::parse(&self.base_url)
            .map_err(|_| "providers.oauth_stub.base_url must be a URL".to_string())?;
        if !matches!(base.scheme(), "http" | "https")
            || !is_literal_loopback(&base)
            || !base.username().is_empty()
            || base.password().is_some()
        {
            return Err(
                "providers.oauth_stub.base_url must be an http or https literal-IP loopback URL"
                    .into(),
            );
        }
        if base.path() != "/" || base.query().is_some() || base.fragment().is_some() {
            return Err(
                "providers.oauth_stub.base_url must be an origin with no path, query or fragment"
                    .into(),
            );
        }
        Ok(base)
    }
}

impl BackendConfig for OAuthStubProviderConfig {
    fn kind(&self) -> &'static str {
        "oauth_stub"
    }

    fn validate(&self, _context: &ValidationContext<'_>, errors: &mut Vec<String>) {
        if let Err(error) = self.base() {
            errors.push(error);
        }
    }

    fn descriptor(&self) -> ServiceDescriptor {
        oauth_stub_descriptor()
    }

    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        Vec::new()
    }

    fn build(&self, host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        let base = self.base().map_err(ProviderBuildError::invalid)?;
        Ok(Arc::new(OAuthRecordsProvider::new(
            &base,
            host.clients(),
            host.limits(),
        )?))
    }
}

/// The OAuth test-records service. Its per-user credential is the caller's
/// delegated OAuth connection.
fn oauth_stub_descriptor() -> ServiceDescriptor {
    let collection = || json!({"type":"string","pattern":"^[a-z0-9_-]{1,64}$"});
    let schema = |required: Value, properties: Value| json!({"type":"object","required":required,"properties":properties,"additionalProperties":false});
    ServiceDescriptor {
        service: "oauth_stub".into(),
        display_name: "OAuth Test Records".into(),
        surface: ServiceSurface::Invoke,
        resource_scopes: BTreeMap::from([(
            "collection".into(),
            ResourceScopeCapabilities {
                resource_type: OAUTH_COLLECTION_RESOURCE.id.clone(),
                selectors: vec!["exact".into(), "all".into()],
            },
        )]),
        actions: vec![
            ActionDescriptor::new(
                "record.list",
                "List records in an authorized test collection",
                schema(json!(["collection"]), json!({"collection": collection()})),
            )
            .read_only()
            .scope("collection")
            .credential_modes(["per_user"]),
            ActionDescriptor::new(
                "record.view",
                "Read one record in an authorized test collection",
                schema(
                    json!(["collection", "id"]),
                    json!({
                        "collection": collection(),
                        "id": {"type":"string","pattern":"^[a-zA-Z0-9_-]{1,128}$"}
                    }),
                ),
            )
            .read_only()
            .scope("collection")
            .credential_modes(["per_user"]),
            ActionDescriptor::new(
                "account.view",
                "Read the connected test account identity",
                schema(json!([]), json!({})),
            )
            .read_only()
            .credential_modes(["per_user"]),
        ],
        credentials: CredentialDescriptor::default()
            .delegated("Lets agents read the test records your account can reach."),
        presentation_body_limit: None,
    }
}

/// The records API at the configured base URL. The runtime lends each
/// invocation the caller's delegated OAuth access; the provider only
/// presents it.
struct OAuthRecordsProvider {
    client: UpstreamClient,
    max_bytes: u64,
}

impl OAuthRecordsProvider {
    fn new(
        base: &Url,
        clients: &dyn UpstreamClientFactory,
        limits: &ProviderLimits,
    ) -> Result<Self, ProviderBuildError> {
        // Like an OAuth authorization server, the literal-IP loopback records
        // API is reached directly. The host grants that route only because
        // this registration is development-only and the deployment enables
        // it; it rejects the client otherwise.
        let client = UpstreamClient::build(
            UpstreamClientSpec {
                label: "providers.oauth_stub",
                provider: "oauth_stub",
                base,
                egress: EgressDeclaration::LiteralLoopback,
                allowed_upstream_hosts: &[format!("{base}**")],
                profile: ClientProfile::Request,
                status_reasons: &[],
            },
            clients,
        )?;
        Ok(Self {
            client,
            max_bytes: limits.max_upstream_response_bytes.min(1024 * 1024),
        })
    }

    async fn send(
        &self,
        url: &Url,
        access: &DelegatedAccess,
        attempt: u32,
    ) -> Result<reqwest::Response, ProviderError> {
        let request = self
            .client
            .request(reqwest::Method::GET, url.clone())
            .bearer_auth(&access.token)
            .header("X-Stub-Target", &access.target)
            .header("X-Stub-Audience", &access.audience);
        self.client
            .send(
                request,
                UpstreamCall {
                    operation: "records.read",
                    attempt,
                },
            )
            .await
            .map_err(|error| {
                ProviderError::error(error.reason_code(), "OAuth records upstream unavailable")
            })
    }

    async fn read_body(&self, mut response: reqwest::Response) -> Result<Value, ProviderError> {
        if !response.status().is_success() {
            complete_upstream_trace(&mut response, Some(ReasonCode::UpstreamFailed));
            return Err(ProviderError::error(
                ReasonCode::UpstreamFailed,
                "OAuth records request failed",
            ));
        }
        let too_large = || {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "OAuth records response exceeds limit",
            )
        };
        if response
            .content_length()
            .is_some_and(|n| n > self.max_bytes)
        {
            complete_upstream_trace(&mut response, Some(ReasonCode::UpstreamProtocolFailed));
            return Err(too_large());
        }
        let trace = take_upstream_trace(&mut response);
        let finish = |reason: Option<ReasonCode>| {
            if let Some(trace) = trace {
                trace.complete(reason);
            }
        };
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if bytes.len() as u64 + chunk.len() as u64 > self.max_bytes {
                        finish(Some(ReasonCode::UpstreamProtocolFailed));
                        return Err(too_large());
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(_) => {
                    finish(Some(ReasonCode::UpstreamConnectionFailed));
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamConnectionFailed,
                        "OAuth records response unavailable",
                    ));
                }
            }
        }
        match serde_json::from_slice(&bytes) {
            Ok(value) => {
                finish(None);
                Ok(value)
            }
            Err(_) => {
                finish(Some(ReasonCode::UpstreamProtocolFailed));
                Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "OAuth records response is invalid",
                ))
            }
        }
    }
}

impl OAuthRecordsProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        let invalid = || {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "Invalid OAuth records action inputs",
            )
        };
        let object = inputs.as_object().ok_or_else(invalid)?;
        if action == "account.view" {
            return if object.is_empty() {
                Ok(BTreeMap::new())
            } else {
                Err(invalid())
            };
        }
        if !matches!(action, "record.list" | "record.view") {
            return Err(invalid());
        }
        let collection = object
            .get("collection")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        if !is_oauth_collection(collection) {
            return Err(invalid());
        }
        if object
            .keys()
            .any(|k| k != "collection" && (k != "id" || action != "record.view"))
        {
            return Err(invalid());
        }
        if action == "record.view" {
            let id = object
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(invalid());
            }
        }
        Ok(BTreeMap::from([(
            "collection".into(),
            vec![collection.into()],
        )]))
    }
}

#[async_trait]
impl Provider for OAuthRecordsProvider {
    // The runtime performs all action, resource and credential-mode admission
    // and lends the invocation its delegated credential only after policy.
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.local_scopes(&request.action, &request.inputs)?;
        let delegated = request.delegated_credential.as_ref().ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "OAuth records need the caller's delegated OAuth connection",
            )
        })?;
        let mut url = self
            .client
            .base()
            .join(match request.action.as_str() {
                "account.view" => "me",
                _ => "api/records",
            })
            .map_err(|_| ProviderError::error(ReasonCode::InputInvalid, "Invalid records route"))?;
        if request.action == "record.view" {
            url.path_segments_mut()
                .map_err(|_| {
                    ProviderError::error(ReasonCode::InputInvalid, "Invalid records route")
                })?
                .push(request.inputs["id"].as_str().unwrap());
        }
        if let Some(collection) = request.inputs.get("collection").and_then(Value::as_str) {
            url.query_pairs_mut().append_pair("collection", collection);
        }
        let started = Instant::now();
        let mut response = self.send(&url, &delegated.access(), 1).await?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            complete_upstream_trace(&mut response, Some(ReasonCode::CredentialInvalid));
            let access = delegated.recover_after_unauthorized().await?;
            response = self.send(&url, &access, 2).await?;
        }
        let status = response.status().as_u16();
        let result = self.read_body(response).await?;
        Ok(ProviderResult {
            result,
            stream: None,
            audit: Some(json!({"provider":"oauth_stub","operation":request.action})),
            upstream_status: Some(status),
            upstream_duration_ms: Some(started.elapsed().as_millis() as u64),
            object_ids: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(base_url: &str) -> OAuthStubProviderConfig {
        OAuthStubProviderConfig {
            base_url: base_url.into(),
        }
    }

    #[test]
    fn base_url_must_be_a_literal_loopback_origin() {
        for accepted in [
            "http://127.0.0.1:8099",
            "http://127.0.0.1:8099/",
            "https://127.0.0.2",
            "http://[::1]:8099",
        ] {
            let base = config(accepted).base().unwrap();
            assert_eq!(base.path(), "/", "{accepted}");
        }
        for rejected in [
            "http://localhost:8099",
            "https://localhost",
            "https://records.example.test",
            "http://10.0.0.1:8099",
            "ftp://127.0.0.1",
            "http://user:secret@127.0.0.1:8099",
            "http://127.0.0.1:8099/api",
            "http://127.0.0.1:8099/?tenant=one",
            "http://127.0.0.1:8099/#records",
            "127.0.0.1:8099",
        ] {
            assert!(config(rejected).base().is_err(), "{rejected}");
        }
    }

    #[test]
    fn the_records_client_requests_the_literal_loopback_route() {
        let host = agent_access_provider::test_support::TestHost::default();
        config("http://127.0.0.1:8099")
            .build(&host.context())
            .unwrap();
        let clients = host.built_clients();
        assert_eq!(clients.len(), 1);
        let client = &clients[0];
        assert_eq!(client.label, "providers.oauth_stub");
        assert_eq!(client.provider, "oauth_stub");
        assert_eq!(client.base.as_str(), "http://127.0.0.1:8099/");
        assert_eq!(client.profile, ClientProfile::Request);
        assert!(client.literal_loopback);
        // A table that skipped validation still never builds a client.
        assert!(
            config("http://localhost:8099")
                .build(&host.context())
                .is_err()
        );
        assert_eq!(host.built_clients().len(), 1);
    }

    #[test]
    fn the_table_is_strict_and_requires_base_url() {
        assert!(
            serde_json::from_value::<OAuthStubProviderConfig>(json!({
                "base_url": "http://127.0.0.1:8099",
                "allow_insecure_loopback": true
            }))
            .is_err()
        );
        assert!(serde_json::from_value::<OAuthStubProviderConfig>(json!({})).is_err());
    }

    #[test]
    fn the_registration_is_a_development_fixture_owning_oauth_collections() {
        assert!(OAUTH_STUB_BACKEND.development_only);
        assert_eq!(OAUTH_STUB_BACKEND.kind, "oauth_stub");
        assert_eq!(
            OAUTH_STUB_BACKEND
                .resource_types
                .iter()
                .map(|descriptor| descriptor.id.as_str())
                .collect::<Vec<_>>(),
            ["oauth_collection"]
        );
        assert!(is_oauth_collection("alpha_1-b"));
        assert!(!is_oauth_collection("Alpha"));
        assert!(!is_oauth_collection(&"a".repeat(65)));
        let descriptor = config("http://127.0.0.1:8099").descriptor();
        assert_eq!(
            descriptor
                .actions
                .iter()
                .map(|action| action.action.as_str())
                .collect::<Vec<_>>(),
            ["record.list", "record.view", "account.view"]
        );
    }
}
