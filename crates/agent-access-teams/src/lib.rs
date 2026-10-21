//! Notifications to exact, managed Microsoft Teams Workflows destinations.
//! Signed endpoints arrive only through broker-admitted private attributes.
mod payload;
#[cfg(test)]
mod tests;

use agent_access_provider::*;
use async_trait::async_trait;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;
use url::Url;

const HOST_SUFFIX: &str = ".environment.api.powerplatform.com";
const MAX_BODY_BYTES: u64 = 24 * 1024;
const ACTION: &str = "notification.send";
const SERVICE: &str = "teams";

pub static TEAMS_DESTINATION_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("teams_notification_destination"),
    "Teams notification destination",
    "Teams notification destinations",
    "release-alerts",
    valid_destination,
    &TEAMS_DESTINATION_ATTRIBUTES,
);

static TEAMS_DESTINATION_ATTRIBUTES: [ResourceAttributeDescriptor; 1] =
    [ResourceAttributeDescriptor::required(
        "webhookUrl",
        "Webhook URL",
        "Signed Microsoft Teams Workflows URL using the Anyone trigger setting",
        valid_webhook_url,
    )];

fn valid_destination(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn supported_origin(url: &Url) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.host_str().is_some_and(|host| {
            host.strip_suffix(HOST_SUFFIX).is_some_and(|prefix| {
                host.len() <= 253
                    && prefix.split('.').all(|label| {
                        !label.is_empty()
                            && label.len() <= 63
                            && label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                            && !label.starts_with('-')
                            && !label.ends_with('-')
                    })
            })
        })
}

fn valid_webhook_url(value: &str) -> bool {
    // Reject normalization surprises before parsing; neither error nor Debug
    // output ever incorporates this secret value.
    !value
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
        && Url::parse(value).is_ok_and(|url| {
            supported_origin(&url)
                && url.path() != "/"
                && url
                    .query_pairs()
                    .any(|(name, value)| name == "sig" && !value.is_empty())
        })
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamsConfig {
    pub allowed_upstream_hosts: Vec<String>,
    #[serde(default)]
    pub egress_proxy: Option<EgressProxyConfig>,
}

impl std::fmt::Debug for TeamsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TeamsConfig")
            .field("allowed_origin_count", &self.allowed_upstream_hosts.len())
            .finish_non_exhaustive()
    }
}

pub static TEAMS_BACKEND: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    "teams",
    parse_backend_config::<TeamsConfig>,
)
.with_resource_types(&[&TEAMS_DESTINATION_RESOURCE]);

impl TeamsConfig {
    fn origins(&self) -> Result<Vec<Url>, String> {
        if self.allowed_upstream_hosts.is_empty() {
            return Err("providers.teams.allowed_upstream_hosts must not be empty".into());
        }
        self.allowed_upstream_hosts.iter().map(|pattern| {
            let mut url = Url::parse(pattern).map_err(|_| "providers.teams.allowed_upstream_hosts requires exact HTTPS Power Platform origins followed by /**")?;
            if !supported_origin(&url) || url.path() != "/**" || url.query().is_some() {
                return Err("providers.teams.allowed_upstream_hosts requires exact HTTPS Power Platform origins followed by /**".into());
            }
            url.set_path("/");
            Ok(url)
        }).collect()
    }
}

impl BackendConfig for TeamsConfig {
    fn kind(&self) -> &'static str {
        "teams"
    }
    fn validate(&self, context: &ValidationContext<'_>, errors: &mut Vec<String>) {
        if context.policy_authority != "managed" {
            errors.push("providers.teams requires policy.authority = managed".into());
        }
        let credentials = context.credentials;
        if credentials.service.is_some()
            || !credentials.per_user_profiles.is_empty()
            || credentials.per_user_delegated
            || credentials.per_user_secret_store
        {
            errors.push(
                "providers.teams does not accept service or per-user execution credentials".into(),
            );
        }
        if let Err(error) = self.origins() {
            errors.push(error);
        }
        validate_egress_proxy_config(
            "providers.teams.egress_proxy",
            self.egress_proxy.as_ref(),
            errors,
        );
    }
    fn validate_resource_attributes(
        &self,
        resource_type: &ResourceType,
        attributes: &ResourceAttributes,
    ) -> Result<(), String> {
        if resource_type != TEAMS_DESTINATION_RESOURCE.id() {
            return Err("unsupported Teams resource type".into());
        }
        if let Some(value) = attributes.get("webhookUrl") {
            let url = Url::parse(value).map_err(|_| "resource attribute webhookUrl is invalid")?;
            if !valid_webhook_url(value)
                || !url_allowed_by_patterns(&url, &self.allowed_upstream_hosts)
            {
                return Err(
                    "resource attribute webhookUrl must use an allowed Teams Workflows origin"
                        .into(),
                );
            }
        }
        Ok(())
    }
    fn descriptor(&self) -> ServiceDescriptor {
        descriptor()
    }
    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        self.egress_proxy
            .as_ref()
            .map(|p| vec![("providers.teams.egress_proxy".into(), p)])
            .unwrap_or_default()
    }
    fn build(&self, host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        let origins = self.origins().map_err(ProviderBuildError::invalid)?;
        let mut clients = BTreeMap::new();
        for base in origins {
            let client = UpstreamClient::build(
                UpstreamClientSpec::new(
                    "providers.teams",
                    "teams",
                    &base,
                    EgressDeclaration::Ordinary(self.egress_proxy.as_ref()),
                    &self.allowed_upstream_hosts,
                    ClientProfile::SingleAttempt,
                ),
                host.clients(),
            )?;
            clients.insert(base.origin().ascii_serialization(), client);
        }
        Ok(Arc::new(TeamsProvider {
            transport: Arc::new(HttpTransport { clients }),
            allowed_upstream_hosts: self.allowed_upstream_hosts.clone(),
            max_bytes: host.limits().max_http_body_bytes.min(MAX_BODY_BYTES),
        }))
    }
}

pub fn descriptor() -> ServiceDescriptor {
    ServiceDescriptor::new("teams", "Microsoft Teams notifications").with_resource_scopes(BTreeMap::from([("destination".into(), ResourceScopeCapabilities::new(TEAMS_DESTINATION_RESOURCE.id().clone(), vec!["exact".into(), "all".into()]))])).with_actions(vec![ActionDescriptor::new(ACTION, "Submit a notification to a configured Teams Workflow; acceptance does not confirm delivery", payload::schema())
            .scope("destination").credential_modes(["service"]).resource_attributes()]).with_credentials(CredentialDescriptor::without_execution_credential())
}

/// What the Workflow endpoint answered: its status and, for HTTP 429, the
/// bounded wait its `Retry-After` named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransportReceipt {
    status: u16,
    retry_after: Option<UpstreamRetryAfter>,
}

impl TransportReceipt {
    #[cfg(any(test, feature = "test-support"))]
    fn status(status: u16) -> Self {
        Self {
            status,
            retry_after: None,
        }
    }
}

#[async_trait]
trait NotificationTransport: Send + Sync {
    async fn send(&self, endpoint: Url, body: Vec<u8>) -> Result<TransportReceipt, ProviderError>;
}

struct HttpTransport {
    clients: BTreeMap<String, UpstreamClient>,
}

#[async_trait]
impl NotificationTransport for HttpTransport {
    async fn send(&self, endpoint: Url, body: Vec<u8>) -> Result<TransportReceipt, ProviderError> {
        let client = self
            .clients
            .get(&endpoint.origin().ascii_serialization())
            .ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::UpstreamProtocolFailed,
                    "Teams destination origin is not configured",
                )
            })?;
        let request = client
            .request(Method::POST, endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        let mut response = client.send(request, UpstreamCall::new(ACTION)).await.map_err(|error| {
            // reqwest's error string can contain the entire signed URL.
            match error {
                // Nothing reached the Workflow, so repeating the send is safe.
                UpstreamError::NotSent { .. } | UpstreamError::NotAllowed => {
                    ProviderError::error(error.reason_code(), "Teams notification request was not sent")
                        .with_mutation_receipt(MutationReceipt::not_applied())
                }
                // A timeout, a transport failure and any failure the provider
                // does not classify may have reached the Workflow.
                _ => ProviderError::error(
                    error.reason_code(),
                    "Teams notification request failed; outcome may be unknown, inspect the workflow before retrying",
                )
                .with_mutation_receipt(MutationReceipt::unknown()),
            }
        })?;
        let status = response.status().as_u16();
        complete_upstream_trace(&mut response, status_reason(status).map(Into::into));
        // Neither success nor error response bodies, headers or Location values
        // belong in broker results; only a throttling wait is read, as a
        // bounded number. Do not read an unbounded upstream body.
        let retry_after = (status == 429)
            .then(|| UpstreamRetryAfter::from_headers(response.headers()))
            .flatten();
        Ok(TransportReceipt {
            status,
            retry_after,
        })
    }
}

fn status_reason(status: u16) -> Option<ReasonCode> {
    match status {
        200..=299 => None,
        300..=399 => Some(ReasonCode::UpstreamProtocolFailed),
        401 => Some(ReasonCode::UpstreamUnauthorized),
        403 => Some(ReasonCode::UpstreamForbidden),
        429 => Some(ReasonCode::UpstreamRateLimited),
        _ => Some(ReasonCode::UpstreamFailed),
    }
}

struct TeamsProvider {
    transport: Arc<dyn NotificationTransport>,
    allowed_upstream_hosts: Vec<String>,
    max_bytes: u64,
}

impl TeamsProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if action != ACTION {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "unsupported Teams action",
            ));
        }
        let (destination, _) = payload::prepare(inputs, self.max_bytes)?;
        Ok(BTreeMap::from([("destination".into(), vec![destination])]))
    }
}

#[async_trait]
impl Provider for TeamsProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }
    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.local_scopes(request.action(), request.inputs())?;
        let (destination, body) = payload::prepare(request.inputs(), self.max_bytes)?;
        if request.service() != "teams"
            || request.credential_mode() != CredentialMode::Service
            || !request.execution().is_none()
            || request
                .authority()
                .resources()
                .and_then(|scopes| scopes.get("destination"))
                != Some(&vec![destination.clone()])
        {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "invalid Teams invocation authority",
            ));
        }
        let value = request
            .resource_attributes()
            .get("webhookUrl")
            .ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::WebhookDestinationDenied,
                    "Teams destination is not configured",
                )
            })?;
        let endpoint = Url::parse(value).map_err(|_| {
            ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "Teams destination is invalid",
            )
        })?;
        if !valid_webhook_url(value)
            || !url_allowed_by_patterns(&endpoint, &self.allowed_upstream_hosts)
        {
            return Err(ProviderError::deny(
                ReasonCode::UpstreamProtocolFailed,
                "Teams destination is outside allowed origins",
            ));
        }
        let audit = json!({"destination":destination,"upstreamOrigin":endpoint.origin().ascii_serialization()});
        let started = Instant::now();
        let receipt = self.transport.send(endpoint, body).await.map_err(|error| {
            error
                .with_upstream(None, Some(started.elapsed().as_millis() as u64))
                .with_audit(audit.clone())
        })?;
        let status = receipt.status;
        let elapsed = started.elapsed().as_millis() as u64;
        if let Some(reason) = status_reason(status) {
            let mut error = if reason == ReasonCode::UpstreamRateLimited {
                upstream_rate_limited(SERVICE, receipt.retry_after)
            } else {
                ProviderError::error(
                    reason,
                    "Teams Workflow rejected the notification; request was not retried",
                )
            };
            // The Broker never follows a redirect, and a proxy can answer 5xx
            // after the Workflow accepted the request.
            if (300..=399).contains(&status) || (500..=599).contains(&status) {
                error = error.with_mutation_receipt(MutationReceipt::unknown());
            }
            return Err(error
                .with_upstream(Some(status), Some(elapsed))
                .with_audit(audit));
        }
        Ok(
            ProviderResult::new(json!({"destination":destination,"accepted":true}))
                .with_audit(audit)
                .with_upstream(Some(status), Some(elapsed))
                .with_object_ids(json!({"destination":destination})),
        )
    }
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use super::*;
    pub type Handler = Arc<dyn Fn(&str, &Value) -> u16 + Send + Sync>;
    struct StubTransport(Handler);
    #[async_trait]
    impl NotificationTransport for StubTransport {
        async fn send(
            &self,
            endpoint: Url,
            body: Vec<u8>,
        ) -> Result<TransportReceipt, ProviderError> {
            Ok(TransportReceipt::status((self.0)(
                endpoint.as_str(),
                &serde_json::from_slice(&body).expect("validated JSON"),
            )))
        }
    }
    pub fn provider(origin: &str, handler: Handler) -> ServiceProvider {
        ServiceProvider::new(
            descriptor(),
            Arc::new(TeamsProvider {
                transport: Arc::new(StubTransport(handler)),
                allowed_upstream_hosts: vec![format!("{}/**", origin.trim_end_matches('/'))],
                max_bytes: MAX_BODY_BYTES,
            }),
        )
    }
}
