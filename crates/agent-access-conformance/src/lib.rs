//! A test-only backend that uses every extension point of the backend
//! contract: a namespace-capable resource type with an action-input
//! projection and configured roots, typed configuration, a
//! managed credential profile, JSON, raw-download, and multipart-upload
//! actions, a presenter with an embedded body and a whole-result Markdown
//! renderer, and (when `endpoints` is enabled) a resource type whose entries
//! keep a private attribute that a single-attempt action consumes. Broker acceptance tests register it beside the linked
//! backends; that it needs nothing outside this crate and the registration
//! list is the point.
use agent_access_provider::presentation::{
    ActionPresentation, BodyPathSegment, EmbeddedBody, EmbeddedBodyCodec, ReadContentFormat,
    RenderBudget, RenderContext, RenderError, RenderedBody,
};
use agent_access_provider::{
    ActionDescriptor, AdmittedRequest, BackendConfig, BackendRegistration, BodyAdmission,
    BrokerBodyPart, BrokerBodyPartSpec, BuildContext, ClientProfile, CredentialDescriptor,
    CredentialView, EgressDeclaration, EgressProxyConfig, NamespaceSelectorDescriptor, Provider,
    ProviderBuildError, ProviderError, ProviderInvocation, ProviderResult, ProviderResultStream,
    ProviderState, ProviderStreamError, ReasonCode, ResourceAttributeDescriptor,
    ResourceAttributes, ResourceScopeCapabilities, ResourceScopes, ResourceSelector, ResourceType,
    ResourceTypeDescriptor, ScopeRequest, ScopeResolution, ServiceDescriptor, ServiceSurface,
    StateDisposition, UpstreamCall, UpstreamClient, UpstreamClientSpec, UpstreamError,
    ValidationContext, attachment_upload_plan, complete_upstream_trace, file_upload_body,
    parse_backend_config, take_upstream_trace, validate_egress_proxy_config,
    validate_upstream_allowlist, validate_upstream_base_url,
};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

const SERVICE: &str = "conformance";
const LABEL: &str = "providers.conformance";
const MAX_PING_MESSAGE_BYTES: usize = 1024;

pub static CONFORMANCE_BACKEND: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    SERVICE,
    parse_backend_config::<ConformanceConfig>,
)
.with_resource_types(&[&CONFORMANCE_ITEM_RESOURCE, &CONFORMANCE_ENDPOINT_RESOURCE])
.development_only();

/// Items on shelves, identified as `shelf/item` with up to two nested
/// shelves. Namespaces cover a shelf and everything below it.
pub static CONFORMANCE_ITEM_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor {
    action_inputs: Some(item_inputs),
    attributes: &[],
    id: ResourceType::from_static("conformance_item"),
    label: "Conformance item",
    plural_label: "Conformance items",
    example: "shelf-one/item-one",
    canonical: |value| is_item_path(value, 2..=4),
    namespace: Some(NamespaceSelectorDescriptor {
        valid: |value| is_item_path(value, 1..=3),
        label: "Items on a shelf",
        members_label: "Items",
        example: "shelf-one",
    }),
};

/// Named endpoints that receive pings. Each managed entry keeps the key the
/// upstream expects as a private attribute: encrypted by the broker, shown
/// only through an audited admin reveal, and handed to the provider only for
/// an authorized invocation that targets exactly that endpoint.
pub static CONFORMANCE_ENDPOINT_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor {
    action_inputs: None,
    attributes: &[ResourceAttributeDescriptor {
        name: "signingKey",
        label: "Signing key",
        description: "Key the conformance upstream requires for pings to this endpoint",
        required: true,
        validate: |value| {
            (16..=256).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_graphic())
        },
    }],
    id: ResourceType::from_static("conformance_endpoint"),
    label: "Conformance endpoint",
    plural_label: "Conformance endpoints",
    example: "alerts",
    canonical: is_endpoint_name,
    namespace: None,
};

/// An exact item is addressed by its whole path.
fn item_inputs(selector: &ResourceSelector) -> Option<Map<String, Value>> {
    let ResourceSelector::Exact { value } = selector else {
        return None;
    };
    Some(Map::from_iter([("item".into(), json!(value))]))
}

fn is_endpoint_name(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_item_path(value: &str, segments: std::ops::RangeInclusive<usize>) -> bool {
    let parts = value.split('/').collect::<Vec<_>>();
    segments.contains(&parts.len())
        && parts.iter().all(|part| {
            (1..=63).contains(&part.len())
                && part.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// `[providers.conformance]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceConfig {
    pub base_url: String,
    pub allowed_upstream_hosts: Vec<String>,
    #[serde(default)]
    pub egress_proxy: Option<EgressProxyConfig>,
    /// Largest file `item.upload` accepts.
    #[serde(default = "default_max_upload_bytes")]
    pub max_upload_bytes: u64,
    /// Offers `endpoint.ping`. Its endpoints' keys are private resource
    /// attributes, which need managed policy.
    #[serde(default)]
    pub endpoints: bool,
    /// Top-level shelves. When set, items must be on one of them, and
    /// discovery reports access to every item per reachable shelf.
    #[serde(default)]
    pub shelves: Vec<String>,
}

fn default_max_upload_bytes() -> u64 {
    1024 * 1024
}

impl BackendConfig for ConformanceConfig {
    fn kind(&self) -> &'static str {
        SERVICE
    }

    fn validate(&self, context: &ValidationContext<'_>, errors: &mut Vec<String>) {
        validate_upstream_base_url(
            &format!("{LABEL}.base_url"),
            &self.base_url,
            context.production(),
            errors,
        );
        validate_upstream_allowlist(
            &format!("{LABEL}.allowed_upstream_hosts"),
            &self.allowed_upstream_hosts,
            context.production(),
            errors,
        );
        validate_egress_proxy_config(
            &format!("{LABEL}.egress_proxy"),
            self.egress_proxy.as_ref(),
            errors,
        );
        if self.max_upload_bytes == 0 || self.max_upload_bytes > context.limits.max_http_body_bytes
        {
            errors.push(format!(
                "{LABEL}.max_upload_bytes must be between 1 and limits.max_http_body_bytes"
            ));
        }
        let mut shelves = std::collections::BTreeSet::new();
        if !self
            .shelves
            .iter()
            .all(|shelf| is_item_path(shelf, 1..=1) && shelves.insert(shelf))
        {
            errors.push(format!(
                "{LABEL}.shelves must be distinct single shelf names"
            ));
        }
    }

    /// The type's own validation checks each value's form; the backend adds
    /// what depends on its configuration.
    fn validate_resource_attributes(
        &self,
        resource_type: &ResourceType,
        _attributes: &ResourceAttributes,
    ) -> Result<(), String> {
        if resource_type != &CONFORMANCE_ENDPOINT_RESOURCE.id {
            return Err("conformance items have no private attributes".into());
        }
        if !self.endpoints {
            return Err(format!(
                "conformance endpoints need {LABEL}.endpoints = true"
            ));
        }
        Ok(())
    }

    fn descriptor(&self) -> ServiceDescriptor {
        conformance_descriptor(self)
    }

    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        self.egress_proxy
            .iter()
            .map(|proxy| (format!("{LABEL}.egress_proxy"), proxy))
            .collect()
    }

    fn build(&self, host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        ConformanceProvider::build(self, host).map(|provider| Arc::new(provider) as _)
    }
}

/// The conformance service. Its actions differ only in how they move bytes.
pub fn conformance_descriptor(config: &ConformanceConfig) -> ServiceDescriptor {
    let item = || json!({"type": "string", "description": "Item path, such as shelf-one/item-one"});
    let locator = json!({
        "type": "object", "required": ["item"],
        "properties": {"item": item()}, "additionalProperties": false
    });
    let upload = json!({
        "type": "object", "required": ["item", "attachments"],
        "properties": {
            "item": item(),
            "attachments": {
                "type": "array", "minItems": 1, "maxItems": 1,
                "items": {
                    "type": "object",
                    "required": ["field", "filename", "contentType", "size", "sha256"],
                    "properties": {
                        "field": {"type": "string"},
                        "filename": {"type": "string"},
                        "contentType": {"type": "string"},
                        "size": {"type": "integer", "minimum": 1, "maximum": config.max_upload_bytes},
                        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                    },
                    "additionalProperties": false
                }
            }
        },
        "additionalProperties": false
    });
    let action = |name: &str, description: &str, schema: &Value| {
        ActionDescriptor::new(name, description, schema.clone())
            .scope("item")
            .credential_modes(["service", "per_user"])
    };
    let mut resource_scopes = BTreeMap::from([(
        "item".into(),
        ResourceScopeCapabilities {
            resource_type: CONFORMANCE_ITEM_RESOURCE.id.clone(),
            selectors: vec!["exact".into(), "namespace".into(), "all".into()],
        },
    )]);
    let mut actions = vec![
        action("item.view", "View an item and its text body", &locator)
            .read_only()
            .presentation(Some(ITEM_PRESENTATION)),
        action("item.download", "Download an item's content", &locator)
            .read_only()
            .raw_download(),
        action(
            "item.upload",
            "Replace an item's content with one file",
            &upload,
        )
        .multipart_upload(attachment_upload_plan(&["item"], Some(1))),
    ];
    if config.endpoints {
        resource_scopes.insert(
            "endpoint".into(),
            ResourceScopeCapabilities {
                resource_type: CONFORMANCE_ENDPOINT_RESOURCE.id.clone(),
                selectors: vec!["exact".into(), "all".into()],
            },
        );
        actions.push(
            ActionDescriptor::new(
                "endpoint.ping",
                "Send one ping to a configured endpoint",
                json!({
                    "type": "object", "required": ["endpoint", "message"],
                    "properties": {
                        "endpoint": {"type": "string", "description": "Endpoint name, such as alerts"},
                        "message": {"type": "string", "minLength": 1, "maxLength": MAX_PING_MESSAGE_BYTES}
                    },
                    "additionalProperties": false
                }),
            )
            .scope("endpoint")
            .credential_modes(["service"])
            .resource_attributes(),
        );
    }
    ServiceDescriptor {
        service: SERVICE.into(),
        display_name: "Conformance".into(),
        surface: ServiceSurface::Invoke,
        resource_scopes,
        actions,
        credentials: CredentialDescriptor::default()
            .service_kinds(&["bearer_token"])
            .profile("api_token", "bearer_token"),
        presentation_body_limit: None,
    }
}

const ITEM_PRESENTATION: ActionPresentation = ActionPresentation {
    embedded_bodies: &[EmbeddedBody {
        owner_path: &[BodyPathSegment::Field("item")],
        codec: &PlainBody,
    }],
    whole: Some(&render_item),
};

/// An item's `body` is plain text: Markdown escapes it, text keeps it.
struct PlainBody;

impl EmbeddedBodyCodec for PlainBody {
    fn render(
        &self,
        owner: &Map<String, Value>,
        format: ReadContentFormat,
        max_body_bytes: u64,
        budget: &mut RenderBudget,
    ) -> Result<Option<RenderedBody>, RenderError> {
        let Some(body) = owner.get("body") else {
            return Ok(None);
        };
        let body = body.as_str().ok_or(RenderError)?;
        if body.len() as u64 > max_body_bytes {
            return Err(RenderError);
        }
        budget.charge_node().map_err(|_| RenderError)?;
        budget.charge_work(body.len()).map_err(|_| RenderError)?;
        let value = match format {
            ReadContentFormat::Native => return Ok(None),
            ReadContentFormat::Text => body.to_owned(),
            ReadContentFormat::Markdown => {
                let mut out = agent_access_provider::presentation::MarkdownWriter::new(
                    max_body_bytes.saturating_mul(2),
                );
                out.push_escaped(body)?;
                out.finish()
            }
        };
        Ok(Some(RenderedBody { format, value }))
    }
}

fn render_item(result: &Value, context: &mut RenderContext) -> Result<(), RenderError> {
    let item = result.get("item").ok_or(RenderError)?;
    let field = |name: &str| item.get(name).and_then(Value::as_str).ok_or(RenderError);
    context.out.push("# ")?;
    context.out.push_heading_text(field("title")?)?;
    context.out.push("\n\nItem: ")?;
    context.out.push_code(field("path")?)?;
    context.out.push("\n\n")?;
    context.out.push_escaped(field("body")?)?;
    context.out.push("\n")
}

struct ConformanceProvider {
    requests: UpstreamClient,
    downloads: UpstreamClient,
    uploads: UpstreamClient,
    /// A ping is not idempotent, so its client never retries on its own.
    pings: UpstreamClient,
    endpoints: bool,
    shelves: Vec<String>,
    max_response_bytes: u64,
    max_download_bytes: u64,
    idle_timeout: Duration,
    max_upload_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PingInputs {
    endpoint: String,
    message: String,
}

fn ping_inputs(inputs: &Value) -> Result<PingInputs, ProviderError> {
    let inputs: PingInputs = parse(inputs)?;
    if !is_endpoint_name(&inputs.endpoint) {
        return Err(invalid("conformance endpoint name is invalid"));
    }
    if inputs.message.is_empty() || inputs.message.len() > MAX_PING_MESSAGE_BYTES {
        return Err(invalid("conformance ping message must be 1 to 1024 bytes"));
    }
    Ok(inputs)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemInputs {
    item: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UploadInputs {
    item: String,
    attachments: Vec<AttachmentInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachmentInput {
    field: String,
    filename: String,
    content_type: String,
    size: u64,
    sha256: String,
}

fn invalid(message: &str) -> ProviderError {
    ProviderError::deny(ReasonCode::InputInvalid, message)
}

fn parse<T: serde::de::DeserializeOwned>(inputs: &Value) -> Result<T, ProviderError> {
    serde_json::from_value(inputs.clone()).map_err(|_| invalid("conformance inputs are invalid"))
}

fn checked_item(item: &str) -> Result<&str, ProviderError> {
    CONFORMANCE_ITEM_RESOURCE
        .is_canonical_target(item)
        .then_some(item)
        .ok_or_else(|| invalid("conformance item path is invalid"))
}

fn upload_inputs(inputs: &Value, max_bytes: u64) -> Result<UploadInputs, ProviderError> {
    let inputs: UploadInputs = parse(inputs)?;
    checked_item(&inputs.item)?;
    let [attachment] = inputs.attachments.as_slice() else {
        return Err(invalid("conformance.item.upload takes exactly one file"));
    };
    if attachment.size == 0 || attachment.size > max_bytes {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentSizeDenied,
            "conformance upload exceeds the configured size",
        ));
    }
    Ok(inputs)
}

fn upstream_error(error: UpstreamError) -> ProviderError {
    ProviderError::error(error.reason_code(), "conformance upstream request failed")
}

fn status_error(status: reqwest::StatusCode) -> ProviderError {
    match status.as_u16() {
        401 => ProviderError::deny(
            ReasonCode::UpstreamUnauthorized,
            "conformance rejected the credential",
        ),
        403 => ProviderError::deny(
            ReasonCode::UpstreamForbidden,
            "conformance denied the request",
        ),
        _ => ProviderError::error(ReasonCode::UpstreamFailed, "conformance request failed"),
    }
}

impl ConformanceProvider {
    fn build(
        config: &ConformanceConfig,
        host: &BuildContext<'_>,
    ) -> Result<Self, ProviderBuildError> {
        let base = Url::parse(&format!("{}/", config.base_url.trim_end_matches('/')))
            .map_err(|_| ProviderBuildError::invalid(format!("{LABEL}.base_url is invalid")))?;
        let client = |profile| {
            UpstreamClient::build(
                UpstreamClientSpec {
                    label: LABEL,
                    provider: SERVICE,
                    base: &base,
                    egress: EgressDeclaration::Ordinary(config.egress_proxy.as_ref()),
                    allowed_upstream_hosts: &config.allowed_upstream_hosts,
                    profile,
                    status_reasons: &[],
                },
                host.clients(),
            )
        };
        Ok(Self {
            requests: client(ClientProfile::Request)?,
            downloads: client(ClientProfile::Stream)?,
            uploads: client(ClientProfile::Upload)?,
            pings: client(ClientProfile::SingleAttempt)?,
            endpoints: config.endpoints,
            shelves: config.shelves.clone(),
            max_response_bytes: host.limits().max_upstream_response_bytes,
            max_download_bytes: host.limits().max_download_bytes,
            idle_timeout: Duration::from_millis(host.limits().streaming_idle_timeout_ms),
            max_upload_bytes: config.max_upload_bytes,
        })
    }

    fn url(&self, item: &str, content: bool) -> Url {
        let mut url = self.requests.base().clone();
        {
            let mut segments = url.path_segments_mut().expect("base URLs have a path");
            segments
                .pop_if_empty()
                .push("items")
                .extend(item.split('/'));
            if content {
                segments.push("content");
            }
        }
        url
    }

    fn token(request: &ProviderInvocation) -> Result<&str, ProviderError> {
        match request
            .execution()
            .static_credential()
            .map(|credential| credential.view())
        {
            Some(CredentialView::Bearer { token }) => Ok(token),
            _ => Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "conformance needs a bearer token",
            )),
        }
    }

    /// Reads a JSON response within the response limit, each chunk within
    /// the streaming idle timeout, and passes it to `parse`. The request's
    /// trace is recorded once the outcome is known, so a body that fails
    /// after a successful status is traced as the failure it is.
    async fn read_json<T>(
        &self,
        mut response: reqwest::Response,
        parse: impl FnOnce(Value) -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        let trace = take_upstream_trace(&mut response);
        let outcome = self.read_json_body(response).await.and_then(parse);
        if let Some(trace) = trace {
            trace.complete(outcome.as_ref().err().map(|error| error.reason_code()));
        }
        outcome
    }

    async fn read_json_body(
        &self,
        mut response: reqwest::Response,
    ) -> Result<Value, ProviderError> {
        if !response.status().is_success() {
            return Err(status_error(response.status()));
        }
        let protocol = |message| ProviderError::error(ReasonCode::UpstreamProtocolFailed, message);
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes)
        {
            return Err(protocol("conformance response exceeds the limit"));
        }
        let mut body = Vec::new();
        loop {
            let chunk = tokio::time::timeout(self.idle_timeout, response.chunk())
                .await
                .map_err(|_| {
                    ProviderError::error(
                        ReasonCode::UpstreamTimeout,
                        "conformance response stalled",
                    )
                })?
                .map_err(|_| {
                    ProviderError::error(
                        ReasonCode::UpstreamConnectionFailed,
                        "conformance response failed",
                    )
                })?;
            let Some(chunk) = chunk else {
                break;
            };
            if (body.len() + chunk.len()) as u64 > self.max_response_bytes {
                return Err(protocol("conformance response exceeds the limit"));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| protocol("conformance response is not JSON"))
    }

    fn result(
        action: &str,
        item: &str,
        result: Value,
        status: u16,
        started: Instant,
    ) -> ProviderResult {
        ProviderResult {
            result,
            stream: None,
            audit: Some(json!({"provider": SERVICE, "operation": action, "item": item})),
            upstream_status: Some(status),
            upstream_duration_ms: Some(started.elapsed().as_millis() as u64),
            object_ids: Some(json!({"item": item})),
        }
    }

    /// Sends one ping with the endpoint's private key. The runtime resolved
    /// the key from the authorized endpoint's managed entry; it never enters
    /// the result, audit, or errors.
    async fn ping(&self, request: &ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        let inputs = ping_inputs(request.inputs())?;
        let Some(key) = request.resource_attributes().get("signingKey") else {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "conformance endpoint has no signing key configured",
            ));
        };
        let mut url = self.pings.base().clone();
        url.path_segments_mut()
            .expect("base URLs have a path")
            .pop_if_empty()
            .extend(["endpoints", inputs.endpoint.as_str(), "ping"]);
        let started = Instant::now();
        let response = self
            .pings
            .send(
                self.pings
                    .request(reqwest::Method::POST, url)
                    .bearer_auth(Self::token(request)?)
                    .header("X-Endpoint-Key", key)
                    .json(&json!({"message": inputs.message})),
                UpstreamCall::new("endpoint.ping"),
            )
            .await
            .map_err(upstream_error)?;
        let status = response.status().as_u16();
        let receipt = self
            .read_json(response, |value| {
                value
                    .get("receipt")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        ProviderError::error(
                            ReasonCode::UpstreamProtocolFailed,
                            "conformance ping receipt is missing",
                        )
                    })
            })
            .await?;
        Ok(ProviderResult {
            result: json!({"endpoint": inputs.endpoint, "receipt": receipt}),
            stream: None,
            audit: Some(
                json!({"provider": SERVICE, "operation": "endpoint.ping", "endpoint": inputs.endpoint}),
            ),
            upstream_status: Some(status),
            upstream_duration_ms: Some(started.elapsed().as_millis() as u64),
            object_ids: Some(json!({"endpoint": inputs.endpoint})),
        })
    }

    async fn view(
        &self,
        request: &ProviderInvocation,
        item: &str,
    ) -> Result<ProviderResult, ProviderError> {
        let started = Instant::now();
        let response = self
            .requests
            .send(
                self.requests
                    .request(reqwest::Method::GET, self.url(item, false))
                    .bearer_auth(Self::token(request)?),
                UpstreamCall::new("item.view"),
            )
            .await
            .map_err(upstream_error)?;
        let status = response.status().as_u16();
        let (title, body) = self
            .read_json(response, |value| {
                let text = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_owned);
                match (text("title"), text("body")) {
                    (Some(title), Some(body)) => Ok((title, body)),
                    _ => Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "conformance item is malformed",
                    )),
                }
            })
            .await?;
        Ok(Self::result(
            "item.view",
            item,
            json!({"item": {"path": item, "title": title, "body": body}}),
            status,
            started,
        ))
    }

    async fn download(
        &self,
        request: &ProviderInvocation,
        item: &str,
    ) -> Result<ProviderResult, ProviderError> {
        let started = Instant::now();
        let mut response = self
            .downloads
            .send_with_deadline(
                self.downloads
                    .request(reqwest::Method::GET, self.url(item, true))
                    .bearer_auth(Self::token(request)?),
                self.idle_timeout,
                UpstreamCall::new("item.download"),
            )
            .await
            .map_err(upstream_error)?;
        if !response.status().is_success() {
            let error = status_error(response.status());
            complete_upstream_trace(&mut response, Some(error.reason_code()));
            return Err(error);
        }
        let size = response.content_length();
        if size.is_some_and(|size| size > self.max_download_bytes) {
            let error = ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "conformance content exceeds the download limit",
            );
            complete_upstream_trace(&mut response, Some(error.reason_code()));
            return Err(error);
        }
        complete_upstream_trace(&mut response, None);
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_owned();
        let (idle, cap) = (self.idle_timeout, self.max_download_bytes);
        let chunks = futures_util::stream::try_unfold(
            (response, 0_u64),
            move |(mut response, read)| async move {
                let chunk = tokio::time::timeout(idle, response.chunk())
                    .await
                    .map_err(|_| {
                        ProviderStreamError::new(
                            ReasonCode::UpstreamTimeout,
                            "conformance download stalled",
                        )
                    })?
                    .map_err(|_| {
                        ProviderStreamError::new(
                            ReasonCode::UpstreamConnectionFailed,
                            "conformance download failed",
                        )
                    })?;
                let Some(chunk) = chunk else {
                    return Ok(None);
                };
                let read = read + chunk.len() as u64;
                if read > cap {
                    return Err(ProviderStreamError::new(
                        ReasonCode::AttachmentSizeDenied,
                        "conformance content exceeds the download limit",
                    ));
                }
                Ok(Some((chunk, (response, read))))
            },
        );
        let mut stream = ProviderResultStream::from_stream(content_type.clone(), chunks);
        if let Some(size) = size {
            stream = stream.with_expected_size(size, "conformance content length did not match");
        }
        let mut result = Self::result(
            "item.download",
            item,
            json!({"item": item, "contentType": content_type, "size": size}),
            status,
            started,
        );
        result.stream = Some(stream);
        Ok(result)
    }

    async fn upload(
        &self,
        request: &ProviderInvocation,
        item: &str,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = upload_inputs(request.inputs(), self.max_upload_bytes)?;
        let attachment = &inputs.attachments[0];
        let [part] = request.body_parts() else {
            return Err(ProviderError::deny(
                ReasonCode::BodyMalformed,
                "conformance.item.upload takes one file part",
            ));
        };
        check_part(part, attachment)?;
        let started = Instant::now();
        let builder = self
            .uploads
            .request(reqwest::Method::PUT, self.url(item, true))
            .bearer_auth(Self::token(request)?)
            .header(
                reqwest::header::CONTENT_TYPE,
                attachment.content_type.as_str(),
            );
        let (builder, progress) = match part.temp_file_path() {
            Some(path) => {
                let (body, progress) = file_upload_body(path).await.map_err(|_| {
                    ProviderError::error(
                        ReasonCode::BodyMalformed,
                        "conformance upload file is unavailable",
                    )
                })?;
                (builder.body(body), Some(progress))
            }
            None => (builder.body(part.bytes.clone()), None),
        };
        let response = self
            .uploads
            .send_upload(
                builder,
                progress,
                self.idle_timeout,
                UpstreamCall::new("item.upload"),
            )
            .await
            .map_err(upstream_error)?;
        let status = response.status().as_u16();
        let revision = self
            .read_json(response, |value| Ok(value.get("revision").cloned()))
            .await?;
        Ok(Self::result(
            "item.upload",
            item,
            json!({
                "item": item,
                "filename": attachment.filename,
                "size": attachment.size,
                "sha256": attachment.sha256,
                "revision": revision,
            }),
            status,
            started,
        ))
    }
}

/// The uploaded part must be the one the admitted metadata described.
fn check_part(part: &BrokerBodyPart, attachment: &AttachmentInput) -> Result<(), ProviderError> {
    let mismatch = |reason, message| Err(ProviderError::deny(reason, message));
    if part.name != attachment.field
        || part.file_name.as_deref() != Some(attachment.filename.as_str())
    {
        return mismatch(
            ReasonCode::BodyMalformed,
            "conformance file part does not match its metadata",
        );
    }
    if part.content_type.as_deref() != Some(attachment.content_type.as_str()) {
        return mismatch(
            ReasonCode::AttachmentMediaTypeDenied,
            "conformance file type does not match its metadata",
        );
    }
    if part.size() != attachment.size || part.sha256_hex() != attachment.sha256 {
        return mismatch(
            ReasonCode::AttachmentIntegrityMismatch,
            "conformance file does not match its metadata",
        );
    }
    Ok(())
}

impl ConformanceProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if action == "endpoint.ping" && self.endpoints {
            let endpoint = ping_inputs(inputs)?.endpoint;
            return Ok(BTreeMap::from([("endpoint".into(), vec![endpoint])]));
        }
        let item = match action {
            "item.view" | "item.download" => parse::<ItemInputs>(inputs)?.item,
            "item.upload" => upload_inputs(inputs, self.max_upload_bytes)?.item,
            _ => {
                return Err(ProviderError::deny(
                    ReasonCode::ServiceActionDenied,
                    "conformance action is not supported",
                ));
            }
        };
        checked_item(&item)?;
        if !self.shelves.is_empty()
            && !self
                .shelves
                .iter()
                .any(|shelf| item.split('/').next() == Some(shelf.as_str()))
        {
            return Err(invalid("conformance item is not on a configured shelf"));
        }
        Ok(BTreeMap::from([("item".into(), vec![item])]))
    }
}

#[async_trait]
impl Provider for ConformanceProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    fn resource_roots(&self, resource_type: &ResourceType) -> Vec<String> {
        if resource_type == &CONFORMANCE_ITEM_RESOURCE.id {
            self.shelves.clone()
        } else {
            Vec::new()
        }
    }

    async fn authorize_body_parts(
        &self,
        request: &AdmittedRequest,
        _state: Option<&ProviderState>,
    ) -> Result<BodyAdmission, ProviderError> {
        if request.action() != "item.upload" {
            return Err(ProviderError::deny(
                ReasonCode::BodyMalformed,
                "conformance action does not accept file parts",
            ));
        }
        let inputs = upload_inputs(request.inputs(), self.max_upload_bytes)?;
        let part_specs = inputs
            .attachments
            .into_iter()
            .map(|attachment| BrokerBodyPartSpec {
                name: attachment.field,
                file_name: attachment.filename,
                content_type: attachment.content_type,
                size: attachment.size,
                sha256: attachment.sha256,
            })
            .collect();
        Ok(BodyAdmission::new(part_specs, StateDisposition::Keep))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        if request.action() == "endpoint.ping" && self.endpoints {
            return self.ping(&request).await;
        }
        let item = request
            .resource_scopes()?
            .get("item")
            .and_then(|items| items.first())
            .cloned()
            .ok_or_else(|| invalid("conformance item scope is missing"))?;
        match request.action() {
            "item.view" => self.view(&request, &item).await,
            "item.download" => self.download(&request, &item).await,
            "item.upload" => self.upload(&request, &item).await,
            _ => Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "conformance action is not supported",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::presentation::response_capabilities;
    use agent_access_provider::test_support::{
        InvocationBuilder, TestHost, bearer_credential, install_trace_capture,
    };
    use agent_access_provider::{
        ActionIo, CorrelationContext, ProviderLimits, with_provider_context,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(base_url: &str) -> ConformanceConfig {
        ConformanceConfig {
            base_url: base_url.into(),
            allowed_upstream_hosts: vec![format!("{base_url}/**")],
            egress_proxy: None,
            max_upload_bytes: default_max_upload_bytes(),
            endpoints: true,
            shelves: Vec::new(),
        }
    }

    fn provider(base_url: &str, limits: ProviderLimits) -> ConformanceProvider {
        ConformanceProvider::build(&config(base_url), &TestHost::with_limits(limits).context())
            .unwrap()
    }

    #[test]
    fn build_declares_each_transfer_profile_with_the_configured_proxy() {
        let host = TestHost::default();
        let mut config = config("https://conformance.example.test");
        config.egress_proxy = Some(EgressProxyConfig {
            url: "http://conformance-proxy.example:3128".into(),
            username_ref: None,
            password_ref: None,
        });
        ConformanceProvider::build(&config, &host.context()).unwrap();
        let built = host.built_clients();
        assert_eq!(
            built
                .iter()
                .map(|client| client.profile)
                .collect::<Vec<_>>(),
            [
                ClientProfile::Request,
                ClientProfile::Stream,
                ClientProfile::Upload,
                ClientProfile::SingleAttempt,
            ]
        );
        for client in built {
            assert_eq!(client.label, LABEL);
            assert_eq!(
                client.route.audit_value(),
                json!({"mode": "service", "proxy": "http://conformance-proxy.example:3128"})
            );
        }
    }

    fn invocation(
        action: &str,
        inputs: Value,
        body_parts: Vec<BrokerBodyPart>,
    ) -> ProviderInvocation {
        let resource_scopes = inputs["item"]
            .as_str()
            .map(|item| BTreeMap::from([("item".into(), vec![item.to_owned()])]))
            .unwrap_or_default();
        InvocationBuilder::new(SERVICE, action)
            .inputs(inputs)
            .resources(resource_scopes)
            .credential(bearer_credential("token"))
            .body_parts(body_parts)
            .build()
    }

    const KEY: &str = "endpoint-key-sentinel-0123456789";

    fn ping(key: Option<&str>) -> ProviderInvocation {
        let request = invocation(
            "endpoint.ping",
            json!({"endpoint": "alerts", "message": "hello"}),
            Vec::new(),
        );
        InvocationBuilder::from(request)
            .resources(BTreeMap::from([("endpoint".into(), vec!["alerts".into()])]))
            .resource_attributes(
                key.map(|key| BTreeMap::from([("signingKey".to_string(), key.to_string())]).into())
                    .unwrap_or_default(),
            )
            .build()
    }

    #[tokio::test]
    async fn pings_carry_the_endpoint_key_once_and_keep_it_private() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/endpoints/alerts/ping"))
            .and(wiremock::matchers::header("x-endpoint-key", KEY))
            .and(wiremock::matchers::header("authorization", "Bearer token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"receipt": "r-1"})))
            .expect(1)
            .mount(&server)
            .await;
        let result = provider(&server.uri(), ProviderLimits::default())
            .invoke(ping(Some(KEY)))
            .await
            .unwrap();
        assert_eq!(
            result.result,
            json!({"endpoint": "alerts", "receipt": "r-1"})
        );
        let visible = format!(
            "{} {:?} {:?}",
            result.result, result.audit, result.object_ids
        );
        assert!(!visible.contains(KEY));
    }

    #[tokio::test]
    async fn pings_are_sent_once_and_need_a_configured_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/endpoints/alerts/ping"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        let provider = provider(&server.uri(), ProviderLimits::default());
        let failed = provider.invoke(ping(Some(KEY))).await.unwrap_err();
        assert_eq!(failed.reason_code(), ReasonCode::UpstreamFailed);
        let unconfigured = provider.invoke(ping(None)).await.unwrap_err();
        assert_eq!(unconfigured.reason_code(), ReasonCode::ScopeUnresolved);
        assert!(!format!("{failed:?}").contains(KEY));
    }

    #[test]
    fn shelves_bound_items_and_are_the_item_roots() {
        let exact = ResourceSelector::Exact {
            value: "shelf-one/item-one".into(),
        };
        assert_eq!(
            (CONFORMANCE_ITEM_RESOURCE.action_inputs.unwrap())(&exact),
            Some(Map::from_iter([(
                "item".into(),
                json!("shelf-one/item-one")
            )]))
        );
        for selector in [
            ResourceSelector::Namespace {
                value: "shelf-one".into(),
            },
            ResourceSelector::All,
        ] {
            assert_eq!(
                (CONFORMANCE_ITEM_RESOURCE.action_inputs.unwrap())(&selector),
                None
            );
        }
        let mut provider = provider(
            "https://conformance.example.test",
            ProviderLimits::default(),
        );
        assert!(
            provider
                .resource_roots(&CONFORMANCE_ITEM_RESOURCE.id)
                .is_empty()
        );
        provider.shelves = vec!["shelf-one".into(), "shelf-two".into()];
        assert_eq!(
            provider.resource_roots(&CONFORMANCE_ITEM_RESOURCE.id),
            ["shelf-one", "shelf-two"]
        );
        assert!(
            provider
                .resource_roots(&CONFORMANCE_ENDPOINT_RESOURCE.id)
                .is_empty()
        );
        assert!(
            provider
                .local_scopes("item.view", &json!({"item": "shelf-two/item"}))
                .is_ok()
        );
        let outside = provider
            .local_scopes("item.view", &json!({"item": "shelf-three/item"}))
            .unwrap_err();
        assert_eq!(outside.reason_code(), ReasonCode::InputInvalid);
        let mut config = config("https://conformance.example.test");
        for shelves in [vec!["a/b"], vec!["one", "one"], vec![""]] {
            config.shelves = shelves.into_iter().map(String::from).collect();
            let mut errors = Vec::new();
            config.validate(
                &ValidationContext {
                    environment: "development",
                    policy_authority: "toml",
                    limits: &ProviderLimits::default(),
                    credentials: Default::default(),
                },
                &mut errors,
            );
            assert_eq!(
                errors,
                ["providers.conformance.shelves must be distinct single shelf names"]
            );
        }
    }

    #[test]
    fn endpoint_keys_are_validated_by_the_type_and_the_backend() {
        let endpoint = &CONFORMANCE_ENDPOINT_RESOURCE;
        let exact = agent_access_provider::ResourceSelector::Exact {
            value: "alerts".into(),
        };
        let key = |value: &str| -> ResourceAttributes {
            BTreeMap::from([("signingKey".to_string(), value.to_string())]).into()
        };
        endpoint
            .validate_attributes(&exact, &key(KEY), true)
            .unwrap();
        assert!(
            endpoint
                .validate_attributes(&exact, &key("short"), true)
                .is_err()
        );
        assert!(
            endpoint
                .validate_attributes(&exact, &ResourceAttributes::default(), true)
                .is_err()
        );
        assert!(
            endpoint
                .validate_attributes(
                    &agent_access_provider::ResourceSelector::All,
                    &key(KEY),
                    true
                )
                .is_err()
        );
        let mut config = config("https://conformance.example.test");
        config
            .validate_resource_attributes(&endpoint.id, &key(KEY))
            .unwrap();
        assert!(
            config
                .validate_resource_attributes(&CONFORMANCE_ITEM_RESOURCE.id, &key(KEY))
                .is_err()
        );
        config.endpoints = false;
        assert_eq!(
            config
                .validate_resource_attributes(&endpoint.id, &key(KEY))
                .unwrap_err(),
            "conformance endpoints need providers.conformance.endpoints = true"
        );
    }

    async fn view(provider: &ConformanceProvider) -> Result<ProviderResult, ProviderError> {
        with_provider_context(
            CorrelationContext::for_tests(),
            SERVICE.into(),
            "item.view".into(),
            provider.invoke(invocation(
                "item.view",
                json!({"item": "shelf/item"}),
                Vec::new(),
            )),
        )
        .await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn json_traces_record_how_the_body_turned_out() {
        let limits = ProviderLimits {
            max_upstream_response_bytes: 64,
            ..ProviderLimits::default()
        };
        for (body, reason) in [
            (r#"{"title":"T","body":"B"}"#.to_string(), None),
            ("not json".to_string(), Some("upstream_protocol_failed")),
            (
                r#"{"title":"T"}"#.to_string(),
                Some("upstream_protocol_failed"),
            ),
            (
                format!(r#"{{"title":"T","body":"{}"}}"#, "x".repeat(64)),
                Some("upstream_protocol_failed"),
            ),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/items/shelf/item"))
                .respond_with(ResponseTemplate::new(200).set_body_string(body.clone()))
                .mount(&server)
                .await;
            let capture = install_trace_capture().start();
            let outcome = capture
                .run(view(&provider(&server.uri(), limits.clone())))
                .await;
            let events = capture.take_upstream_requests();
            assert_eq!(events.len(), 1, "{body}: {events:?}");
            assert_eq!(events[0]["http.statusCode"], 200);
            match reason {
                None => {
                    assert!(outcome.is_ok());
                    assert!(events[0].get("reasonCode").is_none(), "{events:?}");
                }
                Some(reason) => {
                    assert_eq!(outcome.unwrap_err().reason_code().as_str(), reason);
                    assert_eq!(events[0]["reasonCode"], reason, "{body}");
                }
            }
        }
    }

    /// An upload whose response headers arrive and whose body then stalls
    /// fails after the idle timeout instead of holding the invocation.
    #[tokio::test(flavor = "current_thread")]
    async fn stalled_upload_responses_time_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.ends_with(b"payload") {
                let read = socket.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 64\r\n\r\n{")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let provider = provider(
            &base,
            ProviderLimits {
                streaming_idle_timeout_ms: 200,
                ..ProviderLimits::default()
            },
        );
        let content = b"payload";
        let part = BrokerBodyPart {
            name: "file".into(),
            file_name: Some("notes.txt".into()),
            content_type: Some("text/plain".into()),
            bytes: content.to_vec(),
            temp_file: None,
        };
        let inputs = json!({"item": "shelf/item", "attachments": [{
            "field": "file", "filename": "notes.txt", "contentType": "text/plain",
            "size": content.len(), "sha256": part.sha256_hex()
        }]});
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            provider.invoke(invocation("item.upload", inputs, vec![part])),
        )
        .await
        .expect("the idle timeout bounds the response body");
        assert_eq!(
            outcome.unwrap_err().reason_code(),
            ReasonCode::UpstreamTimeout
        );
        server.abort();
    }

    #[test]
    fn items_and_shelves_have_distinct_grammars() {
        let item = &CONFORMANCE_ITEM_RESOURCE;
        assert!(item.is_canonical_target("shelf-one/item-one"));
        assert!(item.is_canonical_target("a/b/c/d"));
        assert!(!item.is_canonical_target("shelf-one"));
        assert!(!item.is_canonical_target("a/b/c/d/e"));
        assert!(!item.is_canonical_target("Shelf/item"));
        assert!(!item.is_canonical_target("shelf//item"));
        let namespace = item.namespace.as_ref().unwrap();
        assert!((namespace.valid)("shelf-one"));
        assert!(!(namespace.valid)("a/b/c/d"));
    }

    #[test]
    fn descriptor_validates_and_covers_every_extension_point() {
        let mut config = config("https://conformance.example.test");
        config.endpoints = false;
        let without_endpoints = conformance_descriptor(&config);
        without_endpoints.validate().unwrap();
        assert!(without_endpoints.action("endpoint.ping").is_none());
        assert!(!without_endpoints.resource_scopes.contains_key("endpoint"));
        config.endpoints = true;
        let descriptor = conformance_descriptor(&config);
        descriptor.validate().unwrap();
        let ping = descriptor.action("endpoint.ping").unwrap();
        assert!(ping.requires_resource_attributes && !ping.read_only);
        let action = |name: &str| descriptor.action(name).unwrap();
        let view = response_capabilities(action("item.view").presentation.as_ref());
        assert!(view.supports_markdown_response() && view.supports_read_content());
        assert!(matches!(
            action("item.download").io,
            ActionIo::RawDownload { .. }
        ));
        assert!(matches!(
            action("item.upload").io,
            ActionIo::MultipartUpload { .. }
        ));
        assert_eq!(
            descriptor.credential_profile_kind("api_token"),
            Some("bearer_token")
        );
    }
}
