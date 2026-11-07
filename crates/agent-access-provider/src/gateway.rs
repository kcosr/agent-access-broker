//! Linked HTTP protocol modules. Identity, credentials, transport and delivery
//! ownership stay in the host; modules only classify and validate protocol data.
use crate::{
    Decision, ModuleMetadata, ProviderBuildError, ProviderError, ProviderReasonDefinition,
    ReasonCode, ResourceScopes, ResourceTypeDescriptor, ServiceDescriptor,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use reqwest::{Method, header::HeaderMap};
use serde_json::Value;
use std::{collections::VecDeque, fmt, pin::Pin, sync::Arc, time::Duration};

/// Parses only the selected module's remaining fields. Parsers must reject all
/// unknown fields (typically with `serde(deny_unknown_fields)`); the host owns
/// common fields and validates the returned descriptor against its context.
pub type GatewayConfigParser = fn(toml::Value) -> Result<Arc<dyn GatewayConfig>, String>;
/// Builds bounded, version-tagged managed data. Builders must reject a zero
/// manifest generation, an empty/invalid hash, and unsupported wire versions.
pub type GatewayManagedPlanBuilder = fn(
    &GatewayServiceContext,
    &GatewayManagedInput,
) -> Result<Arc<dyn GatewayProtocol>, ProviderBuildError>;
const DEFAULT_REQUEST_KINDS: &[GatewayRequestKind] = &[GatewayRequestKind::counted("request")];

/// A protocol kind selected by an assembly, independent of its service instances.
/// Composition rejects duplicate or invalid kinds/request-kind names, foreign
/// domain-reason prefixes, collisions and reserved audit keys before serving.
#[non_exhaustive]
#[derive(Debug)]
pub struct GatewayRegistration {
    module: ModuleMetadata,
    kind: &'static str,
    parse: GatewayConfigParser,
    request_kinds: &'static [GatewayRequestKind],
    resource_types: &'static [&'static ResourceTypeDescriptor],
    domain_reasons: &'static [&'static ProviderReasonDefinition],
    managed_builder: Option<GatewayManagedPlanBuilder>,
    audit_key: &'static str,
}

impl GatewayRegistration {
    pub const fn new(
        module: ModuleMetadata,
        kind: &'static str,
        parse: GatewayConfigParser,
    ) -> Self {
        Self {
            module,
            kind,
            parse,
            request_kinds: DEFAULT_REQUEST_KINDS,
            resource_types: &[],
            domain_reasons: &[],
            managed_builder: None,
            audit_key: "gateway",
        }
    }
    pub const fn with_request_kinds(mut self, kinds: &'static [GatewayRequestKind]) -> Self {
        self.request_kinds = kinds;
        self
    }
    pub const fn with_resource_types(
        mut self,
        types: &'static [&'static ResourceTypeDescriptor],
    ) -> Self {
        self.resource_types = types;
        self
    }
    pub const fn with_domain_reasons(
        mut self,
        reasons: &'static [&'static ProviderReasonDefinition],
    ) -> Self {
        self.domain_reasons = reasons;
        self
    }
    pub const fn with_managed_builder(mut self, builder: GatewayManagedPlanBuilder) -> Self {
        self.managed_builder = Some(builder);
        self
    }
    pub const fn with_audit_key(mut self, key: &'static str) -> Self {
        self.audit_key = key;
        self
    }
    pub const fn module(&self) -> ModuleMetadata {
        self.module
    }
    pub const fn kind(&self) -> &'static str {
        self.kind
    }
    pub const fn request_kinds(&self) -> &'static [GatewayRequestKind] {
        self.request_kinds
    }
    pub const fn resource_types(&self) -> &'static [&'static ResourceTypeDescriptor] {
        self.resource_types
    }
    pub const fn domain_reasons(&self) -> &'static [&'static ProviderReasonDefinition] {
        self.domain_reasons
    }
    pub const fn managed_builder(&self) -> Option<GatewayManagedPlanBuilder> {
        self.managed_builder
    }
    pub const fn audit_key(&self) -> &'static str {
        self.audit_key
    }
    pub fn parse_config(&self, fields: toml::Value) -> Result<Arc<dyn GatewayConfig>, String> {
        (self.parse)(fields)
    }
    pub fn counted(&self, kind: &str) -> Option<bool> {
        self.request_kinds
            .iter()
            .find(|entry| entry.name == kind)
            .map(|entry| entry.counted)
    }
    /// Checks a module-generated failure, never an ordinary upstream HTTP response.
    pub fn check_failure(
        &self,
        phase: GatewayHookPhase,
        error: &ProviderError,
    ) -> Result<(), crate::host::ContractViolation> {
        use crate::host::ContractViolation;
        let reason = error.reason_code();
        if reason.host_port().is_some() {
            return Err(ContractViolation::HostPortNotPermitted);
        }
        if let Some(definition) = reason.domain() {
            return self
                .domain_reasons
                .iter()
                .any(|declared| **declared == *definition)
                .then_some(())
                .ok_or(ContractViolation::UnregisteredDomainReason);
        }
        let Some(code) = reason.standard() else {
            return Err(ContractViolation::HostOnlyReason);
        };
        let permitted = match phase {
            GatewayHookPhase::Classification => matches!(
                code,
                ReasonCode::GatewayRuleNotFound
                    | ReasonCode::GatewayContentTypeDenied
                    | ReasonCode::GatewayMethodDenied
                    | ReasonCode::GatewayQueryDenied
                    | ReasonCode::GitServiceDenied
                    | ReasonCode::GatewayHeaderDenied
                    | ReasonCode::InputInvalid
            ),
            GatewayHookPhase::Preflight => matches!(
                code,
                ReasonCode::GatewayHeaderDenied
                    | ReasonCode::GatewayRequestCapExceeded
                    | ReasonCode::GitPktLineMalformed
                    | ReasonCode::GitPrefixCapExceeded
                    | ReasonCode::GatewayRequestBodyDenied
                    | ReasonCode::GitRefDenied
                    | ReasonCode::GitCapabilityDenied
                    | ReasonCode::InputInvalid
                    | ReasonCode::BodyMalformed
                    | ReasonCode::BodySizeDenied
                    | ReasonCode::BodyFormatUnsupported
                    | ReasonCode::UpstreamTimeout
            ),
            GatewayHookPhase::Verification => matches!(
                code,
                ReasonCode::InputInvalid
                    | ReasonCode::VerificationMismatch
                    | ReasonCode::GatewayRuleNotFound
                    | ReasonCode::ScopeUnresolved
                    | ReasonCode::UpstreamUnauthorized
                    | ReasonCode::UpstreamForbidden
                    | ReasonCode::UpstreamFailed
                    | ReasonCode::UpstreamProtocolFailed
            ),
            GatewayHookPhase::Response => matches!(
                code,
                ReasonCode::UpstreamProtocolFailed | ReasonCode::UpstreamFailed
            ),
        };
        if !permitted {
            return Err(ContractViolation::HostOnlyReason);
        }
        let error_allowed = error.decision() == Decision::Error
            && ((phase == GatewayHookPhase::Verification
                && matches!(
                    code,
                    ReasonCode::UpstreamUnauthorized
                        | ReasonCode::UpstreamForbidden
                        | ReasonCode::UpstreamFailed
                        | ReasonCode::UpstreamProtocolFailed
                ))
                || (phase == GatewayHookPhase::Preflight && code == ReasonCode::UpstreamTimeout)
                || (phase == GatewayHookPhase::Response
                    && matches!(
                        code,
                        ReasonCode::UpstreamProtocolFailed | ReasonCode::UpstreamFailed
                    )));
        let deny_allowed = error.decision() == Decision::Deny
            && !matches!(
                code,
                ReasonCode::UpstreamFailed | ReasonCode::UpstreamTimeout
            )
            && phase != GatewayHookPhase::Response;
        if !deny_allowed && !error_allowed {
            return Err(ContractViolation::ReasonNotPermitted);
        }
        Ok(())
    }
}

/// Protocol hooks cannot report host authentication, authorization or accounting decisions.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayHookPhase {
    Classification,
    Preflight,
    Verification,
    Response,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayRequestKind {
    name: &'static str,
    counted: bool,
}
impl GatewayRequestKind {
    pub const fn counted(name: &'static str) -> Self {
        Self {
            name,
            counted: true,
        }
    }
    pub const fn exempt(name: &'static str) -> Self {
        Self {
            name,
            counted: false,
        }
    }
    pub const fn name(&self) -> &'static str {
        self.name
    }
    pub const fn is_counted(&self) -> bool {
        self.counted
    }
}

/// Nonsecret settings the host supplies to one configured or managed protocol.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct GatewayServiceContext {
    pub service: String,
    pub display_name: String,
    pub broker_hosts: Vec<String>,
    pub upstream_base_url: String,
    pub credential_modes: Vec<String>,
    pub auth_modes: Vec<String>,
}
impl GatewayServiceContext {
    pub fn new(
        service: impl Into<String>,
        display_name: impl Into<String>,
        upstream_base_url: impl Into<String>,
    ) -> Self {
        Self {
            service: service.into(),
            display_name: display_name.into(),
            upstream_base_url: upstream_base_url.into(),
            broker_hosts: Vec::new(),
            credential_modes: Vec::new(),
            auth_modes: Vec::new(),
        }
    }
    pub fn with_broker_hosts(mut self, hosts: Vec<String>) -> Self {
        self.broker_hosts = hosts;
        self
    }
    pub fn with_credential_modes(mut self, modes: Vec<String>) -> Self {
        self.credential_modes = modes;
        self
    }
    pub fn with_auth_modes(mut self, modes: Vec<String>) -> Self {
        self.auth_modes = modes;
        self
    }
}

/// A strict module-owned configuration. All methods are local and offline.
/// The host rejects descriptors whose service, Gateway surface, kind or host
/// reservation differs from the selected registration and service context.
pub trait GatewayConfig: fmt::Debug + Send + Sync {
    fn validate(&self, context: &GatewayServiceContext, errors: &mut Vec<String>);
    fn descriptor(&self, context: &GatewayServiceContext) -> ServiceDescriptor;
    fn build(
        &self,
        context: &GatewayServiceContext,
    ) -> Result<Arc<dyn GatewayProtocol>, ProviderBuildError>;
}

/// A bounded, explicitly versioned serialized plan or route manifest.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct GatewayVersionedData {
    pub version: u32,
    pub data: Value,
}
impl GatewayVersionedData {
    pub fn new(version: u32, data: Value) -> Self {
        Self { version, data }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct GatewayManagedAction {
    pub action: String,
    pub version: u64,
    pub accepted_hash: String,
    pub dispatchable: bool,
    pub plan: GatewayVersionedData,
}
impl GatewayManagedAction {
    pub fn new(
        action: impl Into<String>,
        version: u64,
        accepted_hash: impl Into<String>,
        dispatchable: bool,
        plan: GatewayVersionedData,
    ) -> Self {
        Self {
            action: action.into(),
            version,
            accepted_hash: accepted_hash.into(),
            dispatchable,
            plan,
        }
    }
}
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct GatewayManagedInput {
    pub manifest: GatewayVersionedData,
    pub actions: Vec<GatewayManagedAction>,
    pub manifest_generation: u64,
    pub manifest_hash: String,
}
impl GatewayManagedInput {
    pub fn new(manifest: GatewayVersionedData, actions: Vec<GatewayManagedAction>) -> Self {
        Self {
            manifest,
            actions,
            manifest_generation: 0,
            manifest_hash: String::new(),
        }
    }
    pub fn with_manifest_revision(mut self, generation: u64, hash: impl Into<String>) -> Self {
        self.manifest_generation = generation;
        self.manifest_hash = hash.into();
        self
    }
}

/// Sanitized request head. The host removes authentication and identity carriers.
#[non_exhaustive]
#[derive(Clone, Copy)]
pub struct GatewayRequestHead<'a> {
    method: &'a Method,
    path_and_query: &'a str,
    headers: &'a HeaderMap,
}
impl fmt::Debug for GatewayRequestHead<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayRequestHead")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}
impl<'a> GatewayRequestHead<'a> {
    pub(crate) fn new(method: &'a Method, path_and_query: &'a str, headers: &'a HeaderMap) -> Self {
        Self {
            method,
            path_and_query,
            headers,
        }
    }
    pub fn method(&self) -> &'a Method {
        self.method
    }
    pub fn path_and_query(&self) -> &'a str {
        self.path_and_query
    }
    pub fn headers(&self) -> &'a HeaderMap {
        self.headers
    }
}

pub trait GatewayProtocol: fmt::Debug + Send + Sync {
    fn classify(
        &self,
        head: GatewayRequestHead<'_>,
    ) -> Result<GatewayClassification, ProviderError>;
    /// Construct a bounded protocol probe. The service descriptor's verification
    /// capability is authoritative: the host never calls this for an ineligible
    /// service, and `None` from an eligible service is a contract failure.
    fn verification(
        &self,
        _input: Option<&str>,
    ) -> Result<Option<Box<dyn GatewayVerificationProbe>>, ProviderError> {
        Ok(None)
    }
}

#[non_exhaustive]
pub struct GatewayClassification {
    action: String,
    scopes: ResourceScopes,
    request_kind: &'static str,
    request: Box<dyn GatewayRequest>,
}
impl GatewayClassification {
    pub fn new(
        action: impl Into<String>,
        scopes: ResourceScopes,
        request_kind: &'static str,
        request: Box<dyn GatewayRequest>,
    ) -> Self {
        Self {
            action: action.into(),
            scopes,
            request_kind,
            request,
        }
    }
    pub fn action(&self) -> &str {
        &self.action
    }
    pub fn scopes(&self) -> &ResourceScopes {
        &self.scopes
    }
    pub fn request_kind(&self) -> &'static str {
        self.request_kind
    }
    pub fn into_request(self) -> Box<dyn GatewayRequest> {
        self.request
    }
}
impl fmt::Debug for GatewayClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayClassification")
            .field("action", &self.action)
            .field("request_kind", &self.request_kind)
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait GatewayRequest: Send {
    async fn preflight(
        self: Box<Self>,
        body: GatewayBody,
    ) -> Result<GatewayForwardPlan, ProviderError>;
}

/// Trailer values are deliberately withheld; a protocol can reject their presence.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum GatewayBodyFrame {
    Data(Bytes),
    Trailers,
}
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayBodyError {
    TooLarge,
    Timeout,
    IdleTimeout,
    Read,
}
impl fmt::Display for GatewayBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "gateway body exceeds its limit",
            Self::Timeout | Self::IdleTimeout => "gateway body read timed out",
            Self::Read => "gateway body could not be read",
        })
    }
}
impl std::error::Error for GatewayBodyError {}
pub type GatewayBodyStream =
    Pin<Box<dyn Stream<Item = Result<GatewayBodyFrame, GatewayBodyError>> + Send>>;

/// Host-owned body with bounded inspection and automatic byte-exact replay.
/// Every inspected nonempty data frame and trailer frame remains owned until
/// the host forwards it. Empty data frames are omitted without changing bytes.
/// `max_bytes` is the whole-request wire-byte cap, also the maximum retained
/// inspection memory. Whole frames, including over-read bytes, count against it;
/// protocol-specific prefix limits must be enforced separately by the module.
/// More than 32 consecutive empty data or trailer frames fail inspection with
/// `GatewayBodyError::Read`; nonempty data resets that counter.
/// A failed inspection is terminal: the host must refuse the plan before dispatch.
#[non_exhaustive]
pub struct GatewayBody {
    stream: GatewayBodyStream,
    inspected: VecDeque<GatewayBodyFrame>,
    inspected_bytes: usize,
    max_bytes: usize,
    idle_timeout: Duration,
    ended: bool,
    failed: Option<GatewayBodyError>,
    non_data_frames: u8,
}
impl fmt::Debug for GatewayBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayBody")
            .field("inspected_bytes", &self.inspected_bytes)
            .field("max_bytes", &self.max_bytes)
            .finish_non_exhaustive()
    }
}
impl GatewayBody {
    pub(crate) fn new(stream: GatewayBodyStream, max_bytes: usize, idle_timeout: Duration) -> Self {
        Self {
            stream,
            inspected: VecDeque::new(),
            inspected_bytes: 0,
            max_bytes,
            idle_timeout,
            ended: false,
            failed: None,
            non_data_frames: 0,
        }
    }
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
    pub fn inspected_bytes(&self) -> usize {
        self.inspected_bytes
    }
    /// EOF was observed without failure and all nonempty data and trailer frames
    /// are retained. This query never polls the unread source.
    pub fn is_complete(&self) -> bool {
        self.ended && self.failed.is_none()
    }
    /// Reads the next frame, retaining nonempty data and trailers for forwarding.
    /// More than 32 consecutive empty data or trailer frames fail with `Read`.
    pub async fn next_frame(&mut self) -> Result<Option<GatewayBodyFrame>, GatewayBodyError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.ended {
            return Ok(None);
        }
        let next = match tokio::time::timeout(self.idle_timeout, self.stream.next()).await {
            Ok(next) => next,
            Err(_) => {
                self.failed = Some(GatewayBodyError::IdleTimeout);
                return Err(GatewayBodyError::IdleTimeout);
            }
        };
        match next {
            None => {
                self.ended = true;
                Ok(None)
            }
            Some(Err(error)) => {
                self.failed = Some(error);
                Err(error)
            }
            Some(Ok(frame)) => {
                let contributes_bytes =
                    matches!(&frame, GatewayBodyFrame::Data(bytes) if !bytes.is_empty());
                if contributes_bytes {
                    self.non_data_frames = 0;
                } else {
                    self.non_data_frames = self.non_data_frames.saturating_add(1);
                    if self.non_data_frames > 32 {
                        self.failed = Some(GatewayBodyError::Read);
                        return Err(GatewayBodyError::Read);
                    }
                }
                if let GatewayBodyFrame::Data(bytes) = &frame {
                    let total = self.inspected_bytes.checked_add(bytes.len());
                    if total.is_none_or(|total| total > self.max_bytes) {
                        self.failed = Some(GatewayBodyError::TooLarge);
                        return Err(GatewayBodyError::TooLarge);
                    }
                    self.inspected_bytes = total.expect("checked above");
                }
                if !matches!(&frame, GatewayBodyFrame::Data(bytes) if bytes.is_empty()) {
                    self.inspected.push_back(frame.clone());
                }
                Ok(Some(frame))
            }
        }
    }
    pub(crate) fn into_stream(self) -> GatewayBodyStream {
        if let Some(error) = self.failed {
            return Box::pin(futures_util::stream::once(async move { Err(error) }));
        }
        if self.ended {
            return Box::pin(futures_util::stream::iter(
                self.inspected.into_iter().map(Ok),
            ));
        }
        Box::pin(futures_util::stream::iter(self.inspected.into_iter().map(Ok)).chain(self.stream))
    }
    pub(crate) fn is_empty_complete(&self) -> bool {
        self.is_complete() && self.inspected.is_empty()
    }
    pub(crate) fn failure(&self) -> Option<GatewayBodyError> {
        self.failed
    }
}

/// Recovery is never inferred from an HTTP method or a replayable body.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayReplayProfile {
    /// No application-level resubmission. Safe connection recovery is host-owned.
    Never,
    /// The host may replace an OAuth lease and retry discovery once only after
    /// proving complete EOF with no retained data or trailer frames.
    BodylessCredentialRecovery,
    /// Permission, not a promise of resubmission: the host also needs complete
    /// safely retained request bytes and request-specific transport evidence
    /// of non-processing. Replayability, a method, timeout, reset or bare GOAWAY
    /// never establishes that evidence. A host without such evidence retries
    /// nothing; ordinary safe connection recovery remains independent.
    ConfirmedUnprocessed,
}

/// Explicit finite response-header selections. Host reserved-header checks always apply.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct GatewayResponseProfile {
    pub headers: Vec<String>,
    pub status_headers: Vec<GatewayStatusHeaders>,
    pub translate_unauthorized: bool,
    pub reject_redirects: bool,
    pub preserve_content_length: bool,
    /// On 429 only, let the host emit its bounded whole-second Retry-After.
    pub bounded_retry_after: bool,
    pub validator: Option<Arc<dyn GatewayResponseValidator>>,
}
impl GatewayResponseProfile {
    pub fn new(headers: Vec<String>) -> Self {
        Self {
            headers,
            status_headers: Vec::new(),
            translate_unauthorized: false,
            reject_redirects: false,
            preserve_content_length: false,
            bounded_retry_after: false,
            validator: None,
        }
    }
    pub fn with_status_headers(mut self, headers: Vec<GatewayStatusHeaders>) -> Self {
        self.status_headers = headers;
        self
    }
    pub fn translate_unauthorized(mut self) -> Self {
        self.translate_unauthorized = true;
        self
    }
    pub fn reject_redirects(mut self) -> Self {
        self.reject_redirects = true;
        self
    }
    pub fn preserve_content_length(mut self) -> Self {
        self.preserve_content_length = true;
        self
    }
    pub fn bounded_retry_after(mut self) -> Self {
        self.bounded_retry_after = true;
        self
    }
    pub fn with_validator(mut self, validator: Arc<dyn GatewayResponseValidator>) -> Self {
        self.validator = Some(validator);
        self
    }
}
/// Bounded response metadata validation, with no body, credential or transport access.
/// The result is an upstream-value-preserving filter. The host checks all returned
/// names against the profile and reserved fields and requires every returned
/// value to equal the upstream field values. Framing remains host-owned.
pub trait GatewayResponseValidator: fmt::Debug + Send + Sync {
    fn validate(&self, status: u16, headers: &HeaderMap) -> Result<HeaderMap, ProviderError>;
}
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayStatusMatch {
    /// An exact status from 100 through 599, checked by the host.
    Exact(u16),
    /// A status class from 1 through 5; `Class(2)` selects 2xx. Exact selection
    /// wins over class selection, which wins over `Default`.
    Class(u16),
    Default,
}
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct GatewayStatusHeaders {
    pub status: GatewayStatusMatch,
    pub headers: Vec<String>,
}
impl GatewayStatusHeaders {
    pub fn new(status: GatewayStatusMatch, headers: Vec<String>) -> Self {
        Self { status, headers }
    }
}

#[non_exhaustive]
pub struct GatewayForwardPlan {
    pub method: Method,
    pub relative_target: String,
    pub headers: HeaderMap,
    pub body: GatewayBody,
    pub response: GatewayResponseProfile,
    pub replay: GatewayReplayProfile,
    pub audit: Option<Value>,
    pub audit_target: Option<String>,
}
impl GatewayForwardPlan {
    pub fn new(method: Method, relative_target: impl Into<String>, body: GatewayBody) -> Self {
        Self {
            method,
            relative_target: relative_target.into(),
            headers: HeaderMap::new(),
            body,
            response: GatewayResponseProfile::new(vec!["content-type".into()]),
            replay: GatewayReplayProfile::Never,
            audit: None,
            audit_target: None,
        }
    }
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }
    pub fn with_response(mut self, profile: GatewayResponseProfile) -> Self {
        self.response = profile;
        self
    }
    pub fn with_replay(mut self, replay: GatewayReplayProfile) -> Self {
        self.replay = replay;
        self
    }
    pub fn with_audit(mut self, audit: Value) -> Self {
        self.audit = Some(audit);
        self
    }
    pub fn with_audit_target(mut self, target: impl Into<String>) -> Self {
        self.audit_target = Some(target.into());
        self
    }
}
impl fmt::Debug for GatewayForwardPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayForwardPlan")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

/// The host authorizes this action and these scopes before presenting a credential.
#[non_exhaustive]
#[derive(Clone)]
pub struct GatewayProbeRequest {
    pub action: String,
    pub scopes: ResourceScopes,
    pub normalized_input: String,
    pub relative_target: String,
    pub method: Method,
    pub headers: HeaderMap,
    pub max_response_bytes: usize,
    /// Bounded protocol facts stored under the registration's audit key.
    pub audit: Option<Value>,
    /// Optional safe path template for host transport diagnostics.
    pub audit_target: Option<String>,
}
impl fmt::Debug for GatewayProbeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayProbeRequest")
            .field("action", &self.action)
            .field("method", &self.method)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}
impl GatewayProbeRequest {
    pub fn new(
        action: impl Into<String>,
        scopes: ResourceScopes,
        normalized_input: impl Into<String>,
        relative_target: impl Into<String>,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            action: action.into(),
            scopes,
            normalized_input: normalized_input.into(),
            relative_target: relative_target.into(),
            method: Method::GET,
            headers: HeaderMap::new(),
            max_response_bytes,
            audit: None,
            audit_target: None,
        }
    }
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }
    pub fn with_audit(mut self, audit: Value) -> Self {
        self.audit = Some(audit);
        self
    }
    pub fn with_audit_target(mut self, target: impl Into<String>) -> Self {
        self.audit_target = Some(target.into());
        self
    }
}
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayProbeStatus {
    /// More bytes are needed. The host treats this at EOF or the probe byte cap
    /// as failed verification, never a successful or inconclusive result.
    NeedMore,
    Valid,
    Invalid,
}
pub trait GatewayVerificationProbe: fmt::Debug + Send + Sync {
    fn request(&self) -> &GatewayProbeRequest;
    fn validate_response(
        &self,
        status: u16,
        headers: &HeaderMap,
        prefix: &[u8],
        eof: bool,
    ) -> Result<GatewayProbeStatus, ProviderError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CredentialDescriptor, ServiceSurface};

    #[derive(Debug)]
    struct Fixture;
    fn parse(value: toml::Value) -> Result<Arc<dyn GatewayConfig>, String> {
        if value.as_table().is_none_or(|table| !table.is_empty()) {
            return Err("fixture gateway has no protocol settings".into());
        }
        Ok(Arc::new(Fixture))
    }
    static REGISTRATION: GatewayRegistration =
        GatewayRegistration::new(crate::module_metadata!(), "http_fixture", parse);
    impl GatewayConfig for Fixture {
        fn validate(&self, _: &GatewayServiceContext, _: &mut Vec<String>) {}
        fn descriptor(&self, context: &GatewayServiceContext) -> ServiceDescriptor {
            ServiceDescriptor::new(&context.service, &context.display_name)
                .with_surface(ServiceSurface::Gateway {
                    kind: "http_fixture".into(),
                    broker_hosts: context.broker_hosts.clone(),
                })
                .with_credentials(
                    CredentialDescriptor::without_execution_credential().without_verification(),
                )
        }
        fn build(
            &self,
            _: &GatewayServiceContext,
        ) -> Result<Arc<dyn GatewayProtocol>, ProviderBuildError> {
            Ok(Arc::new(Fixture))
        }
    }
    impl GatewayProtocol for Fixture {
        fn classify(
            &self,
            head: GatewayRequestHead<'_>,
        ) -> Result<GatewayClassification, ProviderError> {
            if head.path_and_query() != "/items" {
                return Err(ProviderError::deny(
                    ReasonCode::GatewayRuleNotFound,
                    "route not found",
                ));
            }
            Ok(GatewayClassification::new(
                "items.read",
                ResourceScopes::new(),
                "request",
                Box::new(Fixture),
            ))
        }
    }
    #[async_trait]
    impl GatewayRequest for Fixture {
        async fn preflight(
            self: Box<Self>,
            body: GatewayBody,
        ) -> Result<GatewayForwardPlan, ProviderError> {
            Ok(GatewayForwardPlan::new(Method::GET, "/items", body))
        }
    }
    #[tokio::test]
    async fn inspection_replays_frames_once_then_the_unread_remainder() {
        let frames = vec![
            Ok(GatewayBodyFrame::Data(Bytes::from_static(b"first"))),
            Ok(GatewayBodyFrame::Trailers),
            Ok(GatewayBodyFrame::Data(Bytes::from_static(b"last"))),
        ];
        let mut body = crate::test_support::gateway_body(frames, 16);
        assert!(matches!(
            body.next_frame().await.unwrap(),
            Some(GatewayBodyFrame::Data(_))
        ));
        assert!(matches!(
            body.next_frame().await.unwrap(),
            Some(GatewayBodyFrame::Trailers)
        ));
        let frames = crate::host::gateway_body_stream(body)
            .collect::<Vec<_>>()
            .await;
        assert_eq!(frames.len(), 3);
        assert!(matches!(&frames[0], Ok(GatewayBodyFrame::Data(bytes)) if bytes == "first"));
        assert!(matches!(&frames[1], Ok(GatewayBodyFrame::Trailers)));
        assert!(matches!(&frames[2], Ok(GatewayBodyFrame::Data(bytes)) if bytes == "last"));
    }
    #[tokio::test]
    async fn protocol_inspection_is_bounded() {
        let mut body = crate::test_support::gateway_body(
            vec![Ok(GatewayBodyFrame::Data(Bytes::from_static(b"over cap")))],
            3,
        );
        assert_eq!(
            body.next_frame().await.unwrap_err(),
            GatewayBodyError::TooLarge
        );
        assert_eq!(
            body.next_frame().await.unwrap_err(),
            GatewayBodyError::TooLarge
        );
        assert_eq!(
            crate::host::gateway_body_failure(&body),
            Some(GatewayBodyError::TooLarge)
        );
        assert!(!body.is_complete());
        let frames = crate::host::gateway_body_stream(body)
            .collect::<Vec<_>>()
            .await;
        assert_eq!(frames.len(), 1);
        assert!(matches!(frames[0], Err(GatewayBodyError::TooLarge)));
    }
    #[tokio::test]
    async fn failed_inspection_cannot_forward_a_prefix_or_poll_past_failure() {
        for failure in [
            GatewayBodyError::Read,
            GatewayBodyError::Timeout,
            GatewayBodyError::IdleTimeout,
        ] {
            let mut body = crate::test_support::gateway_body(
                vec![
                    Ok(GatewayBodyFrame::Data(Bytes::from_static(b"prefix"))),
                    Err(failure),
                    Ok(GatewayBodyFrame::Data(Bytes::from_static(
                        b"must-not-forward",
                    ))),
                ],
                128,
            );
            body.next_frame().await.unwrap();
            assert_eq!(body.inspected_bytes(), 6);
            assert!(!body.is_complete());
            assert_eq!(body.next_frame().await.unwrap_err(), failure);
            assert_eq!(body.next_frame().await.unwrap_err(), failure);
            let frames = crate::host::gateway_body_stream(body)
                .collect::<Vec<_>>()
                .await;
            assert_eq!(frames.len(), 1);
            assert!(matches!(frames[0], Err(error) if error == failure));
        }
    }
    #[tokio::test]
    async fn complete_body_proof_requires_eof_and_retains_every_byte() {
        let mut empty = crate::test_support::gateway_body(Vec::new(), 16);
        assert!(!crate::host::gateway_body_is_empty_complete(&empty));
        assert!(empty.next_frame().await.unwrap().is_none());
        assert!(crate::host::gateway_body_is_empty_complete(&empty));
        let mut body = crate::test_support::gateway_body(
            vec![Ok(GatewayBodyFrame::Data(Bytes::from_static(b"data")))],
            16,
        );
        body.next_frame().await.unwrap();
        assert!(!body.is_complete());
        assert!(body.next_frame().await.unwrap().is_none());
        assert!(body.is_complete());
        assert_eq!(body.inspected_bytes(), 4);
        assert!(!crate::host::gateway_body_is_empty_complete(&body));
    }
    #[tokio::test]
    async fn empty_frames_cannot_grow_retention_or_extend_inspection_forever() {
        let mut body = crate::test_support::gateway_body(
            (0..33)
                .map(|_| Ok(GatewayBodyFrame::Data(Bytes::new())))
                .collect(),
            16,
        );
        for _ in 0..32 {
            body.next_frame().await.unwrap();
        }
        assert!(body.inspected.is_empty());
        assert_eq!(body.next_frame().await.unwrap_err(), GatewayBodyError::Read);
        assert_eq!(
            crate::host::gateway_body_failure(&body),
            Some(GatewayBodyError::Read)
        );
    }
    #[tokio::test]
    async fn a_complete_body_replays_without_repolling_a_non_fused_source() {
        let stream =
            futures_util::stream::unfold(Some(Bytes::from_static(b"0000")), |frame| async {
                frame.map(|bytes| (Ok(GatewayBodyFrame::Data(bytes)), None))
            });
        let mut body = crate::host::gateway_body(Box::pin(stream), 1024, Duration::from_secs(1));
        body.next_frame().await.unwrap().unwrap();
        assert!(body.next_frame().await.unwrap().is_none());
        assert!(body.is_complete());
        let frames = crate::host::gateway_body_stream(body)
            .collect::<Vec<_>>()
            .await;
        assert_eq!(frames.len(), 1);
        assert!(
            matches!(&frames[0], Ok(GatewayBodyFrame::Data(bytes)) if bytes == b"0000".as_slice())
        );
    }
    #[tokio::test]
    async fn bodyless_recovery_proof_rejects_trailers_without_data() {
        let mut body = crate::test_support::gateway_body(vec![Ok(GatewayBodyFrame::Trailers)], 16);
        body.next_frame().await.unwrap();
        assert!(body.next_frame().await.unwrap().is_none());
        assert!(body.is_complete());
        assert_eq!(body.inspected_bytes(), 0);
        assert!(!crate::host::gateway_body_is_empty_complete(&body));
    }
    #[test]
    fn upstream_faults_cannot_be_mislabeled_as_policy_denials() {
        for (phase, code) in [
            (GatewayHookPhase::Preflight, ReasonCode::UpstreamTimeout),
            (GatewayHookPhase::Verification, ReasonCode::UpstreamFailed),
            (GatewayHookPhase::Response, ReasonCode::UpstreamFailed),
            (
                GatewayHookPhase::Response,
                ReasonCode::UpstreamProtocolFailed,
            ),
        ] {
            assert!(
                REGISTRATION
                    .check_failure(phase, &ProviderError::deny(code, "invalid decision"))
                    .is_err()
            );
            assert!(
                REGISTRATION
                    .check_failure(phase, &ProviderError::error(code, "upstream failure"))
                    .is_ok()
            );
        }
        assert!(
            REGISTRATION
                .check_failure(
                    GatewayHookPhase::Response,
                    &ProviderError::deny(
                        ReasonCode::GatewayHeaderDenied,
                        "client status is not an upstream outcome"
                    )
                )
                .is_err()
        );
    }
    #[test]
    fn request_debug_omits_paths_queries_headers_scopes_and_probe_input() {
        let headers = HeaderMap::from_iter([(
            reqwest::header::AUTHORIZATION,
            "secret-header".parse().unwrap(),
        )]);
        let head = GatewayRequestHead::new(&Method::GET, "/secret-path?q=secret-query", &headers);
        let probe = GatewayProbeRequest::new(
            "items.read",
            ResourceScopes::from([("item".into(), vec!["secret-resource".into()])]),
            "secret-input",
            "/secret-path?q=secret-query",
            128,
        )
        .with_headers(headers.clone());
        for value in [format!("{head:?}"), format!("{probe:?}")] {
            assert!(!value.contains("secret-"), "{value}");
        }
    }
    #[test]
    fn module_failures_do_not_claim_host_auth_policy_or_accounting_outcomes() {
        for code in [
            ReasonCode::GatewayAuthInvalid,
            ReasonCode::ServiceActionDenied,
            ReasonCode::RateLimited,
            ReasonCode::BrokerTokenExpired,
        ] {
            assert!(
                REGISTRATION
                    .check_failure(
                        GatewayHookPhase::Classification,
                        &ProviderError::deny(code, "invalid module outcome")
                    )
                    .is_err()
            );
        }
        assert!(
            REGISTRATION
                .check_failure(
                    GatewayHookPhase::Classification,
                    &ProviderError::deny(ReasonCode::GatewayRuleNotFound, "route not found")
                )
                .is_ok()
        );
        assert_eq!(REGISTRATION.counted("request"), Some(true));
        assert_eq!(REGISTRATION.counted("undeclared"), None);
    }
    #[test]
    fn instances_share_kind_without_sharing_service_identity() {
        let first = GatewayServiceContext::new("first", "First", "https://api.example.com");
        let second = GatewayServiceContext::new("second", "Second", "https://api.example.com");
        assert_eq!(Fixture.descriptor(&first).service, "first");
        assert_eq!(Fixture.descriptor(&second).service, "second");
        assert!(
            !Fixture
                .descriptor(&first)
                .credentials
                .verification_supported
        );
    }
}
