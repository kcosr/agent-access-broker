//! The host cooperation ports: what the Broker host implements and calls to
//! build providers and run their hooks.
//!
//! This module is public and supported, and it is a cooperation contract, not
//! a sandbox. Every module a distribution links is trusted with the whole
//! process; these ports keep cooperating modules on the documented path and
//! catch mistakes, but nothing here can prove which component called them.
//! Rust visibility cannot make the host a friend of SDK internals, so the
//! host-only constructors and scopes are public here, in one documented place,
//! instead of on the types they produce. A provider only consumes what they
//! produce; provider tests may implement or call them (`test_support` builds
//! on them).
//!
//! The ports are:
//!
//! - **The network factory contract**: [`UpstreamClientFactory`] builds each
//!   upstream client from a [`ClientTransportSpec`] and returns a
//!   [`TransportClient`] with its sanitized route, applying
//!   [`configure_client_profile`]. [`build_context`] lends the factory, the
//!   generation's limits, the active attribution and the optional
//!   service-scoped signing key to a backend's build.
//! - **Admitted request values**: [`scope_request`] for scope resolution,
//!   [`basic_credential`] and [`bearer_credential`] for static material,
//!   [`admitted_request`] for the admission decision, [`spooled_body_part`] and
//!   [`spooled_body_file`] for body parts the host spooled to disk, and
//!   [`invocation`] for the final invocation built after staging.
//! - **Initial scopes**: [`with_correlation_context`] and
//!   [`with_provider_context`] set the correlation and provider action that
//!   upstream requests carry; [`hook_context`] and [`with_hook_context`] run a
//!   provider hook whose outcomes the host then checks with its
//!   [`HookContext`] ([`ContractViolation`]); [`provider_finalization_context`]
//!   and [`with_provider_finalization`] set the operation deadline and its
//!   bounded finalization marker. [`InvocationScope`](crate::InvocationScope)
//!   carries all of them onto spawned work.
//! - **Signer wrapping**: [`service_signing_key`] scopes the host's stable key
//!   to one service.
//! - **Delegated-lease wrapping**: [`delegated_credential`] lends a host
//!   [`DelegatedLease`] to one invocation, under the
//!   [`delegated_binding_id`] the host derived for it.
//! - **The host-origin failure port**: [`port_failure`] marks a failure one of
//!   the [`HostPort`]s produced, which providers pass on unchanged.
//! - **Host request authorization**: [`authorize_host_request`] adds an
//!   [`UpstreamAuthorization`](crate::UpstreamAuthorization) to a request the
//!   host sends with its own client, such as the Git smart HTTP gateway's,
//!   and [`token_as_basic`] presents token material there as HTTP Basic with
//!   a configured username. Both are host-only: provider, adapter, reference
//!   and helper crates never use them, and
//!   `scripts/check-crate-boundaries.mjs` rejects them there.
//!
//! Nothing here resolves secret references, loads keys or TLS files, reads the
//! process environment or touches a store: those stay inside the host. Nothing
//! here returns credential material either. The host keeps the plaintext it
//! decrypts, and the credentials these ports build present it upstream only
//! as an [`UpstreamAuthorization`](crate::UpstreamAuthorization).
use crate::{
    AdmittedContext, AdmittedRequest, BrokerBodyPart, BrokerBodyPartFile, BuildContext,
    ClientProfile, CorrelationContext, CredentialMode, CredentialPlacement, Decision,
    DelegatedBindingId, DelegatedCredential, DelegatedLease, EgressDeclaration, EgressRoute,
    ExecutionAccess, ExecutionCredential, HookPhase, InvocationAuthority, InvocationIdentity,
    ProviderAttributionConfig, ProviderError, ProviderFinalizationContext, ProviderInvocation,
    ProviderLimits, ProviderReasonDefinition, ProviderState, ReasonCode, ResourceAttributes,
    ScopeRequest, StableSigningKey,
};
use serde_json::Value;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

pub use crate::contract::{ContractViolation, HookContext};
pub use crate::correlation::{with_correlation_context, with_provider_context};
pub use crate::finalization::with_provider_finalization;
pub use crate::signing::service_signing_key;

/// Constructs configured upstream HTTP clients for one runtime generation.
///
/// The host's implementation captures the generation's limits, outbound TLS
/// trust and proxy environment, together with the category of the caller it
/// serves: the host's OAuth manager, or one native registration with its
/// development-only marker. A spec's label or provider identity never changes
/// that category.
///
/// Every returned client applies the requested [`ClientProfile`] (see
/// [`configure_client_profile`]), never follows a redirect on its own, and is
/// routed as its [`EgressDeclaration`] asks. A route the host does not grant to
/// this caller fails construction instead of silently routing elsewhere.
pub trait UpstreamClientFactory: Send + Sync {
    /// Builds the client `spec` describes, or explains why the host refuses
    /// or cannot build it.
    fn build_client(
        &self,
        spec: &ClientTransportSpec<'_>,
    ) -> Result<TransportClient, UpstreamClientFactoryError>;
}

/// What one upstream client needs from the host transport. The SDK builds it
/// from an [`UpstreamClientSpec`](crate::UpstreamClientSpec); a factory only
/// reads it.
#[derive(Debug, Clone, Copy)]
pub struct ClientTransportSpec<'a> {
    label: &'a str,
    provider: &'static str,
    base: &'a Url,
    egress: EgressDeclaration<'a>,
    profile: ClientProfile,
}

impl<'a> ClientTransportSpec<'a> {
    pub(crate) fn new(
        label: &'a str,
        provider: &'static str,
        base: &'a Url,
        egress: EgressDeclaration<'a>,
        profile: ClientProfile,
    ) -> Self {
        Self {
            label,
            provider,
            base,
            egress,
            profile,
        }
    }

    /// The configuration path naming the client in diagnostics, such as
    /// `providers.jira.egress_proxy`. It is safe to show and decides nothing.
    pub fn label(&self) -> &'a str {
        self.label
    }

    /// The `provider` the client's traces record. It decides nothing.
    pub fn provider(&self) -> &'static str {
        self.provider
    }

    /// The service's base URL, whose origin the route is selected for.
    pub fn base(&self) -> &'a Url {
        self.base
    }

    /// The route the provider asks for; the factory decides whether this
    /// caller may have it.
    pub fn egress(&self) -> EgressDeclaration<'a> {
        self.egress
    }

    /// The time and retry profile the client must apply.
    pub fn profile(&self) -> ClientProfile {
        self.profile
    }
}

/// A configured client and the sanitized route its traffic takes.
#[derive(Debug, Clone)]
pub struct TransportClient {
    client: reqwest::Client,
    route: EgressRoute,
}

impl TransportClient {
    /// A client the factory configured, with the route its traffic takes.
    pub fn new(client: reqwest::Client, route: EgressRoute) -> Self {
        Self { client, route }
    }

    /// The client and its route, for the SDK's upstream client wrapper.
    pub fn into_parts(self) -> (reqwest::Client, EgressRoute) {
        (self.client, self.route)
    }
}

/// Why the host could not construct a client. Providers treat the cause as
/// opaque; the host recovers its own diagnostics from it.
pub struct UpstreamClientFactoryError(Box<dyn Error + Send + Sync>);

impl UpstreamClientFactoryError {
    /// Wraps the host's own cause, which travels to the host's diagnostics
    /// as the source of the provider's build error.
    pub fn new(cause: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self(cause.into())
    }

    /// The host's cause.
    pub fn into_cause(self) -> Box<dyn Error + Send + Sync> {
        self.0
    }
}

impl fmt::Debug for UpstreamClientFactoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("UpstreamClientFactoryError")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for UpstreamClientFactoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Error for UpstreamClientFactoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

/// The context a backend builds its provider from for one runtime generation:
/// the generation's limits, the client factory serving this backend, the
/// attribution its configuration activates and the optional stable signing
/// key, which must already be scoped to the backend's service with
/// [`service_signing_key`].
pub fn build_context<'a>(
    limits: &'a ProviderLimits,
    clients: &'a dyn UpstreamClientFactory,
    attribution: ProviderAttributionConfig,
    stable_signing_key: Option<Arc<dyn StableSigningKey>>,
) -> BuildContext<'a> {
    BuildContext {
        limits,
        clients,
        attribution,
        stable_signing_key,
    }
}

/// Applies `profile`'s time bounds and retry policy, measured against
/// `limits`, and disables automatic redirects. Every
/// [`UpstreamClientFactory`] applies it to the clients it builds.
pub fn configure_client_profile(
    builder: reqwest::ClientBuilder,
    profile: ClientProfile,
    limits: &ProviderLimits,
) -> reqwest::ClientBuilder {
    let timeout = Duration::from_millis(limits.request_timeout_ms);
    let builder = builder.redirect(reqwest::redirect::Policy::none());
    match profile {
        ClientProfile::Request => builder.timeout(timeout),
        ClientProfile::SingleAttempt => builder.timeout(timeout).retry(reqwest::retry::never()),
        ClientProfile::Stream => builder,
        ClientProfile::Upload => builder.connect_timeout(timeout),
        ClientProfile::Bounded { total, connect } => builder
            .timeout(total)
            .connect_timeout(connect)
            .retry(reqwest::retry::never()),
    }
}

/// The host's inputs for one scope-resolution request: validated inputs, the
/// host-selected execution context, minimal identity, correlation and the
/// lookup credential the host selected, if any.
///
/// Intentionally exhaustive: the host supplies every input, so a new one
/// fails to compile until the host provides it.
#[derive(Debug, Clone, Copy)]
pub struct ScopeRequestParts<'a> {
    pub service: &'a str,
    pub action: &'a str,
    pub inputs: &'a Value,
    pub execution_context: &'a str,
    pub identity: &'a InvocationIdentity,
    pub correlation: &'a CorrelationContext,
    pub lookup_credential: Option<&'a ExecutionCredential>,
}

/// The request a provider's scope resolution receives. It carries no admitted
/// authority and no execution credential.
pub fn scope_request(parts: ScopeRequestParts<'_>) -> ScopeRequest<'_> {
    let ScopeRequestParts {
        service,
        action,
        inputs,
        execution_context,
        identity,
        correlation,
        lookup_credential,
    } = parts;
    ScopeRequest {
        service,
        action,
        inputs,
        execution_context,
        identity,
        correlation,
        lookup_credential,
    }
}

/// A `basic_api_token` credential from the host's validated material.
pub fn basic_credential(username: String, token: String) -> ExecutionCredential {
    ExecutionCredential::basic(username, token)
}

/// A `bearer_token` credential from the host's validated material.
pub fn bearer_credential(token: String) -> ExecutionCredential {
    ExecutionCredential::bearer(token)
}

/// The host's admission decision for one operation: the admitted context, the
/// validated inputs and the execution and lookup material it selected.
///
/// Intentionally exhaustive: the host supplies every input, so a new one
/// fails to compile until the host provides it.
#[derive(Debug)]
pub struct AdmittedRequestParts {
    pub service: String,
    pub action: String,
    pub execution_context: String,
    pub identity: InvocationIdentity,
    pub correlation: CorrelationContext,
    pub credential_mode: CredentialMode,
    /// Built from the action's validated contract, never from provider
    /// output alone.
    pub authority: InvocationAuthority,
    pub inputs: Value,
    pub execution: ExecutionAccess,
    pub lookup_credential: Option<ExecutionCredential>,
}

/// The read-only admitted request that multipart admission receives and the
/// final invocation is built from.
pub fn admitted_request(parts: AdmittedRequestParts) -> AdmittedRequest {
    let AdmittedRequestParts {
        service,
        action,
        execution_context,
        identity,
        correlation,
        credential_mode,
        authority,
        inputs,
        execution,
        lookup_credential,
    } = parts;
    AdmittedRequest::new(
        AdmittedContext::new(
            service,
            action,
            execution_context,
            identity,
            correlation,
            credential_mode,
            authority,
        ),
        inputs,
        execution,
        lookup_credential,
    )
}

/// A body part the host spooled to `path` while consuming the request body,
/// with its measured size and SHA-256. The part owns the file: dropping the
/// last handle deletes it.
pub fn spooled_body_part(
    name: String,
    file_name: Option<String>,
    content_type: Option<String>,
    path: PathBuf,
    size: u64,
    sha256: String,
) -> BrokerBodyPart {
    BrokerBodyPart::from_temp_file(name, file_name, content_type, path, size, sha256)
}

/// The owning handle of a file the host spooled to `path`, with its measured
/// size and SHA-256. Dropping it deletes the file.
pub fn spooled_body_file(path: PathBuf, size: u64, sha256: String) -> BrokerBodyPartFile {
    BrokerBodyPartFile::new(path, size, sha256)
}

/// The final invocation, built only after staging: body consumption, the
/// revision fences, and decryption of only the admitted resource's
/// attributes.
pub fn invocation(
    request: AdmittedRequest,
    body_parts: Vec<BrokerBodyPart>,
    resource_attributes: ResourceAttributes,
    state: Option<ProviderState>,
) -> ProviderInvocation {
    ProviderInvocation::new(request, body_parts, resource_attributes, state)
}

/// A delegated credential lending `lease` to one invocation. The host has
/// already acquired the lease under its binding identity and revalidates it
/// immediately before dispatch.
pub fn delegated_credential(lease: Arc<dyn DelegatedLease>) -> DelegatedCredential {
    DelegatedCredential::new(lease)
}

/// A delegated binding identity from the host's domain-separated digest of
/// the lease's binding fields.
pub fn delegated_binding_id(digest: [u8; 32]) -> DelegatedBindingId {
    DelegatedBindingId::from_digest(digest)
}

/// A host cooperation port whose failures reach providers, which pass them on
/// unchanged. Each port has an exact allowlist of decisions and reasons.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostPort {
    /// [`DelegatedLease`]: acquiring, revalidating,
    /// rejecting and recovering a delegated credential.
    DelegatedLease,
    /// The admitted operation the host hands a provider: its authority
    /// accessors and its provider state. A provider that asks for an
    /// authority its action was not admitted with
    /// ([`AuthorityMismatch`](crate::AuthorityMismatch)), or finds its own
    /// state missing or of another type
    /// ([`ProviderStateError`](crate::ProviderStateError)), passes on
    /// `broker_provider_contract_failed` with its diagnostic code.
    AdmittedOperation,
}

impl HostPort {
    /// Whether a failure from this port may carry `reason` with `decision`.
    pub fn permits(self, decision: &Decision, reason: ReasonCode) -> bool {
        match self {
            Self::DelegatedLease => matches!(
                (decision, reason),
                (
                    Decision::Error,
                    ReasonCode::UpstreamConnectionFailed
                        | ReasonCode::UpstreamProtocolFailed
                        | ReasonCode::UpstreamRateLimited
                        | ReasonCode::ConcurrencyLimited
                ) | (
                    Decision::Deny,
                    ReasonCode::VersionConflict | ReasonCode::CredentialInvalid
                )
            ),
            Self::AdmittedOperation => matches!(
                (decision, reason),
                (Decision::Error, ReasonCode::BrokerProviderContractFailed)
            ),
        }
    }
}

/// The context of one provider hook the host runs: its service and action,
/// the hook phase, and the domain reasons the service's backend registered
/// (none for an imported service), pinned with the prepared operation.
pub fn hook_context(
    service: impl Into<String>,
    action: impl Into<String>,
    phase: HookPhase,
    domain_reasons: &'static [&'static ProviderReasonDefinition],
) -> HookContext {
    HookContext::new(service.into(), action.into(), phase, domain_reasons)
}

/// The deadline and bounded finalization marker of one provider execution.
/// Run the execution inside it with [`with_provider_finalization`]; the
/// provider reads it with
/// [`current_provider_finalization`](crate::current_provider_finalization).
pub fn provider_finalization_context(
    deadline: Option<tokio::time::Instant>,
) -> ProviderFinalizationContext {
    ProviderFinalizationContext::new(deadline)
}

/// Runs `future` as the provider hook `context` describes. Its service and
/// action become the current provider action, and upstream traces it starts,
/// including from work it moves onto other tasks with
/// [`InvocationScope`](crate::InvocationScope), are checked against it.
pub async fn with_hook_context<F: std::future::Future>(
    context: HookContext,
    future: F,
) -> F::Output {
    crate::correlation::with_hook(context, future).await
}

/// Marks `error` as a failure `port` produced. Its decision and reason are
/// then fixed: a provider that returns it passes the host's failure on, such
/// as a delegated lease's `concurrency_limited` while a refresh is in
/// progress, which ordinary provider errors cannot report. Message, result
/// and audit fields stay editable.
///
/// Only a host implementing `port` calls this. Origin is a cooperation
/// contract between trusted modules, not proof of which component built the
/// value. A domain failure, or an allow outcome, is returned unchanged.
pub fn port_failure(port: HostPort, error: ProviderError) -> ProviderError {
    error.into_host_origin(port)
}

/// Host-only: `request` with `authorization`'s header, replacing any value it
/// already has for that header, for a request the host sends with its own
/// client rather than through an [`UpstreamClient`](crate::UpstreamClient),
/// such as the Git smart HTTP gateway's. Material no header value can hold
/// makes the request fail to build, as reqwest's `bearer_auth` would.
///
/// The returned request carries the credential. Provider, adapter, reference
/// and helper code never calls this: it presents credentials only through the
/// upstream client's send methods
/// ([`UpstreamCall::with_authorization`](crate::UpstreamCall::with_authorization)),
/// and `scripts/check-crate-boundaries.mjs` rejects any use in those crates.
pub fn authorize_host_request(
    request: reqwest::RequestBuilder,
    authorization: &crate::UpstreamAuthorization,
) -> reqwest::RequestBuilder {
    authorization.apply_to_builder(request)
}

/// Host-only: the placement presenting token material, a `bearer_token`
/// credential's token or delegated access, as
/// `Authorization: Basic <base64 of username:token>` under `username`, for an
/// upstream that accepts tokens only as HTTP Basic, such as a Git smart HTTP
/// server behind the gateway. Present it with
/// [`ExecutionCredential::authorization_as`] or
/// [`DelegatedAccess::authorization_as`](crate::DelegatedAccess::authorization_as),
/// then attach the result with [`authorize_host_request`].
///
/// The placement checks before presenting anything. `username` must be 1 to
/// 64 printable ASCII characters (space through `~`) without a colon, and the
/// token 1 to 32,768 visible ASCII characters, as
/// [`CredentialPlacement::bearer`] requires; otherwise presentation fails with
/// [`InvalidMaterial`](crate::CredentialPlacementError::InvalidMaterial). A
/// `basic_api_token` credential fails with
/// [`KindMismatch`](crate::CredentialPlacementError::KindMismatch): it
/// presents its own stored username through
/// [`ExecutionCredential::authorization`]. The header is sensitive, and the
/// resulting authorization exposes nothing, like every presented credential.
///
/// Provider, adapter, reference and helper code never uses this: a provider
/// presents credentials in their own scheme or in a placement of its own, and
/// `scripts/check-crate-boundaries.mjs` rejects any use in those crates.
pub fn token_as_basic(username: impl Into<String>) -> CredentialPlacement {
    CredentialPlacement::token_as_basic(username.into())
}
