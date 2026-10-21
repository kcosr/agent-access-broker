//! The Agent Access Broker provider SDK: the supported contract between the
//! Broker host and the native providers, OAuth companions and helper crates
//! that one Broker distribution links.
//!
//! # Supported surface
//!
//! Every public item is intentional and covered by the compatibility policy
//! below. The surface has these parts, and each item has exactly one path:
//!
//! - **The crate root** holds the provider contract. A backend declares a
//!   [`BackendRegistration`] whose [`BackendConfig`] strictly parses its
//!   `[providers.<kind>]` table, describes its service with a
//!   [`ServiceDescriptor`] and builds a [`Provider`] from a [`BuildContext`]
//!   for one runtime generation. The provider resolves an action's resources
//!   ([`ScopeRequest`], [`ScopeResolution`]), admits multipart body parts
//!   ([`BodyAdmission`]), verifies credentials and serves
//!   [`ProviderInvocation`]s with a [`ProviderResult`] or a [`ProviderError`];
//!   a write's [`MutationReceipt`] says whether a failed write applied.
//!   It reaches upstream services through the host services defined here:
//!   [`UpstreamClient`]s built through the host's client factory, upstream
//!   allowlists, correlation ([`InvocationScope`]), upstream trace events
//!   and authenticated continuation envelopes ([`ContinuationSigner`]). It turns
//!   lent [`ExecutionCredential`]s and [`DelegatedAccess`] into opaque
//!   [`UpstreamAuthorization`]s, in a [`CredentialPlacement`] when the
//!   upstream needs one, and hands them to the client's send methods with
//!   each request ([`UpstreamCall::with_authorization`]); it never reads the
//!   material or holds a request that carries it. An OAuth
//!   companion implements [`OAuthDialect`] and declares an
//!   [`OAuthDialectRegistration`]. Every registration records its declaring
//!   package with [`module_metadata!`].
//! - [`presentation`] holds response presentation: the
//!   [`ActionPresentation`](presentation::ActionPresentation) a descriptor
//!   attaches, the renderer traits, the shared render budget and the Markdown
//!   helpers renderers use.
//! - [`host`] holds the cooperation ports the Broker host implements and
//!   calls: the network factory contract, construction of admitted request
//!   values, the initial correlation, hook and deadline scopes, service-scoped
//!   signer wrapping, delegated-lease wrapping, the host-origin failure port
//!   and the host-only authorization of the host's own requests. Provider code
//!   consumes the capabilities they produce; provider tests may implement or
//!   call them, except the host-only request authorization.
//! - [`deps`] re-exports the third-party types and macros that supported
//!   signatures name (see [Third-party dependencies](#third-party-dependencies)).
//! - `test_support`, behind the `test-support` Cargo feature, holds
//!   deterministic doubles and builders for provider tests: a client factory,
//!   admitted-request and scope-request builders, credentials, signing keys,
//!   scoped trace capture and embedded TLS fixtures. It adds construction and
//!   control only; it never changes runtime behavior.
//!
//! The SDK depends on no Broker crate. It resolves no secret references, loads
//! no TLS files, reads no process environment and touches no store: the host
//! keeps those, together with identity, policy, credential selection, audit,
//! limits and network construction. Providers see only the narrow views here,
//! and no credential value has a plaintext accessor: the upstream client adds
//! credential material to the request it builds, immediately before dispatch.
//!
//! # Trust model
//!
//! This is a cooperation contract, not a sandbox. Every linked provider, OAuth
//! companion and import adapter runs in the Broker process and is trusted with
//! the whole deployment: process-accessible credentials, stores, files,
//! environment, network and audit state. The SDK's read-only authority values,
//! privately constructed credentials, network wrappers and reason validation
//! enforce the contract between cooperating modules and catch mistakes; they do
//! not stop deliberate bypass, such as another HTTP client or direct process
//! access, and Rust visibility cannot make the host a friend of SDK internals.
//! An assembler reviews and qualifies every module it links. Deploy mutually
//! untrusted modules in separate processes.
//!
//! # Reason model
//!
//! Every outcome carries one wire `reasonCode`. Standard reasons are the
//! [`ReasonCode`] vocabulary: each fixes its HTTP status, and providers may
//! report only a closed subset, each with the decisions and in the hook phases
//! ([`HookPhase`]) its contract allows ([`ReasonCode::permits_provider_failure`],
//! [`ReasonCode::permits_provider_allow`], [`ReasonCode::permits_late_stream`]).
//! A backend declares its own domain reasons as static
//! [`ProviderReasonDefinition`]s with a fixed decision and
//! [`ProviderFailureStatus`], lists them with
//! [`BackendRegistration::with_domain_reasons`] and reports them with
//! [`ProviderError::domain`]; their codes start with
//! [`domain_reason_prefix`] of the backend kind. A failure a host port
//! produced ([`host::port_failure`]) passes through provider code unchanged.
//! [`ProviderReason`] is the trusted handle errors, late stream failures and
//! trace classifications carry. The host checks every outcome at the hook
//! boundary ([`host::HookContext`]) and replaces one its contract does not
//! allow with `broker_provider_contract_failed`; records keep the code as a
//! bounded [`ReasonCodeId`] string, readable without the module that defined
//! it.
//!
//! # Continuations
//!
//! Resumable cursors, page tokens and handles use authenticated continuation
//! envelopes. A provider declares each token family as a
//! [`ContinuationFamily`] constant, binds every token to the admitted context
//! and its normalized settings with a [`ContinuationBinding`], and seals and
//! opens tokens with its [`ContinuationSigner`]. The binding authenticates the
//! token without appearing in it; confidential families also encrypt payloads.
//! A token never carries authority, and the host authorizes every continuation
//! again. [`ContinuationFailures`] reports each
//! [`ContinuationError`] as the provider's failure.
//!
//! # Compatibility
//!
//! The SDK, the Broker host crate's composition and test-support interfaces
//! and the shipped workspace packages share one release train and one package
//! version.
//! Within a compatible line, patch releases preserve these supported source
//! contracts, module acceptance and documented semantics. An incompatible
//! change advances the 0.x minor line (a future 1.x line uses major versions)
//! and is documented in the changelog; no old interface, alias or parallel
//! parser is kept. The implementable traits are [`Provider`],
//! [`BackendConfig`], [`OAuthDialect`], [`RedirectAuthorizer`], the
//! presentation codec and renderer traits, and the host's
//! [`UpstreamClientFactory`](host::UpstreamClientFactory),
//! [`StableSigningKey`] and [`DelegatedLease`] ports; adding a required method
//! to one is incompatible. A downstream module's domain reason inventory is
//! part of its own compatibility contract. There is no stable binary ABI:
//! a module update means rebuilding the distribution. The tested toolchain is
//! the repository's pinned one; no wider minimum Rust version is implied.
//!
//! Supported types are built through constructors and builders rather than
//! struct literals, so a compatible release can add fields:
//!
//! - static registrations and definitions, such as [`BackendRegistration`],
//!   [`ResourceTypeDescriptor`] and
//!   [`ActionPresentation`](presentation::ActionPresentation), have private
//!   fields, `const` builders and accessors;
//! - other data types are non-exhaustive and keep public fields only where
//!   they are the data the other side reads, such as [`ProviderResult`] and
//!   [`ServiceDescriptor`];
//! - extendable enums are non-exhaustive, and a match on one ends with an arm
//!   that rejects what the module does not support, such as an unknown
//!   [`StaticCredentialKind`], instead of treating it as success or as another
//!   variant.
//!
//! Data is read through those fields or inherent methods; no public trait
//! exists only for data access. Intentionally exhaustive items, such as
//! [`Decision`], [`CredentialMode`], [`ProviderFailureStatus`] and the shared
//! configuration tables (built from [`Default`] or deserialized), say so in
//! their documentation.
//!
//! # Third-party dependencies
//!
//! Supported signatures name types from these packages. An incompatible
//! release of one of them is an SDK compatibility event; re-exporting does not
//! make the contract independent of them. [`deps`] re-exports every
//! third-party type and macro a provider must name to implement the SDK
//! traits, under a module named after the defining package, so a provider can
//! build against the SDK's versions without naming them in its own manifest.
//!
//! | Package | Line | Items in supported signatures | Re-exported as |
//! | --- | --- | --- | --- |
//! | `async-trait` | 0.1 | the attribute that implements the async traits | [`deps::async_trait`] |
//! | `bytes` | 1 | `Bytes` | [`deps::bytes`] |
//! | `chrono` | 0.4 | `DateTime`, `Utc` | [`deps::chrono`] |
//! | `futures-core` | 0.3 | `Stream` | [`deps::futures_core`] |
//! | `http` | 1 | `Method`, `HeaderMap`, `HeaderName`, as `reqwest` re-exports them | [`deps::http`] |
//! | `reqwest` | 0.12 | `Body`, `Client`, `ClientBuilder`, `RequestBuilder`, `Response` | [`deps::reqwest`] |
//! | `serde_json` | 1 | `Map`, `Value` | [`deps::serde_json`] |
//! | `tokio` | 1 | `time::Instant`, `sync::watch::Receiver` | [`deps::tokio`] |
//! | `toml` | 0.9 | `de::Error`, `de::ValueDeserializer` | [`deps::toml`] |
//! | `url` | 2 | `Host`, `Url` | [`deps::url`] |
//! | `serde` | 1 | `Serialize`, `Deserialize` and `DeserializeOwned` implementations and bounds | not re-exported |
//! | `tracing` | 0.1 | `Span`, `Instrumented`, in `test_support` only | `deps::tracing` with `test-support` |
//!
//! `serde`'s derive macros expand to paths in the deriving crate's own `serde`
//! dependency, so a provider that derives its configuration depends on
//! `serde` 1 directly. A provider that needs more of a package than the
//! re-exported items, such as a `reqwest` status code or the `serde_json::json!`
//! macro, depends on the same semver line directly; Cargo then resolves one
//! copy.

mod admitted;
mod attribution;
mod authority;
mod authorization;
mod backend;
mod capabilities;
mod config;
mod continuation;
mod contract;
mod correlation;
mod credential;
mod delegated;
pub mod deps;
mod descriptor;
mod domain_reason;
mod egress_config;
mod error;
mod finalization;
pub mod host;
mod identifiers;
mod invocation;
mod lookup;
mod module;
mod mutation_receipt;
mod oauth_dialect;
pub mod presentation;
mod provider;
mod reason;
mod resource;
mod result;
mod scope;
mod search;
mod signing;
mod state;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
mod trace;
mod upstream;
mod upstream_allowlist;
mod upstream_rate_limit;
mod upstream_validation;

pub use admitted::{
    AdmittedContext, AdmittedRequest, AuthorityMismatch, InvocationAuthority, ProviderInvocation,
};
pub use attribution::{
    AttributionCapability, AttributionMutation, AttributionRepresentation, AttributionVerb,
    ProviderAttributionConfig, attribution_audit_applied, attribution_skip_target_absent_audit,
    matching_attribution_capabilities, merge_attribution_audit, validate_attribution_pattern,
};
pub use authority::UpstreamAuthority;
pub use authorization::{CredentialPlacement, CredentialPlacementError, UpstreamAuthorization};
pub use backend::{
    BackendConfig, BackendConfigParser, BackendRegistration, BuildContext, CredentialSource,
    ServiceCredentialKinds, ValidationContext, parse_backend_config,
};
pub use capabilities::{
    ActionCapabilities, ResourceScopeCapabilities, ServiceCapabilities, UpstreamResourceOwnership,
};
pub use config::{
    AttachmentLimitsConfig, ProviderLimits, SearchLimitsConfig, UrlPatternPolicy,
    default_attachment_max_bytes, default_attachment_max_total_bytes, default_download_max_bytes,
    is_env_name, is_literal_loopback, is_loopback_or_localhost, is_secret_ref,
    validate_attachment_limits, validate_egress_proxy_config, validate_formats_allow_empty,
    validate_non_empty_control_free_string, validate_provider_limit_relation,
    validate_provider_upload_limit_relation, validate_tenant_host, validate_upload_limits,
    validate_upstream_allowlist, validate_upstream_base_url, validate_url_patterns,
};
pub use continuation::{
    AdmissionStage, ContinuationBinding, ContinuationError, ContinuationFailures,
    ContinuationFamily, ContinuationLifetime, ContinuationOwner, ContinuationSigner,
    ContinuationStage, OpenedContinuation, ScopeResolutionStage, UPSTREAM_QUERY_COMMITMENT_BYTES,
};
pub use correlation::{
    BROKER_REQUEST_ID_HEADER, CorrelationContext, InvocationScope, REQUEST_ID_HEADER,
    current_correlation_context, current_provider_action,
};
pub use credential::{
    CredentialMode, ExecutionAccess, ExecutionCredential, StaticCredentialKind,
    UnsupportedCredentialMode,
};
pub use delegated::{
    DelegatedAccess, DelegatedAccessError, DelegatedBindingId, DelegatedCredential, DelegatedLease,
};
pub use descriptor::{
    ActionDescriptor, ActionIo, CredentialDescriptor, CredentialProfile, DelegatedConnection,
    HeaderEncoding, LookupRequirement, MultipartUploadSpec, NativeSearchEnforcement,
    RESULT_METADATA_HEADER, ScopedMcpNameSource, ServiceDescriptor, ServiceSurface,
    attachment_upload_plan, raw_download_io,
};
pub use domain_reason::{
    ProviderFailureStatus, ProviderReason, ProviderReasonDefinition, domain_reason_prefix,
};
pub use egress_config::{EgressDeclaration, EgressProxyConfig, EgressProxySource, EgressRoute};
pub use error::ProviderBuildError;
pub use finalization::{
    ProviderFinalizationContext, ProviderFinalizationGuard, current_provider_finalization,
};
pub use identifiers::{ResourceScopes, is_action_name, is_service_name};
pub use invocation::{
    BrokerBodyPart, BrokerBodyPartFile, BrokerBodyPartSpec, InvocationIdentity, SearchAuthorization,
};
pub use lookup::LookupAccess;
pub use module::{ModuleMetadata, SDK_PACKAGE};
pub use mutation_receipt::{MutationReceipt, MutationStatus};
pub use oauth_dialect::{
    AuthorizationRequest, CodeExchange, ConnectedIdentity, IssuedRefreshToken, LinkedIdentity,
    OAUTH_MAX_RESPONSE_BYTES, OAuthAdapter, OAuthCallbackIssuer, OAuthClient, OAuthClientAuth,
    OAuthDialect, OAuthDialectError, OAuthDialectRegistration, OAuthHttp, OAuthLoginBinding,
    OAuthLoginProvider, OAuthPermissionProfile, OAuthRegistrationConfig, OAuthResponse,
    OAuthRotation, OAuthScopeMode, OAuthTarget, OAuthTokenEncoding, OAuthTokenType,
    PreparedAuthorization, RefreshReplay, RevocationOutcome, TokenGrant, TokenRevocation,
};
pub use provider::{Provider, ServiceProvider};
pub use reason::{Decision, HookPhase, InvalidReasonCodeId, ReasonCode, ReasonCodeId};
pub use resource::{
    GIT_REPOSITORY_RESOURCE, NamespaceSelectorDescriptor, NamespaceSelectorMetadata,
    ResourceActionInputs, ResourceAttributeDescriptor, ResourceAttributeMetadata,
    ResourceAttributes, ResourcePattern, ResourceSelector, ResourceType, ResourceTypeDescriptor,
    ResourceTypeMetadata, ResourceTypeRegistry, is_canonical_repository_path,
    is_repository_selector_path,
};
pub use result::{
    BoundedDownload, ProviderByteStream, ProviderCredentialVerification, ProviderError,
    ProviderResult, ProviderResultStream, ProviderResultStreamSource, ProviderStreamError,
};
pub use scope::{ScopeRequest, ScopeResolution};
pub use search::{
    ExactSearchProjection, SearchAuthorizationClause, SearchAuthorizationScope,
    SearchProjectionError,
};
pub use signing::{SigningError, StableSigningKey};
pub use state::{BodyAdmission, ProviderState, ProviderStateError, StateDisposition};
pub use trace::{UpstreamTrace, emit_upstream_request_completed};
pub use upstream::{
    BodyReadError, ClientProfile, PendingUpstreamTrace, RedirectAuthorizer, RedirectRules,
    SharedBodyBudget, UploadProgress, UpstreamCall, UpstreamClient, UpstreamClientSpec,
    UpstreamError, UpstreamRequestBudget, complete_upstream_trace, file_upload_body,
    read_bounded_body, read_bounded_body_with_budget, take_upstream_trace,
};
pub use upstream_allowlist::{path_matches_pattern, same_origin, url_allowed_by_patterns};
pub use upstream_rate_limit::{
    UPSTREAM_RETRY_AFTER_MAX_SECONDS, UpstreamRetryAfter, mutation_unverified_after_throttling,
    mutation_unverified_after_throttling_message, upstream_rate_limited,
    upstream_rate_limited_message, upstream_retry_hint,
};
pub use upstream_validation::{
    VALIDATION_FIELD_MAX_BYTES, VALIDATION_FRAGMENT_MAX_BYTES, VALIDATION_MESSAGE_MAX_BYTES,
    VALIDATION_MESSAGE_MAX_PARTS, join_message_parts, push_message_part, read_validation_json,
    response_has_json_content_type, sanitize_field, sanitize_fragment,
};
