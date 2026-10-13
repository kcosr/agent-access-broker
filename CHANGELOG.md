# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Breaking Changes

- The native provider contract changes, so existing provider implementations must be
  updated:
  - **Scope resolution.** `Provider::resolve_scopes`, `resolve_scopes_with_lookup`
    and `resolve_scopes_with_lookup_context` are replaced by one required
    `async fn resolve_scopes(&self, request: ScopeRequest<'_>) -> Result<ScopeResolution, ProviderError>`.
    `ScopeRequest` carries the action, validated inputs, host-selected execution
    context, minimal identity, correlation and an optional host-selected lookup
    credential. `ScopeResolution` returns canonical resource scopes
    (`resources`/`no_resources`) and optional provider state (`with_state`).
  - **Provider state.** JSON `provider_preflight` is replaced by the in-process
    `ProviderState` (typed `new`, `downcast_ref`, `require` and `optional`, with
    redacted Debug). Missing or wrongly typed state fails closed as a contract
    failure.
  - **Body admission.** Multipart admission
    (`authorize_body_parts(&AdmittedRequest, Option<&ProviderState>)`) returns
    `BodyAdmission::new(specs, StateDisposition::{Keep, Replace(..), Clear})`;
    the disposition is explicit and never inferred.
  - **Admitted invocation.** Invocations carry a read-only admitted context with
    a typed `CredentialMode` (`Service`/`PerUser`; external spellings unchanged)
    and an exact `InvocationAuthority` (`ActionOnly`, `Resources` or `Search`).
    `ProviderInvocation` has private fields read through accessors.
  - **Live values are no longer serializable.** Live invocation, credential,
    stream and preflight values no longer implement `Serialize`/`Deserialize`.
    `SearchAuthorization` no longer carries a credential mode, and the lossy
    all-except-to-`"*"` helper is removed from the provider API.
  - **Execution credentials.** These are typed and privately constructed:
    `ExecutionCredential::view()` yields `CredentialView::Basic { username, token }`
    or `Bearer { token }`, with redacted Debug. Execution material is selected
    through `ExecutionAccess::{None, Static, Delegated}`. Lookup credentials are
    static-only. Stored credential rows and the `basic_api_token`/`bearer_token`
    kind spellings are unchanged, so stored credentials keep working.
  - **Delegated leases.** `DelegatedLease` gains the required
    `binding_identity() -> DelegatedBindingId`. The identity survives routine
    refresh, and changes on new consent, replacement or reconnect.

- OAuth loopback exceptions now require a literal IPv4/IPv6 loopback address.
  `http://localhost` is rejected for MCP OAuth endpoints and OAuth destinations;
  use `http://127.0.0.1` or `http://[::1]` with `allow_insecure_loopback = true`.
  `https://localhost` and every other host name now follow the global egress
  proxy resolution instead of connecting directly. Each approved OAuth
  destination origin is routed independently.
- The provider SDK (`agent-access-provider`) no longer exports host network
  plumbing. `PreparedOutboundTls`, `OutboundTlsConfig`, `OutboundTlsTrustMode`,
  `parse_strict_certificate_pem_bundle`, `EgressProxyEnvironment`,
  `EgressProxyRuntimeConfig`, `EgressProxySelection`, `EgressProxyMode`,
  `apply_reqwest_proxy`, `preflight_egress_proxy`, `load_secret_ref_value`,
  `ConfigError` and `UpstreamNetwork` are removed; the TLS, configuration-error
  and secret-reference items now live in `agent-access-core`. Backends build
  clients with `UpstreamClient::build(spec, host.clients())`, where the new
  `host` module's `UpstreamClientFactory` is implemented by the Broker host,
  `UpstreamClientSpec::egress` takes an `EgressDeclaration`, and
  `UpstreamClient::egress_route` returns a sanitized `EgressRoute`.
  `BuildContext` has private fields with accessors and is constructed by
  `host::build_context`; provider tests use `test_support::TestHost`, which
  replaces `test_support::test_outbound_tls`.
- `HostError` is replaced by `ProviderBuildError` in `BackendConfig::build`,
  `ImportedAdapter::build` and `OAuthHttp::build`. It carries safe
  configuration diagnostics; host network failures keep their cause for the
  Broker's own diagnostics.
- The development `oauth_stub` OAuth test-records service now requires an
  explicit `[providers.oauth_stub]` table with a `base_url` naming the records
  API, which must be a literal loopback IP origin (for example
  `http://127.0.0.1:8099`). A `[credentials.per_user.oauth_stub]` OAuth binding
  no longer creates the service implicitly or borrows the `stub` registration's
  `base_url`; configure both, pointing at the same test server. The fixture
  still requires a non-production deployment with
  `deployment.enable_fake_service = true`.
- Import administration responses (`GET /v1/admin/imports`, import inspect,
  preview and mutation results) replace `oauthRegistrations` with
  `importAuthentication`: one entry per selected import kind with an OAuth
  companion, carrying `importKind`, `dialectId` and its approved
  `registrations` (possibly empty). Registrations no longer carry `adapterId`.
- The import adapter contract (`ImportedAdapter`, imported definitions and
  bounded import schemas) moved from `agent-access-provider` to core's internal
  `imports` module. `BrokerCompositionBuilder::import_adapter` takes the opaque
  `ImportedAdapterRegistration` returned by
  `agent_access_mcp_upstream::registration()` and
  `agent_access_openapi_upstream::registration()`; `McpAdapter`,
  `OpenApiAdapter` and `MCP_OAUTH_DIALECT` are no longer exported, and the MCP
  registration supplies the `mcp_oauth` dialect. Selecting that dialect again
  with `.oauth(..)` is rejected as a duplicate.
- Gateway names may no longer match any native provider kind the binary
  selects, even without a `[providers.<kind>]` table; previously only
  configured providers and development kinds were reserved. Rename a
  `[gateways.<name>]` entry called `jira`, `confluence`, `gitlab`,
  `cloudbees_ci`, `gmail`, `teams` or `oauth_stub` (`fake` was already
  reserved). A native provider registration with kind `broker` is rejected when
  the binary's registry is built, even if never configured.
- `BackendRegistration` and `OAuthDialectRegistration` are non-exhaustive with
  private fields. Declare them with the `const` constructors
  (`BackendRegistration::new(module_metadata!(), kind, parser)` with
  `.with_resource_types(..)` and `.development_only()`, and
  `OAuthDialectRegistration::new(module_metadata!(), id, dialect)`) and read
  them through accessors such as `kind()`, `resource_types()`,
  `is_development_only()`, `parse_config()`, `id()` and `dialect()`. Each
  registration, including an `ImportedAdapterRegistration`, records its
  declaring package's name and version as `ModuleMetadata`.
- Response envelopes (`ResponseEnvelope::reason_code`) and audit records
  (`AuditRecord::reason_code`) carry reasons as a validated `ReasonCodeId`
  string instead of the `ReasonCode` enum, so records written with a reason
  from a module that is no longer linked stay readable. The wire spelling is
  unchanged; compare with `ReasonCodeId::standard()` or
  `ReasonCodeId::from(ReasonCode::…)`.
- `ReasonCode::CloudbeesCiLogChunkExceeded` and
  `ReasonCode::CloudbeesCiLogScanExceeded` are removed from the standard
  vocabulary. CloudBees CI now declares `cloudbees_ci_log_chunk_exceeded` and
  `cloudbees_ci_log_scan_exceeded` as its own domain reasons
  (`CLOUDBEES_CI_LOG_CHUNK_EXCEEDED`, `CLOUDBEES_CI_LOG_SCAN_EXCEEDED`); their
  wire spelling, `decision = deny`, HTTP 413, and CLI exit 2 are unchanged.
- `ProviderError`'s decision and reason are private and fixed at construction;
  read them with `decision()` and `reason_code()`, which returns a
  `ProviderReason` handle (a standard reason, a backend's registered domain
  reason, or a host port's failure). `ProviderStreamError::reason_code`,
  `UpstreamTrace::reason_code`, `complete_upstream_trace` and
  `PendingUpstreamTrace::complete` take a `ProviderReason`; convert standard
  reasons with `.into()`.
- `GET /v1/broker/status` and `agent-access broker status` return an explicit
  identity structure instead of `brokerVersion`, `buildCommit` and
  `buildProvenance`, which are removed. The response now has `assembly`
  (`name`, `version`, `qualification`, `source`), `host` and `sdk` (`crate`,
  `version`, `source`), `modules` (every compiled module package with its
  `crate`, `version`, sorted `roles` of `native`, `oauth` or `import`, and
  `source`), `inventoryFingerprint`, `catalogVersion` and `sendSchemaVersion`.
  Each `source` is `{"revision", "provenance"}` with `provenance` `evidence`,
  `declared`, or `unavailable` (with `revision: null`). A release build of
  `agent-access-broker` reports its commit as `evidence` for the assembly, the
  host, the SDK and every module, where it previously reported
  `buildProvenance: "release"`; an unstamped build reports every source as
  `unavailable`. Authorization and `Cache-Control: no-store` are unchanged.
- The `broker_starting` log event replaces `brokerVersion`, `buildCommit` and
  `buildProvenance` with `assemblyName`, `assemblyVersion`,
  `assemblyProvenance`, `qualification`, `inventoryFingerprint` and, when a
  revision is supplied, `assemblyRevision`.
- `AssemblyIdentity` moves its build stamp to explicit source revisions:
  `with_release_commit` and `build_status()` are removed; use
  `with_source(SourceRevision::evidence(commit))` (or
  `SourceRevision::declared`), `with_host_source`, `with_sdk_source`,
  `with_qualification` and `with_module_provenance(&[ModuleProvenance::new(crate,
  version, revision)])`. `BrokerApplication::new` now returns
  `Result<BrokerApplication, CompositionError>` and rejects a malformed identity
  or a provenance map naming an unregistered package, repeating a package or
  giving it conflicting revisions; `main` returns the error to exit `3`.
  `BrokerApplication::status()` returns the derived `BrokerBuildStatus`, which
  is now opaque and serializable only. `BuildProvenance` is removed.
- Core's `StateLockSet::acquire_for_config`, `acquire_for_config_reusing` and
  `acquire_audit_for_config` take a `StateLockHolder` (program name, program
  version and node ID) in place of the node ID.
- The provider SDK lists its exports explicitly, and each supported item has
  one path. Presentation types and traits (`ActionPresentation`,
  `ReadContentFormat`, `ResponseFormat`, `ResponseOptions`,
  `ResponseCapabilities`, `EmbeddedBody`, `BodyPathSegment`,
  `EmbeddedBodyCodec`, `WholeResultRenderer`, `RenderContext`, `RenderError`,
  `RenderBudget`, `RenderBudgetExhausted`, `RenderedBody` and
  `PresentationBudget`) are no longer re-exported at the crate root; import
  them from `agent_access_provider::presentation`. Host-only constructors and
  scopes moved into the `host` module: `with_correlation_context`,
  `with_provider_context`, `with_provider_finalization`, `service_signing_key`,
  `HookContext` and `ContractViolation` keep their names there, while
  `DelegatedCredential::new`, `ProviderFinalizationContext::new`,
  `BrokerBodyPart::from_temp_file` and `BrokerBodyPartFile::new` are replaced by
  `host::delegated_credential`, `host::provider_finalization_context`,
  `host::spooled_body_part` and `host::spooled_body_file`. The
  `DEFAULT_MAX_HTTP_BODY_BYTES`, `DEFAULT_MAX_UPSTREAM_RESPONSE_BYTES`,
  `DEFAULT_REQUEST_TIMEOUT_MS` and `DEFAULT_STREAMING_IDLE_TIMEOUT_MS`
  constants (use `ProviderLimits::default()`), `default_search_max_results`
  (use `SearchLimitsConfig::default()`), `current_hook_context`,
  `apply_current_correlation_headers`, `is_reason_code_id`,
  `is_resource_type_id`, `is_repository_selector_segment` and
  `url_matches_allowed_pattern` are no longer public.
- Supported SDK types are built through constructors and builders, never
  struct literals, and extendable enums are non-exhaustive (see
  `api/README.md` for the policy and the intentionally exhaustive items).
  - Static definitions have private fields and `const` builders:
    `ResourceTypeDescriptor::new(id, label, plural_label, example, canonical)`
    with `.with_namespace(NamespaceSelectorDescriptor::new(..))`,
    `.with_attributes(&[ResourceAttributeDescriptor::required(..)])` and
    `.with_action_inputs(..)`, read through `id()`, `label()`, `namespace()`,
    `attributes()`, `action_inputs(selector)` and `is_valid`;
    `presentation::ActionPresentation::new(bodies, whole)` and
    `EmbeddedBody::new(owner_path, codec)`.
  - `UpstreamClientSpec::new(label, provider, base, egress, allowed_hosts,
    profile)` with `.with_status_reasons(..)`, and `RedirectRules::new(max,
    deadline, authorize)` with `.correlating_other_origins()`, `.with_vet(..)`
    and `.with_decorate(..)`, have private fields. `DelegatedAccess::new(token,
    target, audience, version, expires_at)` has private fields read through
    `token()`, `target()`, `audience()`, `version()` and `expires_at()`.
  - `ProviderResult::new(result)` with `.with_stream(..)`, `.with_audit(..)`,
    `.with_upstream(status, duration_ms)` and `.with_object_ids(..)`;
    `ProviderLimits::default()` with `.with_max_http_body_bytes(..)` and the
    other limit builders; `ServiceDescriptor::new(service, display_name)` with
    `.with_surface(..)`, `.with_resource_scopes(..)`, `.with_actions(..)`,
    `.with_credentials(..)` and `.with_presentation_body_limit(..)`;
    `TokenGrant::new(access_token, token_type, expires_in, refresh_token)` with
    `.with_scopes(..)` and `.with_supersedes_other_access(..)`;
    `ConnectedIdentity::new(display_name)` with `.with_subject(..)`;
    `OAuthTarget::new(id, audience, scopes)` with `.with_name(..)`. These and
    the other data types (`ActionDescriptor`, `CredentialDescriptor`,
    `MultipartUploadSpec`, `ResourceScopeCapabilities`, `AttributionCapability`,
    `ProviderCredentialVerification`, `ProviderStreamError`,
    `ProviderResultStream`, `UpstreamCall`, `UpstreamTrace`,
    `InvocationIdentity`, `SearchAuthorization`, `BrokerBodyPartSpec`,
    `BrokerBodyPart`, `CorrelationContext`, `ValidationContext`,
    `ServiceCredentialKinds`, `OAuthClient`, `AuthorizationRequest`,
    `CodeExchange`, `OAuthCallbackIssuer`, `PreparedAuthorization`,
    `RenderedBody`, `ResponseOptions`, `ResponseCapabilities`, `RenderContext`,
    the discovery projections and `test_support::BuiltClient`) keep their
    public fields but are non-exhaustive; each has a `new` constructor where
    downstream code builds it. Provider tests build in-memory body parts with
    `BrokerBodyPart::in_memory` under the `test-support` feature.
  - Non-exhaustive enums now include `ReasonCode`, `ResourceSelector`,
    `ActionIo`, `ServiceSurface`, `CredentialView`, `StaticCredentialKind`,
    `ExecutionAccess`, `InvocationAuthority`, `EgressDeclaration`,
    `ClientProfile`, `UpstreamError`, the OAuth option enums and
    `OAuthDialectError`; matches need a fallback arm that rejects the
    unsupported variant. `ProviderFailureStatus` is now exhaustive.
  Serialized and stored shapes are unchanged.
- The `agent-access-broker` library exports only `composition()`, the modules
  the distribution links, and `build_identity()`, the executable's identity.
  Its router, reload-state and registry exports (`build_router`,
  `build_public_router`, `build_gateway_router`, `build_reloadable_state`,
  `ReloadableState`, `validate_reload_timeout`, `validate_shutdown_timeout`,
  `backend_registry` and `broker_build_status`) are removed, and
  `agent-access-broker-host` keeps its routers and reload state private, so
  they have no other import path. Run a broker with
  `BrokerApplication::new(composition, identity)`; start one in tests with the
  host's `test-support` feature (`test_support::IsolatedBroker`); read the
  build status with `BrokerApplication::status()`, whose
  `BrokerBuildStatus` is now `agent_access_broker_host::BrokerBuildStatus`; and
  read selected kinds, resource types, route specifications and configured
  service descriptors from `BrokerComposition`.
- The provider SDK no longer exports `OpaqueTokenSigner`. Seal handles and
  cursors with a `ContinuationFamily` and `ContinuationSigner`; a
  `ContinuationLifetime::Durable` family replaces `sign_durable` and
  `verify_durable`. `StableSigningKey` and `host::service_signing_key` remain
  the host's signing-key port.

### Added

- The standard reason `broker_provider_contract_failed` (HTTP 500,
  `decision = error`) identifies a provider outcome that its contract does
  not allow. It also reports a provider whose own operation state is missing
  or of another type (`ProviderStateError`), or that asks for an authority its
  action was not admitted with (`AuthorityMismatch`), keeping their internal
  diagnostic codes.
- Native backends can declare provider-owned domain reasons: static
  `ProviderReasonDefinition`s with a fixed `deny` or `error` decision and a
  `ProviderFailureStatus` (400, 403, 404, 409, 413, 415, 424, 500, 502, 503 or
  504), listed with `BackendRegistration::with_domain_reasons` and reported
  with `ProviderError::domain`. Codes start with the backend kind (hyphens as
  underscores) and `_`; the registry rejects codes another selected backend
  owns, standard codes, and reserved `broker_` prefixes before serving. A
  credential verification failing with a domain reason whose status is 424,
  502, 503 or 504 records `verification_failed`, like the standard upstream
  failures.
- The provider SDK publishes the standard reasons providers may report, with
  their decisions and hooks (`ReasonCode::permits_provider_failure`,
  `permits_provider_allow`, `permits_late_stream`, `HookPhase`), and host-origin
  failures (`host::HostPort`, `host::port_failure`) that providers pass on
  unchanged, such as a delegated lease's `concurrency_limited`.
- Release qualification runs a required `crate-boundaries` gate
  (`node scripts/check-crate-boundaries.mjs`). Every workspace crate declares a
  role, and the check rejects dependencies that cross the role boundaries.
- The provider SDK provides signed continuation envelopes for resumable
  cursors, page tokens and handles: `ContinuationFamily` declares a token
  family (service, purpose, version, payload cap, expiry and a generation,
  stable-when-configured or durable signing lifetime), `ContinuationBinding`
  binds the admitted context, configuration, resources and normalized settings
  through the MAC context only, `ContinuationSigner` seals and opens tokens,
  and `ContinuationError` reports rejected tokens separately from signing
  failures.
- `ContinuationFamily::with_max_payload_bytes` sets a family's payload cap at
  run time, beyond the 64 KiB ceiling of `ContinuationFamily::new`, for a
  family relaying upstream tokens that only a configured response limit
  bounds; `max_token_bytes()` saturates instead of overflowing.
- Continuation families can relay an upstream service's own page token
  (`ContinuationSigner::seal_relayed`/`open_relayed`), optionally with a keyed
  commitment to the composed upstream query that rejects the token with
  `ContinuationError::UpstreamQueryChanged` once that query changes, and can
  size their cap from a response limit with
  `ContinuationFamily::max_payload_bytes_within`. A family declared
  `opened_during_scope_resolution()` is opened during scope resolution with
  `bind_scope` and `ContinuationSigner::open_during_scope_resolution`, its
  owner carried as a keyed commitment; `ContinuationBinding` records its stage
  as a `ContinuationStage` type parameter (`AdmissionStage` by default, or
  `ScopeResolutionStage`).
- `ContinuationFailures` reports each `ContinuationError` as a provider's
  failure for rejected tokens, oversized payloads (given the family's cap) or
  unavailable signing keys, optionally wording `Expired`,
  `UpstreamQueryChanged` or `DurableKeyUnavailable` differently. CloudBees,
  GitLab, Gmail, Jira and Confluence report their continuation failures
  through it, with unchanged reasons, decisions and messages.
- The provider SDK exports `SDK_PACKAGE`, its own package name and version,
  which the host reports as the status's `sdk`.
- `scripts/verify-release-provenance.mjs` checks the release dependency graph
  before building: the resolved features of every normal and build unit of
  `agent-access-broker` and `agent-access` (`cargo tree -e normal,build
  --format '{p}\t{f}'`) must not include `test-support`, and the graph must link
  no `reference` crate. It also requires each host, SDK and module package that
  the status stamps with the qualified commit to resolve, among those selected
  units, to exactly one tracked path package in the checkout, rejecting a
  same-version package from another source and two selected origins sharing a
  crate name and version.
- A checked-in supported public API inventory under `api/`, generated by
  `node scripts/public-api.mjs update` with the `nightly-2026-07-13` rustdoc
  JSON and `cargo-public-api` 0.52.0. It covers the SDK and host with and
  without `test-support`, the assembly library, the reviewed selection entry
  points of the linked natives, OAuth dialects and import adapters, and the
  workspace and third-party types their signatures expose. It also records the
  contracts the signatures omit: required or provided trait items, trait dyn
  compatibility, and how structs, variants and enums can be constructed or
  matched. `node scripts/public-api.mjs check` fails when the candidate's API differs
  from the inventory. `0.2.0` is the first released baseline.
- Release qualification runs a required `public-api` gate
  (`node scripts/public-api.mjs check`). Preflight requires the pinned nightly
  and `cargo-public-api` and records their versions in `qualification.json`.
- `agent_access_provider::deps` re-exports the third-party types and macros
  that the SDK's supported signatures name: the `async_trait` attribute and
  selected `bytes`, `chrono`, `futures-core`, `http`, `reqwest`, `serde_json`,
  `tokio`, `toml` and `url` items, each under a module named after its
  package. The SDK's crate documentation records their versions, the supported
  surface, the trust model and the compatibility policy.
- `agent-access-broker-host` has a `test-support` feature for acceptance
  tests. `test_support::IsolatedBroker` starts a composition on a real
  configuration file through the production startup, reload and drain logic,
  with explicit reload, shutdown and join instead of process signals.
  `ProviderFixture` supplies the providers of configured native kinds, and
  read-only views expose the fixture's audit and managed stores. Release builds
  must not enable the feature.
- A provider-author guide, `docs/provider-sdk.md`, replaces the "Adding a
  backend" section of the architecture document. It covers the supported SDK
  surface and trust model, registration and configuration, descriptors, scope
  resolution and provider state, admitted authority and static and delegated
  credential obligations, governed HTTP, continuation tokens, standard and
  domain reasons, outcomes, testing, the compatibility policy and a worked
  example.
- A downstream assembly guide, `docs/downstream-assembly.md`, covers building
  another distribution from the Broker host: composition, the application
  lifecycle, assembly identity and module provenance, canonical Git pins,
  coordinated upgrades, source overrides, lockfile review, CLI and portal
  assets, the release-feature check and qualification.
- Release qualification runs a required `downstream-consumer` gate
  (`node scripts/verify-downstream-consumer.mjs`). It stages a separately owned
  provider repository with the conformance crate and a downstream Broker
  assembly as independent Git repositories pinned to the candidate commit,
  builds and tests them and the candidate's CLI with `--locked --offline` from
  the shared Cargo download cache, reviews their lockfiles for one SDK package
  identity, checks that the assembled executable reports its own identity, the
  locked sources of the host, SDK and modules and their inventory fingerprint,
  and runs it against a synthetic CloudBees CI controller through that CLI.
  Every crate in `Cargo.lock` must already be in the download cache, and Cargo
  configuration outside the driver's private Cargo home must not apply to its
  stage. In the same stage it builds and tests the code of the provider SDK and
  downstream assembly guides, which marks every Rust block: `rust check` blocks
  compile as modules of a generated SDK-only crate, `rust file=` and
  `toml file=` blocks form the guides' example crates, staged in the provider
  repository and beside the assembly, and `rust fragment` blocks are
  deliberately not compiled. Guide code blocks may not open inside a
  blockquote or on a list item's marker line, and every staged Rust file must
  be read by a compiled target. The assembly guide's example must share its
  `main.rs` and `build.rs` with the fixture's assembly as the guide states.

### Changed

- Startup, reload and import-write diagnostics for a retained imported service
  identity collision now name both owners, such as
  `retained imported service jira collides with the selected native provider kind jira`.
- Broker process lifecycle, HTTP, MCP, management, gateway, and reload events
  now log under `agent_access_broker_host::…` targets instead of
  `agent_access_broker` and `agent_access_broker::…`; lifecycle events such as
  `broker_starting`, `broker_listening`, and `broker_shutdown` use
  `agent_access_broker_host::lifecycle`. Update module-level `RUST_LOG`
  directives accordingly. The default filter now names
  `agent_access_broker_host=info` explicitly, which the `fallback` field of
  `logging_filter_invalid` reports. The `agent_access_broker::handlers::oidc`
  diagnostic target is unchanged.
- `agent-access-broker serve`, and the broker run without a subcommand, now exit
  `3` instead of `1` when the configuration cannot be read, parsed, or
  validated at startup, matching `config validate`. Other startup and runtime
  failures still exit `1`, and the `Error: …` message is unchanged.
- State lock metadata records the holding executable's assembly name as
  `program` and its version as `programVersion`, and held-lock diagnostics show
  both. Lock file names are unchanged and independent of the executable name,
  so differently named executables still exclude each other on one state set.
- The aggregate HTTP MCP endpoint reports the assembly name and version as
  `serverInfo`, and service endpoints report the assembly version; both
  previously used the host package version.
- Imported MCP connections send `clientInfo`
  `{"name": "agent-access-broker-host", "version": <host version>}`, naming the
  Broker host implementation, instead of `agent-access-broker` with the adapter
  package version.
- When shutdown reaches `--shutdown-timeout-ms`, the broker now cuts off the
  public and gateway connections still open and waits for their tasks to end
  before the final audit drain, instead of leaving them running until the
  process exits.

- The Broker now enforces each provider's reason contract at the hook that
  reported it (scope resolution, body admission, invocation, credential
  verification, and late result streams), for native and imported services. A
  standard reason outside the provider-reportable subset for its hook and
  decision, an unregistered or modified domain reason, a host port's failure
  outside its allowlist, an `upstream_rate_limited` failure without its
  rate-limit result, or a late stream code outside its subset now reports
  `broker_provider_contract_failed` (HTTP 500, `decision = error`) with a fixed
  message instead of the provider's outcome; an invocation's adds
  `result.executionState = "unknown"` and `result.retrySafe = false`. A
  delegated credential's failures, such as a busy refresh's
  `concurrency_limited`, still pass through unchanged. Upstream trace
  classifications, including a client's declared status reasons, are checked
  against the hook that sent the request and logged as
  `broker_provider_contract_failed` when rejected or made outside a provider
  hook. Rejections log a `provider_contract_failed` event with a diagnostic
  code.
- A GitLab write whose request provably never reached GitLab (no connection
  was established, including a connect timeout) now fails with
  `upstream_connection_failed` or `upstream_timeout` and a result of
  `mutationStatus: "not_applied"`, `retrySafe: true`. Writes with a
  verification contract (review participation, approvals, suggestion
  application, webhooks, and provisioning) previously reported it as
  `mutation_verification_failed` with `applied_unverified` unless a readback
  proved the target unchanged; other writes returned the same error without a
  receipt. Failures after the request may have been sent keep their existing
  outcome.

### Fixed

- Management credential verification and imported-service discovery report a
  provider failure's own decision in the response and its management audit
  record instead of always `deny`: upstream failures such as `upstream_timeout`,
  host-origin failures such as a delegated lease's `concurrency_limited`, and
  domain reasons defined as `error` now report `decision = error`. Host
  failures preparing discovery, such as an unavailable store or a missing
  encryption key, still report `deny`. Reason codes and HTTP statuses are
  unchanged.

### Removed

## [0.1.0] - 2026-10-11

### Initial release

- A standalone Broker and CLI for scoped, audited access to service APIs while
  keeping upstream credentials in the Broker.
- Managed accounts, groups, typed resources, execution contexts, service policies,
  grants, restricted agent tokens, and trusted human identity through configured
  ingress callers.
- A same-origin portal for administration, personal credentials and OAuth,
  access management, and audit investigation.
- Typed CLI commands, native HTTP and local stdio MCP, catalog-driven invocation,
  runtime schemas, and a governed Git smart HTTP gateway.
- Integrations for Jira, Confluence, GitLab, CloudBees CI, Gmail, Teams Workflows,
  imported HTTP MCP services, and imported OpenAPI services.
- Encrypted credential storage, delegated OAuth, key rotation, bounded transfers,
  outbound destination controls, quotas, and structured audit and observability.
- Operator and administrator guides, sample configurations, dependency notices,
  and a release workflow that qualifies the exact commit before publication.
