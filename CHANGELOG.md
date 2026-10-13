# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Breaking Changes

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
  owns, standard codes, and reserved `broker_` prefixes before serving.
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
