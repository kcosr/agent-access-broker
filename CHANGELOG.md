# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- Core-owned delegated Broker administration: complete-tuple service-account,
  group and grant operations, reference-only absent-slot credential installation,
  and bounded child invocation tokens with atomic encrypted output capture.
- Principal creation, group-member changes, administrator/self-service token
  issuance, grant-subject changes, grant PATCH, and administrator/personal
  credential installation recheck original authority in their transaction and
  retain completion ownership through disconnect and shutdown.

### Breaking Changes

- GitLab project access-token creation and service-account membership replace
  the numeric `accessLevel` input and `--access-level` flag with strict built-in
  `role` names and `--role`. Provisioning configuration replaces
  `max_access_level` with `max_role` (default `"developer"`). Numeric role
  inputs and old spellings are rejected; numeric `accessLevel` result metadata
  is unchanged. Discovery advertises only roles permitted by the configured cap;
  action details distinguish role inputs, existing-role checks and numeric metadata.
- Availability prerequisites now use a tagged `kind` contract. Local-runtime
  prerequisites omit `credentialMode` and can require caller authentication.
- Reserve `broker_management` and `access_management` for the core-owned local
  administration service. Its four Broker resource types accept exact selectors.
- Provider actions declare plural `resource_scopes` through `.scopes(...)`.
  Capability and runtime metadata use `requiredScopes`; discovery and previews
  use complete `targets` maps. Every required resource dimension must be covered
  by one grant and by the token's resource restrictions. Singular scope fields
  and the old one-target query shape are removed.
- The host's test-support `ManagedStoreError` adds `ManagementDenied` and
  `CommitUnknown`; exhaustive downstream matches must handle both.

- Connection credential PUTs, including literal tokens, return `409 version_conflict` before writing when a runtime publication overtakes admission; retry the PUT using current configuration.

- Declared transferable provider secrets default to encrypted temporary reference
  delivery. Configure `[secret_outputs] mode = "raw"` for intentional plaintext
  delivery. Reference-capable actions require a managed encrypted store.
- Actions declaring secret outputs now use `mcp.operation_timeout_ms` as one
  total producer budget on every transport, in both reference and raw modes.
  It starts at governed invocation entry and includes audit admission, scope
  and credential preparation, and sequential provider calls. An earlier caller
  deadline wins. Secret capture and durable completion audit preserve known
  outcomes outside producer cancellation.
- Managed-store schema `029_secret_references` adds temporary encrypted outputs,
  bounded outcome receipts, and durable trusted-caller generations. Rollback
  requires a pre-migration backup.
- The exhaustive `ManagedStoreError` enum exposed through the host's
  `test-support` API gains five `SecretReference*` variants. Downstream tests
  that exhaustively match this enum must handle the new variants.
- Native provider search authority now uses constructor-built, normalized
  `SearchAuthorizationScope` clauses (included selectors minus excluded
  selectors, unioned across clauses). The former scope variants are removed.
  `ActionDescriptor.search_contained` is replaced by optional `native_search`
  enforcement, distinguishing upstream-constrained and result-filtered native
  searches; exact-only query providers use `exact_projection()`. New native-search
  audit records store `searchAuthorization.scope` as
  `{clauses:[{included,excluded}]}`; historical records retain their stored JSON.
  Imported commands retain their separate exact-only wire boundary;
  their metadata cannot enable native search enforcement. Stored grants and
  token restrictions are unchanged.

- The native provider contract changes, so existing provider implementations must be
  updated:
  - **Scope resolution.** `Provider::resolve_scopes`, `resolve_scopes_with_lookup`
    and `resolve_scopes_with_lookup_context` are replaced by one required
    `async fn resolve_scopes(&self, request: ScopeRequest<'_>) -> Result<ScopeResolution, ProviderError>`.
    `ScopeRequest` carries the action, validated inputs, host-selected execution
    context, minimal identity, correlation and optional host-selected lookup
    access. `ScopeResolution` returns canonical resource scopes
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
  - **Execution credentials.** These are typed, privately constructed and
    opaque: provider code reads only `ExecutionCredential::kind()`, never the
    material, and never holds a request carrying it. `authorization()`
    presents a credential in its kind's own scheme (HTTP Basic or Bearer), and
    `authorization_as(&CredentialPlacement)` in a checked `bearer()`,
    `basic()` or named `header(name)` placement or fails with
    `CredentialPlacementError`. The resulting opaque `UpstreamAuthorization`
    travels with the send call (`UpstreamCall::with_authorization`,
    `with_authorizations`, `RedirectRules::with_authorization`); the upstream
    client adds the sensitive header to the request it builds, with the bytes
    `basic_auth` and `bearer_auth` produce. Only the host's own clients attach
    one directly, through the host-only `host::authorize_host_request`, which
    the crate-boundary check rejects in native, adapter, reference and helper
    crates. Debug output is redacted. Credentials compare with `==` only under
    the `test-support` feature, in constant time. Execution material is
    selected through `ExecutionAccess::{None, Static, Delegated}`, and lookup
    material through the non-exhaustive `LookupAccess::{Static, Delegated}`
    (`lookup_access()` on scope and admitted requests). Delegated lookup
    access holds the operation's one delegated lease, shared with execution,
    so its clones never add a 401 recovery. Stored credential rows and the
    `basic_api_token`/`bearer_token` kind spellings are unchanged, so stored
    credentials keep working.
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
    `ResourceTypeDescriptor::new(id, label, plural_label, example, canonical,
    attributes)` with `.with_namespace(NamespaceSelectorDescriptor::new(..))`
    and `.with_action_inputs(..)`, read through `id()`, `label()`,
    `namespace()`, `attributes()`, `action_inputs(selector)` and `is_valid`;
    `presentation::ActionPresentation::new(bodies, whole)` and
    `EmbeddedBody::new(owner_path, codec)`. The private attributes are a
    constructor argument, `&[]` for none; `with_attributes` is removed. A
    nonempty attribute list is its own `static` array of
    `ResourceAttributeDescriptor::required(..)` or `optional(..)` entries; an
    inline `&[..]` array no longer compiles.
  - Resource types can also be declared at runtime:
    `ResourceTypeDescriptor::declared(id, label, plural_label, example,
    pattern, attributes)` and `ResourceAttributeDescriptor::declared(name,
    label, description, required, pattern)`, with `ResourcePattern::new(source,
    max_length)` as the whole-value grammar, a complete `regex`-dialect
    expression on its own. Descriptor accessors return
    borrowed `&str` and `&[ResourceAttributeDescriptor]` instead of `'static`
    data. `ResourceTypeRegistry` holds shared `Arc<ResourceTypeDescriptor>`
    values: `get` and `descriptors` return them, and `from_shared` builds a
    registry from them.
  - `UpstreamClientSpec::new(label, provider, base, egress, allowed_hosts,
    profile)` with `.with_status_reasons(..)`, and `RedirectRules::new(max,
    deadline)` with `.with_authorization(..)`, `.correlating_other_origins()`,
    `.with_vet(..)` and `.with_decorate(..)`, have private fields.
    `UpstreamCall::new(operation)` carries `.with_attempt(..)` and the
    credentials it presents. `DelegatedAccess::new(token,
    target, audience, version, expires_at)` has private fields read through
    `target()`, `audience()`, `version()` and `expires_at()`; its token is
    presented only through `authorization()` (`Authorization: Bearer`) and
    `authorization_as(&CredentialPlacement)`.
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
    `ActionIo`, `ServiceSurface`, `StaticCredentialKind`,
    `CredentialPlacementError`, `ExecutionAccess`, `InvocationAuthority`,
    `EgressDeclaration`, `ClientProfile`, `UpstreamError`, the OAuth option
    enums and
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
- `UpstreamClient` now keeps credentials on its base origin. Every send
  method, including each hop of `get_following_redirects`, refuses a request to
  another origin that carries an `Authorization`, `Proxy-Authorization` or
  `Cookie` header or a header value marked sensitive (as every presented
  `UpstreamAuthorization`, `bearer_auth`, `basic_auth` and URL-embedded
  credentials produce), failing before it is
  sent with `UpstreamError::NotSent`. Previously only the redirect helper kept
  credentials on the base origin, and `send` delivered them to any allowlisted
  origin. Requests without credentials still reach every allowlisted origin.
  A provider that needs credentials on another origin builds a client whose
  base is that origin, and marks custom credential headers sensitive. The
  shipped providers already met this rule.
- `get_following_redirects` presents a chain's authorization only on hops
  within its authorized path: the client's base origin at or below the base's
  path, compared by whole segments, instead of any hop on the base origin.
  `RedirectRules::with_authorized_prefix(&url)` names another path on that
  origin, such as one tenant's path on a gateway shared by many tenants. With
  an authorization, a hop on the base origin outside the path fails the chain
  as `UpstreamError::Redirect` before it is sent, and a credential that
  `with_decorate` adds outside it fails as `NotSent`. A path that a server could
  decode into a dot segment, such as `..%2F`, is outside every path.
  `RedirectRules::with_authorizer` takes the new implementable
  `RedirectAuthorizer` trait, which supplies each authorized hop's
  authorization immediately before that hop is sent, so delegated access is
  revalidated per hop; its failure is the new `UpstreamError::Authorization`,
  which carries the provider's own `ProviderError`. `with_authorization` keeps
  presenting one static credential. CloudBees CI's redirects already stayed
  within its controller base.
- `[limits].upload_spool_dir` is now required. It previously defaulted to
  `<working directory>/target/agent-access-upload-spool`, which under a service
  manager such as systemd is `/target/agent-access-upload-spool`, and the Broker
  creates and state-locks that directory at startup. A configuration without the
  setting, including one without a `[limits]` table, now fails `config validate`
  and startup with ``missing field `upload_spool_dir` ``. Before upgrading, add
  it to every Broker configuration, pointing at a dedicated broker-owned
  directory, for example:

  ```toml
  [limits]
  upload_spool_dir = "/var/lib/agent-access-broker/spool"
  ```

  To keep using the previous location, set it explicitly. Relative paths still
  resolve against the working directory. `LimitsConfig` no longer implements
  `Default`; construct it with `LimitsConfig::new(upload_spool_dir)`, which
  applies the built-in default for every other limit.
- Personal credentials are configured as credential connections.
  `[credentials.connections.<id>]` (`display_name`, `token_profile`, and
  `oauth = { registration, profile }`) defines one per-principal credential,
  and every service whose `[credentials.per_user.<service>]` entry is
  `type = "connection"` with `connection = "<id>"` uses it. Services that reach
  the same upstream account can share one connection, such as GitLab REST and
  a GitLab Git gateway with one stored GitLab token, while keeping separate
  grants. The per-user types `managed_store` and `oauth` and the `credential_name`
  and `profile` keys are removed without a fallback parser; a per-user `type` is
  `connection` or `secret_store`. A principal's kind selects the method from
  configuration alone, with no fallback between methods: people use OAuth when
  the connection sets it and a token they store otherwise; service accounts use
  tokens administrators provision and `system` principals tokens they store,
  never OAuth; a configured static principal takes the kind of the active
  managed principal with its ID, and other static principals and anonymous
  callers have no connection method. A connection's tokens are stored under its ID with the
  name `default`, so a connection with the same ID and profile as an earlier
  per-service credential reads its tokens unchanged; tokens under another name
  stay stored but unread. Credential rights apply to the connection and
  `default`; rights on other names have no effect. Connection IDs share the
  service namespace: a connection may not be named `broker`, or after a
  configured service, gateway or imported service that does not use it.
  Imports with a personal binding publish their own connection under their
  service ID and need no configuration change. There is no schema migration;
  rewrite the configuration before upgrading, following the credential
  connections steps under the operator guide's upgrade and rollback section.
- Personal credential management is keyed by credential connection. `GET
  /v1/credentials` returns `{connections, retained}`: each connection's method
  for the caller (`token`, `oauth` or `unavailable`), the services it serves
  that the caller is entitled to with a count of the others, and its active
  token, plus the stored rows the configuration no longer selects. `GET
  /v1/credentials/targets` lists connections, and `GET|PUT|DELETE
  /v1/credentials/connections/{connection}` with `/verify` and
  `/input-schema` replace the `{service}/{name}` routes; the administrator
  routes move to `/v1/admin/principals/{principal}/credentials/connections/{connection}`
  and apply only when the connection selects a token for that principal, and
  `GET /v1/admin/principals/{principal}/credentials` lists a principal's
  connections and retained rows in the personal list's shape. A classless
  self-service caller needs its managed principal row, whose kind selects each
  connection's method.
  Verification takes an optional `service` beside `repository`, probes as the
  credential owner and returns `probeService`. `DELETE
  /v1/credentials/retained/{credentialId}` removes a retained row, and
  `PUT /v1/admin/credentials/{id}` and `POST /v1/admin/credentials/{id}/verify`
  are removed. OAuth routes are keyed by registration: `POST /v1/oauth/connect`
  takes `registration` (and `importedService` for an administrator's import
  discovery), `DELETE /v1/oauth/connections/{registration}` disconnects, and
  `GET /v1/oauth/connections` returns one row per registration with its
  `consumers` and `otherConsumers` instead of `service` and
  `serviceDisplayName`; a registration the user still holds tokens for but no
  connection selects is listed for disconnection only, with `permissionProfile`,
  `scopeMode` and `target` null. A connection without `display_name` is named
  by its ID. Consent is admitted for the registration as a whole,
  through any consuming service the user holds a `per_user` grant on, and
  consent flows left pending by an earlier version are discarded. Management
  audit targets name `{principal, connection}`, `{principal, credentialId}` for
  retained-row deletes, and `{registration}` for OAuth; connection records list
  the consuming services in `providerAudit.management.targetServices`, and only a
  connection with a single consumer sets `targetService`. The CLI follows: `credentials
  inspect|put|delete|verify <connection>` drop the credential-name positional,
  `credentials targets` and `credentials delete-retained <credential-id>` are
  added, verification takes `--service` (`--verify-service` on `put`), and
  `admin credentials list <principal>` lists a principal's connections, while
  `list-stored [--principal]`, `targets`, `inspect-by-id` and `delete-by-id`
  are added. The portal's Credentials list has one row per connection and
  per OAuth registration, merging the separate Connected accounts section, and
  lists retained rows for deletion.
- Jira and Confluence declare the vendor-level token profiles
  `atlassian-api-token` (an Atlassian account email and classic API token, sent
  as HTTP Basic to the site) and, when the provider routes through the
  Atlassian gateway, `atlassian-bearer-token` (a service account's scoped
  token, sent as a bearer token through the gateway). The product profiles
  `jira-cloud-api-token`, `jira-bearer-token`, `confluence-cloud-api-token` and
  `confluence-bearer-token` are removed without an alias: a connection naming
  one fails validation and lists the profiles its services accept. Because both
  products declare the same profiles, one `atlassian` connection can serve
  Jira and Confluence on one site. Tokens stored under the product profiles
  stay stored, still decrypt for rewrap, and are listed as retained rows, but
  are never read: people store their Atlassian token once, one token where they
  stored two, and administrators re-provision service accounts' tokens.
- GitLab page tokens, Jira search continuations, and Confluence search
  continuations, list tokens and draft handles are bound to the credential
  method that reaches the upstream: for a stored or service token, its type
  (not its value); for delegated (OAuth) access, the OAuth connection and its
  generation, never the access version; and the configured `cloud_id` on
  Atlassian gateway routes. A switch between a token and OAuth, another token
  type, another account, a reconnected connection or another gateway site
  rejects them with the existing `input_invalid` or `invalid_draft_handle`,
  while a routine OAuth refresh keeps them. Confluence draft handles carry a
  keyed commitment to that binding, checked after admission, and use the
  prefix `aab_confluence_draft_v4_`. Tokens and draft handles issued before
  the upgrade are rejected: repeat the search or listing without the token,
  and create or stage the draft again.
- The SDK's intentionally exhaustive `OAuthRegistrationConfig` gains the
  optional `login_binding: Option<OAuthLoginBinding>` field. Code that builds
  it with a struct literal adds `login_binding: None`; deserialized
  registrations without the key are unchanged, as are their fingerprints and
  stored connections.

### Added

- Confidential fixed-length continuations use AES-256-GCM with binding-separated
  HKDF keys and carried absolute expiry. Bounded upstream operations share atomic
  HTTP attempt and decoded-body byte budgets.

- GitLab repository discovery (`project.search`) and separately grantable native
  searches for issues, merge requests, code, commits, project wikis, and comments
  (`search.*`), with typed `gitlab project search` / `gitlab search` commands and
  shared invoke/send/OpenAPI/MCP schemas. Namespace-aware repository filtering,
  selected execution credentials, current ownership confirmation, bounded
  previews, and validated optional locators protect returned content.
  Discovery accepts GitLab's defaulted keyset links while validating destination,
  requested filters, ordering, page size, and cursor. Project wiki hits may
  include their parent group as metadata without granting group authority.
  Group-only wiki hits are discarded from instance-wide results and fail closed
  on project-scoped searches. GitLab-specific guidance distinguishes live
  discovery from `resources_list` registrations and wiki snippets from repository
  file reads. Project details include optional description, last activity, and
  star count.
- Operator-configured GitLab engine/category/scope capabilities and bounded scan
  work, with explicit incomplete-coverage statuses and confidential continuations
  that preserve the original 15-minute expiry. Basic code/commit/wiki/comment
  search requires a project; advanced and Zoekt tuples require explicit setup.
  Agent guidance follows the service's configured default when `engine` is
  omitted. Existing single-project `issue.search` and `merge_request.search`
  retain their structured-list contracts.

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
- `DelegatedCredential::revalidated_access_for(target, audience)` revalidates
  a delegated lease and returns its access only for exactly that target and
  audience, and `access_for` makes the same comparison without revalidating.
  `DelegatedAccessError` separates the host's revalidation failure, returned
  unchanged, from a mismatch the provider reports. Gmail and imported MCP
  check their delegated access through them, with unchanged errors and order
  of checks.
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
- The provider SDK streams a bounded raw download with
  `ProviderResultStream::from_bounded_response` and a `BoundedDownload`: a
  label, a byte cap with the late reason it reports, an idle timeout and an
  optional expected size. Stalls, read failures, cap overruns and size
  mismatches fail late with code-only reasons.
- The provider SDK reads a bounded response body into memory with
  `read_bounded_body(response, byte_cap, idle_timeout)`, which rejects a
  declared `Content-Length` over the cap before reading and returns a typed
  `BodyReadError` (`TooLarge`, `IdleTimeout`, or `Transport` with `timed_out`)
  for the provider to map.
- The provider SDK validates URL pattern lists with `validate_url_patterns`
  and a `UrlPatternPolicy`: the allowlist grammar (a fixed host, no embedded
  credentials, literal, `*` or `**` path segments) plus the policy's schemes,
  emptiness, query and fragment, and repeat rules.
- The provider SDK builds mutation receipts with `MutationReceipt`:
  `not_applied()` for a proven-unsent write (`mutationStatus: "not_applied"`,
  `retrySafe: true`), `unknown()` for a write that may have reached the
  upstream without a response (`mutationStatus: "unknown"`,
  `retrySafe: false`) and `applied_unverified(stage, safe_locators)`.
  `ProviderError::with_mutation_receipt` attaches one to a failure's result,
  keeping its other fields, `ProviderError::or_mutation_receipt` attaches one
  unless the error already reports a `mutationStatus`,
  `ProviderError::unverified_after_mutation` reports a failed read-back after an
  applied write as `applied_unverified` (keeping throttling's
  `mutation_verification_failed`), and `MutationReceipt::write_into` writes one
  into a result value.
  `MutationStatus` names the non-exhaustive status vocabulary.
- Agent token options (`GET /v1/tokens/options` and
  `GET /v1/admin/principals/{principal}/agent-token-options`) report `mcp`:
  `{"url": ...}` with `mcp.public_url`, serialized as the broker parses it
  (punycode host, normalized separators), when the HTTP MCP endpoint is enabled
  and a `broker_tokens` identity source reads `Authorization: Bearer`, otherwise
  `null`. Auditors receive `null`.
- After issuing an agent token, the portal's **Token created** dialog shows
  **Connect an MCP client** when token options report an HTTP MCP endpoint: the
  server URL, the line that sets `AGENT_ACCESS_TOKEN` (macOS/Linux or Windows
  PowerShell), and setup for Pi, OpenCode, Claude Code, Codex and Cursor, with
  copy buttons: a command (Cursor: an install link) and a configuration file,
  except that Claude Code gets only a user-scope command, which adds the server
  for all of the user's projects. Client snippets name the variable, never the
  token; the chosen client is remembered in the browser.
- `[command_imports.<name>]` approves a local executable for the `command`
  import kind, with its path, timeout, output and concurrency caps, working
  directory, network mode, `log_stderr` opt-in and environment. Imports name it
  as `command:<name>`; `imports.allowed_endpoints` gates HTTP(S) endpoints only
  and may be empty when every allowed kind uses command endpoints. Offline
  validation warns about missing executables and enabled `log_stderr`.
- Managed-store migration `027_command_imports` adds the nullable
  `imported_services.accepted_metadata_json` column and lets imported execution
  slots hold `basic_api_token` material, copying every existing slot row
  unchanged. Import credential writes accept `username` (CLI `--username`) for a
  command import's `username_token` credential.
- The `command` import kind (`agent-access-command-import`) imports an approved
  command by running `<path> describe` and mapping its `agent-access-command/1`
  manifest; invalid actions stay listed as unsupported. Acceptance stores the
  manifest's service metadata, and a command without a credential enables with
  service-mode grants and no credential. Import list responses include
  `commandImports` (approved names only) and command import results
  `commandVersion`.
- Command imports register the resource types their manifests declare under
  Broker type IDs proposed as `<service>_<id>`. Accepted types are listed by
  `GET /v1/resource-types`, stay registered while the import is disabled or
  retired and across restarts, which build them from stored import metadata
  before validating stored resources, and validate their private attributes
  from the declaration without a configured backend. A type marked removed in
  the accepted metadata accepts no new resources.
- Command import refreshes change resource types in place under the safe-change
  rules. Previews record a decision per added, changed, restored or removed
  type in `resourceTypeChanges`, which discovery and preview results show with
  the stored resources each decision depends on; changes that would need
  decrypting stored attribute values make the type's actions unsupported. The
  accept body's `resourceTypeIds` chooses Broker type IDs for added types.
  Acceptance rechecks every resource-dependent decision under the policy
  mutation lock and rejects, naming the resources, when one no longer holds;
  it deletes removed attributes' values with resource version bumps, keeps
  removed types with resources and drops unused ones, publishing the advanced
  policy revision and reporting `resourceTypeEffects`. An import with accepted
  actions may accept a preview with no selections to apply only its metadata
  and type changes. Acceptances that add types, delete values or drop types
  write a success completion audit record naming the added Broker type IDs,
  the affected resources with deleted attribute names (never values), dropped
  types and policy revisions; any acceptance that changes types checks every
  stored resource against the new registry before it commits. Attribute rules
  count only exact resources, since `all` resources hold no attribute values.
  A command declares at most 16 types and an import keeps at most 16 removed
  types besides them, and `unresolved_resource_type` is reserved.
- Resource type listings (`GET /v1/resource-types` and the runtime catalog's
  `resourceTypes`) name a command import's types' `importedService` and mark a
  removed type `removed: true`. The SDK's `ResourceTypeMetadata` gains the
  `removed` and `imported_service` fields.
- Command import runs (`describe` now, `invoke` and `verify` through the
  command hook) start one process in its own process group, with an empty
  environment plus the configured `env` and request data only on stdin, under
  a supervisor that caps stdout, keeps 4 KiB of stderr, kills the group at the
  command deadline and reaps it before releasing its slot. Each command name
  has one concurrency budget of `max_concurrent` slots, shared by its imports,
  runs and runtime generations; calls wait for a slot before their final
  checks and fail `upstream_timeout` when none frees by their deadline, and a
  reload that changes the command's entry fences calls still waiting. Failures
  log `command_import_failed`. Shutdown kills and reaps command processes
  after the operation drain, including those whose call already ended, and
  reports any it could not reap.
- Command import calls run their command. After the slot and the final checks
  (dispatch fence, the named resource entries revalidated and decrypted, and
  credentials: a service slot at its admitted version, a personal credential
  as it is now), the Broker writes one `agent-access-command/1` request to the
  command's stdin with the caller, the inputs, the admitted `authorization`
  (`broker` with the named resources' IDs, names and private attributes, or
  `command` with the top band's grants, each with its credential and boundary),
  the `token` or `username_token` credentials those grants use, and, with
  `network = "inherit"`, the egress proxy route with its credentials, the
  `NO_PROXY` entries, the trust mode and the configured `ca_certificate` path,
  also set as environment variables per trust mode. A queued call whose
  resource entry changed fails `scope_unresolved`, one whose service slot
  rotated fails `service_action_denied`, and one whose personal credential was
  removed fails `credential_not_provisioned`, all without starting a process.
  Responses return `result.upstreamCommand`, map command error codes to Broker
  reasons with the command's message and `retryAfterSeconds`, and report the
  command's write receipt with `operationDispatched`; a response that breaks
  the contract, including a message, verification stage or locator
  containing a supplied credential or proxy secret in any form the command
  receives or derives (each token, the Basic `username:token` form, and the
  proxy password raw, percent-encoded, in the proxy URL and in its Basic
  `username:password` form), fails `operation_failed`; private attribute
  values are not checked, and command messages may hold no control
  character other than tab. Every admitted exact resource is fenced by its
  row version, creation time (to the second), display name, type, selector
  and private attribute versions, and the import's dispatch fence is checked
  again immediately before the process starts. Invocation audit adds
  `providerAudit.command` (process facts, with `contractViolation` `null`
  until a verdict) and `providerAudit.commandAuthorization` (the admitted
  authorization in either mode), kept for interrupted calls. Shutdown fails a
  command call it stops with `operation_cancelled`. Verifying a personal
  credential runs the command's `verify` when its manifest declares it,
  fenced like a call, and stays local otherwise; its audit, failed or not,
  keeps the process facts with no upstream status.
- The portal imports local commands. **Import service** offers the **Local
  command** type, which picks an operator-approved command by name, never a
  path, and chooses shared and personal credential modes, or none. The
  discovery preview shows the command version, credential kind and
  verification support, any OAuth notice, each resource type's decision with
  the stored resources it depends on and an editable Broker type ID for new
  types (sent as `resourceTypeIds`), and for each action **Resources checked
  by: Broker** or **Command**, with what the command must enforce. A command
  import with accepted actions may accept a preview with no selections. The
  Import tab shows the accepted version, credential, verification and resource
  types and takes the username of a `username_token` execution credential; the
  Actions tab, action drawer and grant editor (from the policy catalog's
  `resourcesCheckedBy`) show who checks each action's resources. Acceptance
  messages report deleted attribute values and dropped types, and a refused
  import change lists the retained grants and stored resources in its
  `target.affectedGrants` (each grant once, by the managed ID or `toml:<index>`
  reference the grant routes accept, with its subjects' reasons joined) and
  `target.resources`, linked to where they are fixed. The preview rejects a
  Broker type ID another service's type already registers, the credential
  mode controls name the modes the manifest declares, a token-only execution
  credential is saved without a username, and verifying a credential the
  command does not verify upstream says it was checked locally. Resource
  creation no longer offers removed imported types.

- Native Confluence personal spaces use existing `confluence_space` exact
  resources and grants with their actual `~`-prefixed keys. Page/blog reads,
  writes, drafts, locators, and search preserve those keys; `all` space coverage
  includes personal spaces subject to the same upstream permissions, exclusions,
  and token restrictions. No caller-relative home selection is implied.

- Git HTTP gateways can present `bearer_token` credentials as HTTP Basic, as
  GitLab's Git endpoint requires: `[gateways.<name>].upstream_token_auth =
  { scheme = "basic", username = "oauth2" }` sends the token as the Basic
  password under the configured username, for service and per-user
  (`git-bearer-token`) credentials alike. The default, `{ scheme = "bearer" }`
  or no setting, keeps `Authorization: Bearer`. `username` is required with
  `basic` and rejected with `bearer`, and must be 1 to 64 printable ASCII
  characters without a colon. `basic_api_token` credentials keep their own
  stored username. Git credential verification presents credentials the same
  way as forwarding. The provider SDK adds the host-only placement
  `host::token_as_basic`, for static and delegated tokens; the crate-boundary
  check rejects it in native, adapter, reference and helper crates.

- Invocation and Git gateway audit records carry `credentialConnection`, the
  credential connection a personal credential came from. It is present when the
  selected credential mode is `per_user`; when a command call passes a
  `per_user` grant even though mixed modes leave `credentialMode` null; and
  when a metadata lookup before policy used the caller's token or OAuth lease,
  even if the call is then denied without a credential mode. It is absent when
  only service credentials are used.

- The provider SDK adds `UpstreamAuthority` and
  `ServiceDescriptor::with_upstream_authority`, through which a backend
  declares the upstream instance its credentials act on, and the provided
  `OAuthDialect::check_consumer_authority`, which accepts every consumer by
  default. The host checks that a token credential connection's consumers act
  on one instance, and that an OAuth connection's registration dialect accepts
  each consumer, at `config validate`, startup, reload and every imported-catalog
  publication. `ServiceCredentialKinds` adds `per_user_delegated`, set with the
  `with_per_user_delegated` builder, which reports that a credential connection
  also offers OAuth; `per_user` reports the token profile's kind, or `oauth`
  for an OAuth-only connection.

- Delegated (OAuth) credential connections serve metadata lookups. A
  lookup-backed action whose `per_user` grant selects an OAuth connection
  looks up with a lease on the caller's connection, acquired only once a
  candidate grant exists, and execution reuses that lease, so one invocation
  has one 401 recovery across its lookups and execution. When scope
  resolution used the shared lookup credential and final policy selects the
  OAuth connection, execution's lookups use the lease acquired after policy.
  An OAuth connection may serve consumers with `per_user` lookup-backed
  actions, and caller discovery offers those actions once the caller has
  connected. A lookup that fails because the
  connection awaits new consent, is being refreshed or has its refresh
  throttled reports that failure, with any retry time, instead of the
  concealed `scope_unresolved`.

- Native backends can mark an action token-only with
  `ActionDescriptor::token_only()` (the `token_only` field) when the upstream
  accepts only a token for it, never delegated access. Eligibility uses the
  credential mode each grant region selects: where the winning grant is
  `per_user` and the caller's credential connection selects OAuth, discovery
  hides the action and invocation denies it, never falling back to a lower
  grant; `service` regions and stored-token selections keep it usable. A
  pre-scope plan that uses the caller's own credential is denied before any
  acquisition, refresh or lookup, and actions without a pre-scope lookup are
  denied after policy and before acquisition, with `credential_not_provisioned`;
  a winning `per_user` grant after a shared pre-scope lookup is denied by final
  policy as `scope_unresolved`. The command-enforced planner omits such grants
  like any unsupported mode. Imported descriptors never carry the marker. The
  conformance backend's `item.upload` uses it. GitLab's
  `project.access_token.create`/`rotate` and
  `service_account.token.create`/`rotate` are token-only.
- The production `gitlab` OAuth dialect (`adapter = "gitlab"`,
  `agent_access_gitlab::GITLAB_OAUTH_DIALECT`, selected by the Broker binary)
  connects a person's account on one GitLab instance through an instance-wide
  confidential GitLab application. Registrations use `client_secret_post`, form
  encoding, `rotation = "rotate_both"` and exactly one permission profile whose
  `audience` is `gitlab` and whose `target` is the normalized instance base of
  `base_url`; the sample and docs default to the `api` and `write_repository`
  scopes. The connected account is `/api/v4/user`'s numeric `id` and
  `username`. Granted scopes come from the token response, or, when a code
  exchange omits them, from `/oauth/token/info` (whose failure fails the
  connection and stores nothing); a refresh that omits them keeps the
  originally granted scopes. Refresh material is consuming. Only consumers on
  the registration's instance, such as GitLab REST and a Git gateway there,
  pass offline validation. See [GitLab OAuth](docs/oauth.md#gitlab).
- GitLab REST accepts delegated access: a `gitlab` credential connection may set
  `oauth`, and people's GitLab REST lookups and actions then use their GitLab
  OAuth connection, with one lease per invocation. Immediately before each
  GitLab request the provider pins the access to its instance (`api_base_url`
  without `/api/v4`) and the `gitlab` audience. A 401 marks the presented
  access rejected and renews it once per invocation, whether it answered a
  lookup or the execution, and repeats that request, including a write or an
  upload; a further 401 fails as `credential_invalid`. A connection failure
  that stops a read-back after GitLab applied a write reports the write as
  `mutation_verification_failed` with an `applied_unverified` receipt,
  `retrySafe: false` and its safe locators. Static tokens are
  presented as before. Token-only project and service-account token actions
  stay unavailable through OAuth. See
  [GitLab REST OAuth connections](docs/providers-gitlab-rest.md#oauth-connections).
- The development `oauth_stub` service declares its `base_url` as its upstream
  authority.
- Optional OAuth login binding, off unless a registration sets
  `login_binding = { provider = "microsoft", upstream_identity_provider,
  upstream_tenant_id }`: the Broker installs an upstream account only when it
  reports a linked identity at that upstream identity provider whose external
  ID is the Entra object ID of the owner's Broker Microsoft sign-in, whatever
  sign-in the browser session used. The owner's sign-in must be in
  `upstream_tenant_id`, the operator's statement of the tenant the upstream's
  provider uses, which must be `browser_auth.oidc.microsoft.tenant_id`.
  Consent start and installation check it, installation again inside its
  transaction. Without a linked sign-in the connections listing reports
  `connectUnavailableReason: "login_binding_required"`, which the portal
  explains, and consent fails with `oauth_login_binding_required`; an account
  linked elsewhere fails with `oauth_login_binding_mismatch` and stores
  nothing. Only the `gitlab` dialect supports it, reading `/api/v4/user`'s
  `identities` (GitLab's Entra provider must use `uid_field = "oid"`);
  validation rejects it on other dialects. Adding, changing or removing it
  makes the registration's owners reconnect. The SDK adds
  `OAuthLoginBinding`, `OAuthLoginProvider`, `LinkedIdentity`,
  `ConnectedIdentity::linked_identities` with `with_linked_identities`, and the
  default `OAuthDialect::supports_login_binding`. See
  [GitLab login binding](docs/oauth.md#gitlab-login-binding).
- Git gateways present OAuth connections. A gateway whose `credential_modes`
  include `per_user` accepts delegated credentials, so its credential
  connection may set `oauth`; for GitLab, people connect once for GitLab REST
  and Git. Each Git HTTP request acquires the caller's lease after policy and
  revalidates it immediately before sending, pinned to the gateway's own
  `upstream_base_url` instance, and presents the access token through
  `upstream_token_auth` (GitLab: `{ scheme = "basic", username = "oauth2" }`).
  Ref discovery recovers once from an upstream 401; `git-upload-pack` and
  `git-receive-pack` POSTs mark the presented access rejected and fail without
  replay. Upstream rejection and a connection needing reconnect (never
  connected, `invalid_grant`, or a refresh with an unknown outcome) answer HTTP
  403 `credential_invalid` with a plain-text message naming the portal
  reconnect, never 401, so Git neither prompts nor has its credential helper
  erase the Broker token. Gateway audit records of a personal connection add
  `providerAudit.gateway.credentialMethod` (`oauth` or `token`). See
  [Git gateway OAuth connections](docs/git-http-gateway.md#oauth-connections).
- The production `atlassian` OAuth dialect (`adapter = "atlassian"`,
  `agent_access_atlassian::ATLASSIAN_OAUTH_DIALECT`, selected by the Broker
  binary) connects a person's Atlassian account for Jira and Confluence
  through an OAuth 2.0 integration from Atlassian's developer console.
  Registrations use `base_url = "https://auth.atlassian.com"`,
  `client_secret_post`, `encoding = "json"`, `rotation = "rotate_refresh"` and
  exactly one explicit permission profile requesting `read:me` and
  `offline_access`, whose `audience` is `api.atlassian.com` and whose `target`
  is the site's cloud ID. Authorization always asks for
  `audience=api.atlassian.com` and `prompt=consent`, with the host's PKCE
  challenge. The connected account is `/me`'s `account_id`. Granted scopes come
  from the token response: a code exchange without `scope` fails and stores
  nothing, and a refresh without it keeps the originally granted scopes.
  Targets are the sites `accessible-resources` lists, with each site's product
  entries merged into one target with the union of their scopes plus the
  granted `read:me`; connecting requires the profile's site with every
  requested scope. Refresh material is consuming, and Atlassian's HTTP 403
  `invalid_grant` requires reconnect. Only consumers acting through the
  Atlassian gateway on the profile's cloud ID pass offline validation.
  Disconnect stays local (`remoteRevocation: "not_requested"`). The docs cover
  the integration's setup, scopes, per-product registrations for people with
  only one product, the shared 65,000-point hourly quota and the 90-day
  inactivity expiry. See [Atlassian OAuth](docs/oauth.md#atlassian).
- Jira and Confluence accept delegated access: a credential connection they use
  may set an `atlassian` OAuth registration, and people's lookups and actions
  then use their Atlassian connection, with one lease per invocation. OAuth
  always goes through the Atlassian gateway,
  `https://api.atlassian.com/ex/{jira|confluence}/{cloudId}/`, while stored and
  service tokens keep routing by kind. Immediately before each request,
  including lookups, list pages and read-backs, the provider pins the access to
  the gateway route's cloud ID and the `api.atlassian.com` audience; an
  attachment download does so before each redirect hop within the site. A 401
  marks the presented access rejected and renews it once per invocation,
  whether it answered a lookup or the execution, and repeats that request,
  including a write or an upload; a further 401 fails as `credential_invalid`
  asking the person to reconnect Atlassian. A connection failure before a write
  keeps its own reason without a receipt, also for an attachment batch before
  any upload applied; one that stops a read-back after the write was accepted
  reports `mutation_verification_failed` with an `applied_unverified` receipt,
  `retrySafe: false` and its safe locators. Credential verification stays
  token-only. The provider guides list each action's Atlassian OAuth scopes,
  and the sample and OAuth guide request that inventory: `read:me`,
  `offline_access`, `read:jira-work`, `write:jira-work` and Confluence's
  classic (REST API v1) and granular (v2) scopes, without `read:jira-user` or
  `read:confluence-space.summary`. See
  [Jira](docs/providers-jira.md#oauth-connections) and
  [Confluence](docs/providers-confluence.md#oauth-connections) OAuth
  connections.
- GitLab OAuth remote revocation. When the Broker ends a GitLab OAuth family
  (disconnect, a reconnect or account replacement, a consuming refresh whose
  outcome was lost, or disabling the owner), it fences it locally and, in the
  same transaction, keeps its latest tokens in an encrypted pending revocation;
  it then revokes the refresh and access tokens through GitLab's
  `POST /oauth/revoke`. Disconnect makes the first attempt before responding; a
  background worker in each serving process retries each throttled, unanswered
  or client-rejected (`invalid_client`, `unauthorized_client`) token on its own
  schedule, after 30 s, 2 min, 10 min and 1 h or a longer `Retry-After`, fails
  it after the fifth try, and at startup resumes revocations a stopped process
  left pending. A refresh in flight at the fence never installs its successor,
  which is revoked too, also when it arrives after another process presumed the
  refresh lost or the rest of the family was revoked; a lost refresh outcome
  makes the family `unconfirmed`. A remote failure never restores access.
  `DELETE /v1/oauth/connections/{registration}`, `GET /v1/oauth/connections`
  rows and OAuth rows of `GET /v1/credentials` report `remoteRevocation`
  (`not_requested`, `pending`, `revoked`, `failed` or `unconfirmed`) for the
  owner's ended families; a registration whose revocation is `pending`,
  `failed` or `unconfirmed` stays listed, as a cleanup-only row after its owner
  lost every grant and disconnected. The portal shows the state in connection
  rows as concerning ended connections, beside the current connection's own
  status, and in the disconnect notice. Dialects that do not revoke, including
  Google, imported MCP OAuth and the development stub, report `not_requested`. A registration fingerprint
  change, removed registration or disabled OAuth cannot revoke; see
  [remote revocation](docs/oauth.md#remote-revocation) for the GitLab-side
  action. The SDK adds the default `OAuthDialect::supports_revocation` and
  `OAuthDialect::revoke`, with `TokenRevocation`, `OAuthTokenType` and
  `RevocationOutcome`.
- The portal's principal **Credentials** tab lists a person's OAuth
  connections read-only, for administrators and auditors alike: one row per
  registration from `GET /v1/admin/principals/{principal}/credentials`, marked
  **Managed by user**, with the services using it, the registration and the
  remote revocation of the connections the Broker ended, also as a cleanup-only
  row after the person lost every grant. **Needs attention** counts failed and
  unconfirmed revocations. The tab shows no connection status or connected
  account, which that response does not carry, and offers no Connect,
  Reconnect or Disconnect: only the person acts on their OAuth account.
- Managed-store migration `028_oauth_revocations` adds the `oauth_revocations`
  table of pending remote revocations, one per ended family, naming a refresh
  attempt whose late successor it still captures, and changes no existing row. Its
  encrypted payloads join key readiness, the used-key inventory and
  `admin credentials rewrap`. Rolling back across it needs a pre-migration
  backup.

### Changed

- Jira and Confluence validation accepts OAuth connections through the
  Atlassian gateway: a per-user connection with `oauth` alone, or with the
  `atlassian-bearer-token` profile, is valid when the provider allows
  `api.atlassian.com`, and counts as the gateway's execution credential. An
  `oauth` connection without the gateway fails with
  `credentials.per_user.<service> offers delegated (OAuth) access, which
  requires providers.<service>.allowed_upstream_hosts to include
  api.atlassian.com`, and a connection combining `atlassian-api-token` with
  `oauth` is rejected with `credentials.per_user.<service> combines OAuth with
  a basic_api_token profile; ...`. A gateway without either credential now
  reports `no bearer_token or OAuth execution credential is configured`.
  `credentials.service` entries must still be `bearer_token` on the gateway.
- `agent-access-atlassian` is a `native` module crate: it registers the
  `atlassian` OAuth dialect, the assembly links it directly, its build status
  module is listed with release provenance, and `api/agent-access-atlassian.txt`
  inventories its selection entry point. Its Jira and Confluence helpers stay
  unsupported outside the first-party providers; their backend seams
  (`JiraBackend`, `ConfluenceBackend`) now take an `AtlassianCredential`, a
  static token or the invocation's delegated access, instead of a static
  credential.
- Git gateway error responses are labeled `Content-Type: text/plain;
  charset=utf-8`, so Git shows their one-line reason as `remote:` output when
  ref discovery fails. Their status, reason code header and body are unchanged.
- Existing Confluence `all` resources used by grants, groups, and token
  restrictions now cover personal spaces visible to the selected upstream
  credential; those keys were previously rejected. Review this coverage before
  upgrading, especially service-mode grants using shared credentials. To limit
  access to team spaces, select exact team-space resources; exact personal-space
  exclusions cover only the listed keys and do not exclude future personal spaces.
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
- Late raw-download failures of GitLab, Jira, Confluence and CloudBees CI
  record uniform messages in their terminal audit record, such as
  `GitLab download exceeded the download limit` or
  `Jira attachment download stalled`, without upstream error detail. Reason
  codes are unchanged, except that a GitLab repository file download whose
  request deadline expires mid-body reports `upstream_timeout` instead of
  `upstream_connection_failed`. A GitLab, Jira or Confluence download whose
  body overruns its `Content-Length` now fails before the excess is delivered
  instead of at the end, still with `upstream_protocol_failed`.
- The GitLab webhook destination diagnostic for repeated patterns now reads
  `contains duplicate normalized entry` instead of
  `contains duplicate normalized destination`.
- GitLab writes without a verification contract (issue, note, merge-request
  and merge, general discussion, discussion-note edit/delete, resolve/reopen,
  branch, file, commit, pipeline and job mutations, and project uploads) whose
  request may have reached GitLab but got no response, because it timed out
  (including a stalled upload) or its connection failed after sending, now add
  `mutationStatus: "unknown"`, `retrySafe: false` to their unchanged
  `upstream_timeout` or `upstream_connection_failed` error, which previously
  carried no result. The same writes now also report `mutationStatus:
  "unknown"`, `retrySafe: false` for a redirect or 5xx response
  (`upstream_failed`), since the Broker never follows a redirect and a proxy can
  answer 5xx after a committed write, and for an upstream failure GitLab does
  not classify, and `mutationStatus:
  "applied_unverified"`, `retrySafe: false`, `verificationStage:
  "mutation_response"` with request-derived `safeLocators` when GitLab answered
  with a success status whose response then failed, stalled, exceeded the byte
  cap, did not parse, carried a body on a no-content response or did not match
  the request. Reasons, statuses and messages are unchanged; 4xx rejections,
  throttling and failures before sending keep no receipt.
- Imported MCP and OpenAPI write failures whose request was never dispatched
  (`toolDispatched: false` or `operationDispatched: false`: the tool call was
  never sent, or the Broker refused its URL or proved it unsent) now report
  `retrySafe: true` with their unchanged `mutationStatus: "not_applied"`
  instead of `retrySafe: false`. Dispatched failures keep
  `mutationStatus: "unknown"`, `retrySafe: false`.
- A CloudBees CI `build.trigger` POST and a Teams `notification.send` request
  that the Broker proves were never sent now add `mutationStatus:
  "not_applied"`, `retrySafe: true` to their unchanged error (CloudBees CI:
  `upstream_connection_failed` or `upstream_timeout`, `CloudBees CI request
  failed`; Teams: `Teams notification request was not sent`, which also covers
  a refused endpoint URL). Both previously carried no result. Reads, including
  the trigger's job read, carry no receipt.
- A Teams notification that may have reached the Workflow without a confirmed
  outcome (a timeout, a transport failure or another unclassified failure
  after sending, a redirect or a 5xx response) and a CloudBees CI trigger POST
  answered with a redirect, or failing without a response in a way other than
  a timeout, transport failure or proven-unsent request, now add
  `mutationStatus: "unknown"`,
  `retrySafe: false` to their unchanged error. CloudBees CI's existing
  `applied_unverified` outcomes are unchanged.
- A Gmail archive, trash or restore whose request the Broker proves was never
  sent now reports `mutationStatus: "not_applied"`, `retrySafe: true` with its
  unchanged `upstream_connection_failed` or `upstream_timeout`, and its message
  drops the `mutation outcome may be unknown, inspect before retrying` suffix
  (`Gmail request failed`). Mutations that may have reached Gmail keep the
  suffix.
- Gmail archive, trash and restore failures that may have applied now carry a
  receipt with their unchanged reason and message: `mutationStatus:
  "unknown"`, `retrySafe: false` after a timeout or transport failure once
  sent, a redirect or 5xx response or the operation deadline, and
  `mutationStatus:
  "applied_unverified"`, `verificationStage: "mutation_response"` with the
  requested `message` or `thread` ID as `safeLocators` when Gmail answered
  with a success status whose body could not be read or parsed.
- Jira write actions (`issue.create`, `issue.child.create`, `issue.update`,
  `issue.parent.set`, `issue.dependency.add`, `comment.add`, `comment.reply`,
  `comment.update`, `comment.delete`, `comment.property.set`,
  `comment.property.delete`, and `attachment.add` when its first upload was not
  sent) whose request the Broker proves was never sent now add
  `mutationStatus: "not_applied"`, `retrySafe: true` to their unchanged error,
  which previously carried no result: `upstream_connection_failed` or
  `upstream_timeout` for single writes, and `upstream_failed` with
  `Jira attachment upload failed` for the attachment batch.
- Jira write failures that may have applied now carry a receipt with their
  unchanged reason and message: `mutationStatus: "unknown"`,
  `retrySafe: false` when the mutation request got no response (or an
  unclassified failure), a redirect or a 5xx; `mutationStatus:
  "applied_unverified"` at
  `mutation_response` when Jira answered with a success status whose response
  then failed, did not parse or did not match the request; and
  `applied_unverified` at the read-back stage when the read-back after an
  applied create, child create, update, parent set or dependency add failed or
  did not match, or the result exceeded the response limit (throttled
  read-backs keep their `mutation_verification_failed`). An `attachment.add`
  batch in which an upload may have applied reports `unknown` alongside its
  result, unless throttling already reported it as `applied_unverified`.
- Confluence write actions (page create, update and move; blog create and
  update; page and blog draft create, stage, update, publish and discard;
  footer comment add; comment update, delete and reply; and page, blog and draft
  attachment batches whose first upload was not sent) whose request the Broker
  proves was never sent now add `mutationStatus: "not_applied"`,
  `retrySafe: true` to their unchanged error: `upstream_connection_failed` or
  `upstream_timeout` for single writes, and `upstream_failed` with the batch's
  existing message for attachment batches. Draft attachment batches keep their
  `status: "partial"` result alongside the receipt.
- Confluence write failures that may have applied now carry a receipt with
  their unchanged reason and message: `mutationStatus: "unknown"`,
  `retrySafe: false` when the mutation request got no response (or an
  unclassified failure), a redirect or a 5xx; `mutationStatus:
  "applied_unverified"` at
  `mutation_response` when Confluence answered with a success status whose
  response then failed, did not parse or did not match the request, or when
  anything after the accepted write failed; and `applied_unverified` at the
  read-back stage when a read-back request failed (throttled read-backs keep
  their `mutation_verification_failed`). Page, blog and draft attachment
  batches in which an upload may have applied report `unknown` alongside their
  result, unless throttling already reported `applied_unverified`.

- Agent token issuance uses a dedicated page for personal and administered
  accounts, with the grant builder's shared read-only/write-capable action
  selector, a collapsible section per restricted service, a summary of each
  service's action and resource selection, a full-width live access preview,
  and persistent Issue/Cancel actions that count remaining issues and link to
  the first. Service-specific filters and column All/None preserve selections
  outside the matching actions, and resource choices list only the resource
  types the service's actions use. Unsaved navigation requires confirmation,
  and successful issuance selects the new token while displaying its one-time
  secret and MCP setup.
- The shared action selector lists each column's actions in a grid that uses
  the available width. Effective-access previews list action names without
  separators, breaking long names after their dots, and collapse rows with more
  than six actions to a count. The grant and token editors' action bars use a
  neutral tone unless something needs fixing.

### Fixed

- Delegated credential installation retains safe secret-reference provenance in
  completion audit. All credential-install paths reject references produced by
  Broker administration, preventing invocation tokens from becoming upstream
  connection credentials while preserving approved receiver use.
- Grant PATCH rechecks current authentication and policy-write authority inside
  its transaction, including when replacing grant subjects.
- Grant-subject edits preserve the active policy snapshot when the edited grant
  is disabled or the final subject is removed with `disable_grant`. Disabled
  grants cannot become effective or displace unrelated active grants.
- Delegated writes that fail before starting a transaction report
  `not_dispatched`; shared management adapters return storage unavailability for
  a poisoned connection lock.

- GitLab REST resolves the old path or web URL of a renamed, moved or
  transferred project to the project's current identity. GitLab 16.7 and later
  answer a lookup of the old path with a redirect naming the project's numeric
  ID, which the Broker reported as `upstream_failed`. It now takes only that
  ID, without following the redirect, reads the project by ID through
  `api_base_url`, and authorizes, executes and reports its current path. A path
  another project has since taken names that project, as in GitLab. Every
  action also requires the project it looks up again at execution to have an
  authorized path, so a project that moved between authorization and execution
  to a path that was not authorized is refused with `scope_unresolved` instead
  of acted on. Grants name paths: a project that took over an authorized path
  in between passes, as any project at that path does.
- Jira and Confluence attachment downloads through the Atlassian gateway
  presented the credential, such as a service account's bearer token, on every
  redirect hop to `api.atlassian.com`, whose one origin serves every Atlassian
  site. A redirect to another site's cloud ID, directly or back from a media
  host, therefore received the credential and could return that site's bytes.
  Downloads now present the credential only within the route's site (the
  configured cloud ID's `/ex/<product>/<cloudId>/` path, or the tenant host),
  and such a redirect fails with `upstream_protocol_failed` before it is sent.
  Media host redirects still work without the credential.
- The Broker now enforces `limits.max_download_bytes` on every raw download
  itself instead of relying on each provider to bound its stream. A download
  that would pass the limit delivers only the bytes within it, then fails as a
  late stream failure with `attachment_size_denied`, the reason the SDK's
  bounded downloads report; its terminal audit record is `failed` with the
  delivered byte count and digest. An in-memory body over the limit fails
  before its first byte. The CLI and stdio MCP report the truncated download as
  failed and leave an existing destination unchanged. Provider limits are
  unchanged.
- Management credential verification and imported-service discovery report a
  provider failure's own decision in the response and its management audit
  record instead of always `deny`: upstream failures such as `upstream_timeout`,
  host-origin failures such as a delegated lease's `concurrency_limited`, and
  domain reasons defined as `error` now report `decision = error`. Host
  failures preparing discovery, such as an unavailable store or a missing
  encryption key, still report `deny`. Reason codes and HTTP statuses are
  unchanged.
- GitLab webhook destination patterns that differ only in a nondefault port,
  such as `https://hooks.example.com:8443/**` and
  `https://hooks.example.com:9443/**`, are no longer rejected as duplicates.
  A pattern with an explicit default port, such as `:443` for `https`, is still
  a duplicate of the same pattern without it.
- The `broker_listening` event reports the address each listener bound rather
  than the requested one, so `serve --listen 127.0.0.1:0` names the port the
  system assigned instead of port 0. Other addresses are reported as before.
- Restricted token drafts wait for complete context, service, and action
  selections before requesting an effective-access preview, avoiding spurious
  `allowedServices must not be empty` errors. Incomplete restrictions cannot
  silently become a token that follows all current grants.
- Confirming **Discard changes** after browser Back or Forward in the grant
  editor now leaves the page instead of leaving the confirmation pending.
- GitLab Git gateway examples in the sample broker config and CLI guide now use
  Basic credentials (`basic_api_token` or the `git-basic-api-token` profile)
  instead of a Bearer token, which GitLab's Git HTTP endpoint rejects. The
  configuration reference's gateway example includes its Basic service
  credential, and the Git gateway guide notes that GitLab accepts the access
  token with any non-empty username, such as `oauth2`.
- Jira and Confluence configurations that route through the Atlassian gateway
  (`api.atlassian.com` in `allowed_upstream_hosts`) now validate per-user
  `managed_store` bearer profiles (`jira-bearer-token`,
  `confluence-bearer-token`). Backend validation previously compared the raw
  `managed_store` type with `bearer_token` and rejected every per-user entry,
  so these documented profiles could not be used. Gateway mode still requires
  every configured service and per-user credential to resolve to
  `bearer_token`.
- An HTTP MCP response that a client has not read, including a `202`
  notification or `DELETE` response, no longer keeps the runtime generation
  that admitted it, or that generation's state locks, alive. It keeps only
  its MCP capacity lease and delivery deadline.
- Graceful shutdown now closes HTTP MCP sessions still open once the
  listeners have drained, after in-flight responses are delivered.
  Previously each open session kept the broker state, including its state
  locks, until the process exited. Closing a session still never cancels an
  admitted operation.
- GitLab `webhook.create`, `webhook.update`, `webhook.custom_header.set` and
  `webhook.custom_header.delete` returned a plain error when GitLab accepted
  the write but rejected its readback with a 4xx status such as 401, 403 or
  404, or when the readback exceeded the configured content bounds. The error
  had no `applied_unverified` receipt, no `retrySafe: false` and no webhook
  ID, so a caller who retried could create a duplicate webhook. Every failure
  of a readback after an accepted write, with a static token or an OAuth
  connection, now reports `mutation_verification_failed` with that receipt and
  the webhook's ID, the one GitLab returned for a create. Failures before the
  write, and GitLab rejecting the write itself, keep their own reason without
  a receipt. The other GitLab writes with a readback already reported every
  readback failure this way.
- GitLab writes with a verification contract (inline discussions, discussion
  replies, draft notes, draft publication, review submission, approvals,
  suggestion application, webhook and provisioning mutations) reported a write
  the Broker could not prepare, such as one the upstream allowlist refuses, as
  `mutation_verification_failed` with `applied_unverified` and
  `retrySafe: false`, although nothing was sent. Approvals, draft publication,
  review submission and suggestion application could also report it so when
  their probe of the target failed. Such a write now keeps the reason of its
  cause, such as `upstream_protocol_failed`, without a receipt or a probe. A
  readback the Broker could not prepare after an accepted write still reports
  the write as `applied_unverified`.
- Confluence search, blog search, and page and blog reads failed with
  `upstream_protocol_failed` ("Confluence browser URL failed validation")
  whenever a result lived in a space whose URL an administrator had changed:
  Confluence keeps the key, such as `RAILS`, in the API but links under the
  alias, such as `/spaces/VLABS/pages/...`. One such result failed its whole
  search page. A link's space segment now matches the space key or the space's
  URL alias, taken from the v2 space object's `currentActiveAlias` where the
  Broker already reads it, otherwise from the space object's own
  `_links.webui`, with no extra upstream request. Page and blog URL locators
  naming the alias resolve to the content's space key; a URL's space segment is
  never a scope. A link that still fails a check is replaced by the constructed
  `viewpage.action?pageId=` or `/spaces/<key>` URL instead of failing the
  operation, and is recorded in its audit under `browserUrlFallbacks` with the
  rule it failed and a masked link shape.
- Confluence search and blog search checked returned content against the space
  names the caller wrote rather than the authorization boundary. With
  all-space access, `space = VLABS` in CQL, or `spaces: ["VLABS"]`, narrowed
  the check to `VLABS`. A result that Confluence resolved to the space's key,
  such as `RAILS`, then failed the whole search with `scope_unresolved`.
  Returned content is now checked against the granted space keys or all-except
  exclusions, as `docs/design.md` describes. A caller-written name still
  narrows the query, but cannot widen access or lift an exclusion.
- Jira references that use a previous project key, which Jira keeps as aliases
  after a project key change, could be refused although Jira resolves them.
  Modern issue URLs (`/jira/.../projects/{project}/issues/{key}`) whose project
  segment differs from the key prefix, such as an old project with a current
  key, were rejected as `locator_invalid` before the lookup. They are now
  accepted when the segment is a valid project key, and the issue key alone
  identifies the issue. Search with all-project access rejected the current
  issues Jira returns for JQL `project = OLD` or explicit `projects: ["OLD"]`,
  because containment was narrowed to the names the caller wrote. Returned
  issues are now checked against the authorization boundary only. A create
  whose project key Jira resolved to a renamed project's current key reported
  `upstream_protocol_failed`; it is now `scope_unresolved`, keeping its
  `applied_unverified` receipt. Issues are still authorized by their current
  project, never by the alias prefix, and results report the current key.
- Jira comment, comment-property, attachment (`attachment.add`,
  `attachment.download`, `attachment.list`) and `verify` actions confirmed the
  issue again at invocation but did not check its project against the admitted
  scopes. An issue moved to an ungranted project after authorization was still
  read or written. Invocation now denies such an issue with `scope_unresolved`
  before any execution request, as issue reads and mutations already did.
  `attachment.add` confirms the issue immediately before its first upload
  instead of reusing the lookup from body admission, which no longer calls Jira.

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
