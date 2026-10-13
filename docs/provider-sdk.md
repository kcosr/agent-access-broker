# Provider SDK guide

This guide is for developers who write a native provider: a Rust crate that
gives Agent Access Broker typed actions for one upstream service. A provider
crate depends on the provider SDK, `agent-access-provider`. It declares
configuration, resource types and actions. It resolves the resources an action
touches and executes admitted invocations against its upstream. The Broker host
owns everything around that: identity, policy, credential custody, admission,
limits, audit and process lifecycle.

Providers are ordinary compiled crates. An assembly selects them when it is
built, and changing a provider means rebuilding that assembly. There is no
runtime module loader, plugin protocol or stable binary interface. The upstream
`agent-access-broker` executable is one assembly. Another team can build its own
distribution from upstream crates and its own providers; see the
[downstream assembly guide](downstream-assembly.md).

The surrounding runtime contract is in [the architecture](design.md), wire
reasons and status mapping are in [the HTTP API](http-api.md), and configuration
keys are in [the configuration reference](configuration.md). The
[worked example](#worked-example) at the end is a complete minimal provider.

## Contents

- [Supported surface](#supported-surface)
- [Trust model](#trust-model)
- [Registration and configuration](#registration-and-configuration)
- [Descriptors and scope resolution](#descriptors-and-scope-resolution)
- [Authority and credentials](#authority-and-credentials)
- [Network](#network)
- [Signing and continuations](#signing-and-continuations)
- [Reasons and outcomes](#reasons-and-outcomes)
- [Testing](#testing)
- [Compatibility policy](#compatibility-policy)
- [Worked example](#worked-example)

## Supported surface

The supported Rust interfaces are:

- **The provider SDK**, `agent-access-provider`: the provider contract at the
  crate root, where each item has exactly one path; the `presentation` module;
  the `host` module of host cooperation ports; the `deps` module of third-party
  re-exports; and the `test_support` module behind its `test-support` feature.
  The crate documentation summarizes the same surface.
- **The Broker host's composition interface**, `agent-access-broker-host`:
  `BrokerComposition`, `BrokerApplication`, `AssemblyIdentity` and their
  companion types, plus its test support. Assemblies use them; see the
  [downstream assembly guide](downstream-assembly.md).
- **Selection entry points of shipped modules**: the registration statics of the
  shipped native providers and OAuth dialects, such as
  `agent_access_cloudbees_ci::CLOUDBEES_CI_BACKEND`, and the `registration()`
  functions of the shipped MCP and OpenAPI import adapters.
- **Public types that those signatures expose**, to the extent they expose them.

The checked-in [public API inventory](../api/README.md) lists this surface
item by item. A provider crate's production dependencies are the SDK and,
optionally, ordinary helper libraries. It never depends on `agent-access-core`,
the host, an assembly, the CLI or an import adapter. Upstream enforces this
for its own workspace with `node scripts/check-crate-boundaries.mjs`, and a
downstream provider repository should hold itself to the same rule.

These traits are intentionally implementable:

| Trait | Implemented by |
| --- | --- |
| `Provider` | Each provider instance: scope resolution, body admission, credential verification and invocation. |
| `BackendConfig` | Each provider's parsed `[providers.<kind>]` table. |
| `OAuthDialect` | An OAuth companion for one family of authorization servers. |
| `EmbeddedBodyCodec`, `WholeResultRenderer` | Optional presentation of rich bodies and whole results. |
| `host::UpstreamClientFactory`, `StableSigningKey`, `DelegatedLease` | The host, and deterministic doubles in provider tests. |

Supported types are built through constructors and builders, never struct
literals, so a compatible release can add a field:

- Static registrations and definitions, such as `BackendRegistration`,
  `ResourceTypeDescriptor`, `ProviderReasonDefinition` and
  `ContinuationFamily`, have private fields, `const` builders and accessors.
- Data types whose fields are the data the other side reads, such as
  `ProviderResult` and `ServiceDescriptor`, keep public fields but are
  non-exhaustive and built with `new` and `with_*` builders.
- Inputs only the SDK reads, such as `UpstreamClientSpec` and `RedirectRules`,
  and lent credential material, such as `DelegatedAccess`, have private fields
  and constructors.
- Values the host constructs for a request, such as `ScopeRequest`,
  `ExecutionCredential`, `DelegatedBindingId`, `AdmittedRequest` and
  `ProviderInvocation`, have private fields. The `host` module constructs them
  for the host, `test_support` constructs them for provider tests, and provider
  code reads them through accessors.

Extendable enums are non-exhaustive. The
[construction and exhaustiveness policy](../api/README.md#construction-and-exhaustiveness-policy)
lists the intentionally exhaustive items.

The following are not supported provider interfaces:

- The Rust API of `agent-access-core`. It is host implementation, even where a
  supported signature exposes one of its types.
- Helper crates such as `agent-access-content` and `agent-access-atlassian`.
  They are ordinary libraries for the first-party providers, not SDK contracts.
- Custom imported-protocol adapters. The MCP and OpenAPI adapters are shipped
  selections only; their construction contract is internal to core.
- Typed CLI wrappers and provider-specific portal plugins. A provider without
  typed CLI commands works through the generic `agent-access invoke`, JSON
  `send`, HTTP and MCP surfaces, and the portal renders its descriptor-driven
  metadata.
- Several configured instances of one native kind. A kind has one
  `[providers.<kind>]` table and one service.

## Trust model

One distribution may link modules owned by several teams. Every linked native
provider, OAuth companion and import adapter is trusted with the entire
deployment: every credential, store, file, environment variable, network route
and audit record the process can reach. The assembler must review and qualify
those dependencies before linking them.

The SDK's checks are cooperation contracts, not a sandbox. Read-only authority
values, privately constructed credentials, network wrappers and reason
validation keep a cooperating provider within its contract, and they catch
bugs. They cannot stop linked Rust code from deliberately bypassing them, for
example by building another HTTP client or reading process state directly. In
particular:

- The host-origin failure branch ([`host::port_failure`](#contract-failures)) is
  public across crates, so a module could forge a host failure. Modules use host
  ports only in their documented roles.
- Module metadata and the assembly's provenance map are labels, not
  cryptographic attestation; whoever builds the assembly controls them.
- A development-only registration is gated by configuration admission. Linking
  it into a production assembly is permitted; configuring it in production is
  rejected.

Deploy mutually untrusted modules in separate processes or deployments, each
with its own state, keys and credentials. The broader security posture is in the
[security model](security-model.md#linked-module-trust).

## Registration and configuration

### Registration

A provider crate exports one `BackendRegistration` static. Selecting it in an
assembly's composition is the only host change a provider needs:

```text
BackendRegistration::new(module_metadata!(), "notes", parse_backend_config::<NotesConfig>)
    .with_resource_types(&[&NOTEBOOK_RESOURCE])
    .with_domain_reasons(&[&NOTE_ARCHIVED])
```

- `module_metadata!()` captures the declaring package's Cargo name and version.
  The host reports it in the build status's module inventory, and an assembly
  keys its provenance map by it. Several registrations from one package, such as
  a native provider and its OAuth dialect, are roles of the same module.
- The kind is the `[providers.<kind>]` table name and the service ID. It
  matches `^[a-z][a-z0-9_-]{0,62}$`. The host rejects the kind `broker`, a
  kind another selected module uses, and a configured Git gateway or retained
  imported service with the same name. These checks apply even when the
  provider is not configured.
- `with_resource_types` lists the resource types the provider defines, in
  listing order; see [typed resources](#typed-resources).
- `with_domain_reasons` lists the provider's own failure reasons; see
  [domain reasons](#domain-reasons).
- `development_only()` marks a fixture. Configuring it requires a
  non-production deployment with `deployment.enable_fake_service = true`.

An OAuth companion is a separate `OAuthDialectRegistration` static, built with
`OAuthDialectRegistration::new(module_metadata!(), id, &DIALECT)` and selected
independently. Several providers can then share one dialect. The host owns
consent, PKCE, state, encryption, single-flight refresh and connection fences.
A dialect owns the wire protocol: authorization URLs, token requests, identity
and target discovery, and failure classification. It sends each token request
once through `OAuthHttp`, which the host routes. The
[OAuth guide](oauth.md) describes the operator-facing behavior.

### Configuration parsing and validation

The parser deserializes one `[providers.<kind>]` table into a type that
implements `BackendConfig`. `parse_backend_config::<T>` serves any `T` that
derives `Deserialize`. Reject unknown fields with
`#[serde(deny_unknown_fields)]`.

`BackendConfig` methods run offline, at startup, on reload and in
`config validate`:

- `validate(&ValidationContext, &mut errors)` pushes messages that name fields
  under `providers.<kind>`. The context exposes only `deployment.environment`
  (with `production()`), the policy authority, the Broker limits and the
  credential kinds configured for this service under `credentials.service` and
  `credentials.per_user`. It does not expose the rest of the configuration or
  any store.
- `validate_resource_attributes` checks private resource values against the
  active configuration. Its diagnostics must not contain the supplied values,
  because administrators see them.
- `descriptor()` returns the service descriptor. It depends on the
  configuration alone, because offline validation calls it before any provider
  exists. A descriptor may vary with configuration; Jira and Confluence omit
  write actions when their content formats are disabled.
- `egress_proxies()` lists configured per-service proxies with their
  configuration labels. The host checks each proxy at startup, even when an
  environment proxy takes precedence.

The SDK provides pure validators for common fields:
`validate_upstream_base_url` (HTTPS, or loopback HTTP outside production),
`validate_upstream_allowlist`, `validate_egress_proxy_config`,
`validate_tenant_host` and the attachment and limit relation checks. None of
them reads files, the process environment or secret references; the host
resolves secret references such as a proxy's `password_ref`.

### Building a provider

`build(&BuildContext)` constructs the provider for one runtime generation. It is
synchronous and offline. It may prepare clients and local capabilities, but it
never contacts an upstream, verifies a credential or refreshes OAuth. The build
context offers:

- `limits()`, the Broker's `ProviderLimits`;
- `clients()`, the host's upstream client factory (see [network](#network));
- `attribution()`, the attribution footers enabled for this service;
- `stable_signing_key()`, the stable key scoped to this service, when one is
  configured (see [signing](#signing-and-continuations)).

A failure is a `ProviderBuildError`. `ProviderBuildError::invalid` carries a
safe configuration diagnostic. When the host could not construct a client,
`UpstreamClient::build` returns an error that keeps the host's own cause for its
logs.

A reload builds a new provider from the new configuration and leaves admitted
operations on the generation that admitted them. A reload cannot link or unlink
a crate; that needs a new build and a restart.

## Descriptors and scope resolution

### Service descriptors

The `ServiceDescriptor` is the one authoritative description of the service.
Configuration validation, policy validation, admission, discovery, the runtime
catalog, OpenAPI, the send schema, MCP tools and the portal's credential forms
all read it. The host validates every descriptor before activation and in
`config validate`; see [the descriptor checks](design.md#service-descriptors).

Build actions with `ActionDescriptor::new(name, description, input_schema)` and
its builder methods:

| Method | Declares |
| --- | --- |
| `.scope(name)` | The resource scope the action is authorized against. Without one the action is action-only. |
| `.credential_modes(["service", "per_user"])` | The grant modes that may select its credentials. |
| `.read_only()` | A reviewed read. Actions default to `read_only = false`; never infer it from a name. |
| `.lookup(LookupRequirement::ScopeResolution)` | That scope resolution needs a host-selected lookup credential before policy. `LookupRequirement::Execution` asks for one only at execution. |
| `.search_contained()` | That the host computes a search boundary and the provider constrains its query to it. |
| `.raw_download()`, `.multipart_upload(plan)` | Streamed response bodies, or admitted file uploads. |
| `.resource_attributes()` | That dispatch needs the private attributes of the one admitted exact resource. |
| `.sensitive_output(pointer)` | A JSON pointer into `/result` whose value is a deliberate secret. The host sends such responses with `Cache-Control: no-store`. |
| `.requires_stable_signing_key()` | That the action issues durable handles, so the Broker must hold a stable key. |
| `.documentation(json)`, `.presentation(..)`, `.attribution(..)`, `.upstream_resource_ownership(..)` | Extended usage text, rich rendering, attribution footers and static ownership metadata. |

Keep the description and input schema concise; they are part of initial MCP tool
discovery. Put grammar, limits and examples in `documentation`, which detailed
discovery, OpenAPI and the send schema carry but MCP tool definitions omit.

`CredentialDescriptor` states whether invocations need a broker-selected
execution credential (`CredentialDescriptor::without_execution_credential()`
when they do not), which static kinds `credentials.service.<service>` accepts,
managed-store credential profiles, inputs that credential verification needs,
and, with `.delegated(description)`, that per-user delegated OAuth credentials
are accepted.

### Typed resources

A `ResourceTypeDescriptor` static defines one resource type.
`ResourceTypeDescriptor::new(id, label, plural_label, example, canonical)`
takes an identifier (`^[a-z][a-z0-9_]{0,63}$`), labels, an example and a
canonical-target grammar, and supports exact and all selectors.
`with_namespace(NamespaceSelectorDescriptor::new(..))` adds namespace selectors,
`with_attributes` adds private string attributes, and `with_action_inputs` adds
an action-input projection. Exact selectors and every resolved target must
satisfy the canonical grammar, which keeps namespace prefix matching sound.
Policy validation, resource management, discovery and the portal read the
published metadata.

Private attributes (`ResourceAttributeDescriptor::required` or `optional`)
are secret values on exact managed resource entries, such as a Teams Workflow
URL. The host encrypts them, reveals them only through an audited administrator
action, and decrypts only the admitted resource's attributes immediately before
dispatch.

The host always registers the `git_repository` type. A provider may scope
actions to it, as GitLab REST does, instead of defining its own. The registry
rejects duplicate type identifiers across selected providers.

`Provider::resource_roots` may return configuration-derived roots of a type,
such as CloudBees CI controller aliases, which discovery filters by each
caller's coverage. Neither roots nor renderer support authorize anything. Each
action has one resource scope, but that scope may name several resources that
one grant must cover together, as GitLab cross-project operations do.

### Scope resolution

```text
async fn resolve_scopes(&self, request: ScopeRequest<'_>) -> Result<ScopeResolution, ProviderError>;
```

The host calls `resolve_scopes` for every ordinary action before it authorizes
the action. The `ScopeRequest` carries the service and action, inputs validated
against the schema, the host-selected execution context, the minimal caller
identity, correlation and, only for `LookupRequirement::ScopeResolution`
actions with a viable grant path, the host-selected lookup credential. It
carries no admitted authority and no execution credential. A provider must not
use another lookup credential or fall back to a shared one.

- A local resolver parses the inputs and returns at once:
  `ScopeResolution::resources(scopes)`, where `ResourceScopes` maps each scope
  name to its canonical values.
- An action-only provider returns `ScopeResolution::no_resources()`.
- A provider that looks up upstream metadata must use only the lookup
  credential.
  The host keeps lookup failures concealed until resource authorization has
  succeeded.

The host then intersects the scopes with token restrictions and selects one
grant covering every required resource. Search-contained actions skip this hook;
the host plans their boundary from policy instead (see
[authority variants](#authority-variants)).

### Provider state and body admission

A provider can carry what one hook learned to its later hooks in the same
prepared operation with `ScopeResolution::with_state(ProviderState::new(value))`.
`ProviderState` holds owned `'static` data behind an `Arc`, so clones share it
and its `Debug` output is redacted. The host carries it without inspecting,
serializing or merging it, and it never reaches another generation's provider.
Prefer immutable snapshots; any interior mutation, including under cancellation,
is the provider's responsibility.

Read state with `ProviderState::require::<T>` when the hook needs it, or
`ProviderState::optional::<T>` when it may be absent. Missing state, or state of
another type, is a `ProviderStateError`. Returned with `?`, it becomes the host's
`broker_provider_contract_failed` with a diagnostic code; the state's contents
are never logged.

```rust
use agent_access_provider::{
    ProviderError, ProviderInvocation, ProviderState, ResourceScopes, ScopeResolution,
};

/// What scope resolution learned upstream, reused when the action runs.
struct ResolvedNote {
    notebook: String,
    revision: u64,
}

fn resolved(notebook: String, revision: u64) -> ScopeResolution {
    let scopes = ResourceScopes::from([("notebook".to_owned(), vec![notebook.clone()])]);
    ScopeResolution::resources(scopes)
        .with_state(ProviderState::new(ResolvedNote { notebook, revision }))
}

fn resolved_note(request: &ProviderInvocation) -> Result<(&str, u64), ProviderError> {
    let note = ProviderState::require::<ResolvedNote>(request.state())?;
    Ok((note.notebook.as_str(), note.revision))
}
```

Multipart actions admit their file metadata before the host reads the body.
`authorize_body_parts(&AdmittedRequest, Option<&ProviderState>)` returns
`BodyAdmission::new(part_specs, disposition)`, where the disposition states what
happens to the state:

- `StateDisposition::Keep` keeps the state the hook received;
- `StateDisposition::Replace(state)` replaces the whole state; to keep scope
  and admission data, compose them into one value;
- `StateDisposition::Clear` drops it.

There is no default disposition, and missing state never means Keep. The
admission view has neither body data nor decrypted private attributes, and it
cannot change the service, identity, authority, credential selection or policy.
After admission the host consumes the body and checks each part's declared size
and SHA-256. At invocation the provider still checks that each part matches the
metadata it admitted. The default `authorize_body_parts` denies every multipart
request with `body_malformed`.

## Authority and credentials

### The admitted request

After policy admits an operation, the host builds a read-only admitted context
and hands the provider a `ProviderInvocation`. Its accessors are the provider's
only view of the operation:

| Accessor | Value |
| --- | --- |
| `service()`, `action()` | The admitted service and action. |
| `execution_context()` | The context the host authorized. It never comes from a tool input. |
| `identity()` | The principal and whether it authenticated, nothing more. |
| `correlation()` | Request identifiers for upstream correlation headers. |
| `credential_mode()` | `CredentialMode::Service` or `CredentialMode::PerUser`. |
| `authority()`, `resource_scopes()`, `search_authorization()` | The exact admitted authority. |
| `inputs()` | Inputs validated against the action's schema. |
| `execution()`, `lookup_credential()` | The selected execution material and any static lookup credential. |
| `body_parts()`, `resource_attributes()`, `state()` | Staged body parts, the admitted resource's private attributes and provider state. |

`context()` returns the shared `AdmittedContext`, which continuation bindings
use. Live invocation, credential, stream and state values implement neither
`Serialize` nor `Deserialize`, and credential `Debug` output is redacted. Keep
credential material out of results, audit data, error messages and logs.

The host owns ordering. It admits identity, context, action, schema and grant
paths; the provider resolves scopes; the host authorizes and selects
credentials; the provider admits multipart metadata; and the host stages the
body. Immediately before dispatch the host revalidates private resource
bindings, decrypts only the admitted resource's attributes and revalidates
delegated leases. The provider then performs its own execution-side checks with
the execution credential. Lookup authority never substitutes for execution
authority.

### Authority variants

`InvocationAuthority` is chosen from the action's validated contract:

- `ActionOnly`: an action without a resource scope. It never inherits resources.
- `Resources(ResourceScopes)`: the canonical resources one admitted grant
  covers. An ordinary scoped action never receives empty authority.
- `Search(SearchAuthorization)`: the complete search boundary of a
  search-contained action, a scope type with a `SearchAuthorizationScope` of
  `Finite { values }` or `AllExcept { excluded_values }`.

`resource_scopes()` and `search_authorization()` return the expected variant,
or an `AuthorityMismatch` that `?` turns into `broker_provider_contract_failed`.
A search provider rewrites its upstream query within the boundary and checks
every returned item with `SearchAuthorizationScope::matches`. It never receives a
lossy `*` in place of an all-except boundary.

Act on the admitted resources, not on raw inputs. When an input names the
resource, check that it equals the admitted value before you use it.

### Static credentials

`execution()` returns `ExecutionAccess`:

- `ExecutionAccess::None`: the action needs no broker-selected credential, as
  for a Teams Workflow whose authority is a private resource attribute.
- `ExecutionAccess::Static(ExecutionCredential)`: one of the two static kinds.
- `ExecutionAccess::Delegated(DelegatedCredential)`: a person's delegated
  connection, described below.

Static and delegated material never coexist. The static kinds are exactly
`basic_api_token` and `bearer_token`. `ExecutionCredential::kind()` names the
kind, and `view()` returns `CredentialView::Basic { username, token }` or
`CredentialView::Bearer { token }`. `CredentialView` is non-exhaustive, so a
match on it ends with an arm that rejects any other view. Only the host
constructs credentials, so the
material a kind requires is always present. Provider-defined kinds, credential
JSON and delegated lookup credentials are not supported. A lookup credential is
static, is used only for lookup, and never stands in for execution material.

When the selected kind is not one the provider can use, deny with
`credential_not_provisioned`. Declare the accepted service kinds and managed
profiles in the descriptor so administrators see the right forms.

### Delegated access

A service that accepts per-user OAuth connections declares
`CredentialDescriptor::delegated(description)`. Its invocations receive a
`DelegatedCredential` that wraps the host's lease. Binding a connection to an
OAuth registration does not prove which upstream resource or API audience the
token serves, so the provider must check that on every use:

1. Before each upstream request, including each page or detail call of one
   invocation, call `revalidate().await?`. It confirms the connection is still
   current and renews stale access.
2. Read `access()` and check its `target()` and `audience()` against the values
   the provider requires. Deny with `credential_invalid` when they differ.
3. Attach its `token()` only to requests for the provider's own origin, after
   the origin check in [credentials and origins](#credentials-and-origins).

```rust
use agent_access_provider::{DelegatedCredential, ProviderError, ReasonCode};

const NOTES_TARGET: &str = "https://notes.example.com/";
const NOTES_AUDIENCE: &str = "https://notes.example.com/api";

/// The token to present for the next upstream request.
async fn delegated_token(credential: &DelegatedCredential) -> Result<String, ProviderError> {
    credential.revalidate().await?;
    let access = credential.access();
    if access.target() != NOTES_TARGET || access.audience() != NOTES_AUDIENCE {
        return Err(ProviderError::deny(
            ReasonCode::CredentialInvalid,
            "the connected account does not grant access to the notes service",
        ));
    }
    Ok(access.token().to_owned())
}
```

Return lease failures unchanged with `?`. They are host-origin failures; a
refresh already in progress, for example, reports `concurrency_limited` (HTTP
429), which a provider cannot report itself.

An upstream 401 does not license a retry. `mark_rejected(version)` invalidates
only the rejected access version for later calls, without refreshing or
replaying. `recover_after_unauthorized()` obtains replacement access once per
invocation and its clones; a second call fails. Repeating a request after that
recovery is a deliberate, documented provider decision. Gmail repeats a
subrequest once after a received HTTP 401, never after a transport error, 403,
429, 5xx or malformed response. Imported MCP never repeats.

`binding_identity()` returns an opaque `DelegatedBindingId` for the lease. Routine
refresh keeps it; new consent, replacement and reconnection change it. Bind
continuation tokens to it (see [binding](#binding)).

### Credential verification

`verify_execution_credential(&ExecutionCredential, &CorrelationContext)` checks
selected static material upstream for administrators. Return
`Ok(Some(ProviderCredentialVerification { .. }))` with the upstream status,
duration and safe audit data. The default `Ok(None)` means verification is
unsupported, never that it succeeded.

## Network

### Upstream clients and profiles

Build every upstream client in `BackendConfig::build` through the host's factory:

```text
UpstreamClient::build(
    UpstreamClientSpec::new(label, provider, base, egress, allowed_upstream_hosts, profile),
    host.clients(),
)?
```

- `label` names the client in diagnostics, such as `providers.notes`. It
  decides nothing.
- `provider` is the name traces record.
- `base` is the service's base URL. `request()` adds the invocation's
  correlation headers only on this origin. The client does not decide where
  credentials go; see [credentials and origins](#credentials-and-origins).
- `egress` declares the route the client needs; see below.
- `allowed_upstream_hosts` are URL patterns. The client's send methods and its
  redirect helper refuse every request and redirect hop outside them.
- `profile` bounds time and retries; see below.
- `.with_status_reasons(..)` optionally declares default trace classifications
  for statuses the provider leaves unclassified, such as 409 for a version
  conflict.

The host captures the generation's limits, outbound TLS trust and proxy
environment, applies the profile, disables automatic redirects and returns the
client with a sanitized route. The SDK never hands a provider proxy credentials
or TLS files; `egress_route()` reports only the mode and proxy origin for audit. Build
several clients when the protocol needs them: one per profile, per destination
or per credential route.

`ClientProfile` bounds time and retries:

| Profile | Use |
| --- | --- |
| `Request` | Ordinary requests, each within `request_timeout_ms`. |
| `SingleAttempt` | The same deadline with every automatic HTTP retry disabled, for requests that must not repeat, such as non-idempotent mutations. |
| `Stream` | No whole-request deadline, for streamed downloads. Bound each chunk with the streaming idle timeout. |
| `Upload` | Only connecting is bounded; `send_upload` fails when upload progress stalls. |
| `Bounded { total, connect }` | Explicit shorter bounds with retries disabled. |

Keep a provider's established profile choice when you change unrelated code.
`Request` is not a no-retry promise.

### Routes, proxies and the loopback rule

`EgressDeclaration::Ordinary(proxy)` takes the host's ordinary selection: a
`NO_PROXY` match connects directly; otherwise the environment proxy for the
scheme, then the client's configured service proxy, then the global
`network.egress_proxy`, and otherwise a direct connection. Loopback URLs are no
exception for production providers.

`EgressDeclaration::LiteralLoopback` asks for a direct connection to a literal
IPv4 or IPv6 loopback base URL, bypassing every proxy. The host grants it only
to its own OAuth clients and to enabled development-only registrations, and only
for a literal loopback IP address such as `http://127.0.0.1:8099` or
`http://[::1]:8099`. `localhost` and every other host name never qualify; the
host resolves no name to grant it. Any other caller or URL fails client
construction instead of routing elsewhere. Development fixtures use it for
local test servers; it is not a general proxy bypass.

### Requests, redirects and traces

- `client.request(method, url)` starts a request. It carries the invocation's
  correlation headers only on the service's own origin.
- `client.send(builder, UpstreamCall::new("note.view"))` sends it within the
  profile. `send_with_deadline` adds a header deadline for streaming clients,
  and `send_upload` sends a streamed body with progress tracking. Always send
  through these methods: the builder's own `send` would bypass the allowlist
  and the trace.
- An `UpstreamError` means no usable response. `NotSent` proves the request
  never reached the upstream; `Timeout` and `Transport` may have been received
  and acted on. `reason_code()` gives the standard reason to report. Keep a
  possibly sent mutation's uncertainty in its outcome.
- Clients never follow redirects. `get_following_redirects(url, rules,
  operation)` follows a GET chain by hand under
  `RedirectRules::new(max_redirects, deadline, authorize)`. Every hop must be
  allowlisted, carry no embedded credentials and pass any `with_vet` check.
  The helper calls `authorize` only for hops on the service's own origin.
  Other origins receive correlation headers only with
  `correlating_other_origins()`. Atlassian attachment downloads opt in for
  media hosts; CloudBees CI artifact downloads do not.

Each request records one `upstream_request_completed` trace. Classify the
response with `complete_upstream_trace(&mut response, reason)`, or detach the
pending trace with `take_upstream_trace` while you read the body and call
`complete` with the outcome. A dropped response records its status alone. The
host checks each classification against the hook that sent the request (see
[upstream traces](#upstream-traces)).

Task-local invocation context does not follow `tokio::spawn`. Run work you move
to another task with `InvocationScope::current().run(future)`. That keeps its
correlation, hook, deadline and tracing span, so its traces stay attributed.

### Credentials and origins

`UpstreamClient` enforces the allowlist and places correlation headers by
origin, but credential placement is the provider's obligation. `send` delivers
every header the provider added to the builder to any allowlisted URL,
including a secondary origin such as a media or artifact host. A token attached
with `bearer_auth` to a request for such a URL reaches that host.

- Build request URLs from `client.base()`. Treat a URL from an upstream response
  or a caller input, such as a pagination link or a download location, as
  untrusted.
- Attach credentials to an ordinary request only when the URL's origin equals
  the client's base origin, as `same_origin(&url, client.base())` checks.
- For a redirect chain, pass credentials in the `authorize` callback of
  `get_following_redirects` rather than on the first request. The helper
  applies it only to hops on the base origin.

```rust
use agent_access_provider::deps::http::Method;
use agent_access_provider::deps::reqwest::RequestBuilder;
use agent_access_provider::deps::url::Url;
use agent_access_provider::{ProviderError, ReasonCode, UpstreamClient, same_origin};

/// A GET for an upstream-supplied link that carries the token only on the
/// client's own origin.
fn authorized_get(
    client: &UpstreamClient,
    link: Url,
    token: &str,
) -> Result<RequestBuilder, ProviderError> {
    if !same_origin(&link, client.base()) {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "the upstream returned a link on another origin",
        ));
    }
    Ok(client.request(Method::GET, link).bearer_auth(token))
}
```

The shipped providers follow this split. Confluence rejects an upstream
pagination link on another origin before it sends the link with credentials.
Jira and Confluence attachment downloads follow redirects to Atlassian media
origins with correlation headers but without credentials, and CloudBees CI
artifact downloads send neither to artifact storage.

### Limits and throttling

Respect the `ProviderLimits` the build context lends: `max_upstream_response_bytes`
for JSON bodies read into memory, `max_download_bytes` and
`streaming_idle_timeout_ms` for streams, `request_timeout_ms` and
`max_http_body_bytes`. Read bodies chunk by chunk against the cap; never trust
a `Content-Length` alone.

Report upstream throttling with `upstream_rate_limited(service, retry_after)`,
where `UpstreamRetryAfter::from_headers` reads a bounded `Retry-After`. Its
result names the service and the wait. Throttling after a mutation was applied
is never `upstream_rate_limited`, because a retry would repeat the write. Use
`mutation_unverified_after_throttling` or
`ProviderError::unverified_if_throttled` (see
[outcomes and receipts](#outcomes-and-receipts)).

## Signing and continuations

Seal every resumable cursor, page token or handle that a native action returns
or relays in a signed continuation envelope. Never pass an upstream pagination
token through unwrapped.

### Token families

Declare each token family once as a `ContinuationFamily` constant:

```text
ContinuationFamily::new(service, purpose, version, lifetime, max_payload_bytes)
```

- Each service, purpose and version is a separate family. Tokens of one family
  never open as another's, even under the same key.
- `ContinuationLifetime` chooses the signing key and therefore how long tokens
  stay valid:
  - `Generation`: a key generated with the provider instance. A reload or
    restart invalidates the tokens, even when a stable key is configured.
  - `StableWhenConfigured`: the service-scoped stable key when one is
    configured, otherwise the generation key.
  - `Durable`: only the stable key. Without one, sealing and opening fail; an
    action issuing such handles declares `.requires_stable_signing_key()` so the
    host requires the key.
- `.expires_after(duration)` gives tokens a lifetime; `.clock_skew(duration)`
  tolerates instances with differing clocks sharing a stable key.
- `.owner(ContinuationOwner::PerUserCaller)` binds the principal only in
  per-user mode. A service-mode token is then deliberately shared by every
  principal admitted in service mode under an otherwise identical binding. The
  default `ContinuationOwner::Caller` always binds the principal.
- `.shared_across_actions()` lets several actions of the service accept a token,
  such as a handle; `.token_prefix(prefix)` adds a visible family prefix.

Build one `ContinuationSigner` per provider instance from
`ContinuationSigner::new(host.stable_signing_key().cloned())`; clones share its
keys. Changing a token's format means a new version. Obsolete versions are
rejected, never decoded alongside the new one.

### Binding

`family.bind(request.context(), configuration)` binds a token to the admitted
service, the action (unless shared), the execution context, the credential
mode, the principal as the owner policy declares, and `configuration`, the
provider's fingerprint of the configuration the token depends on (never
credentials). Add the resource identifiers and the normalized query, filter and
output settings with `.text`, `.number`, `.flag`, `.optional_text`,
`.optional_number`, `.texts` and `.bytes`, including defaulted values. For
delegated access, `.delegated(&credential)` binds the lease's
`DelegatedBindingId`, target and audience; routine refresh keeps all three.

The binding is a canonical, length-delimited encoding whose digest enters the
MAC context. The token carries only its version, expiry, payload and MAC, so a
changed context, principal, mode, configuration, resource or setting is
indistinguishable from forgery. A token never carries authority. Do not bind the
effective grant boundary: the host authorizes every continuation under current
policy, and the provider applies its containment and result checks again on
every page. When a newly rewritten query is incompatible with an upstream
cursor, reject the token or restart rather than weakening a restriction.

```rust
use agent_access_provider::{
    ContinuationError, ContinuationFamily, ContinuationLifetime, ContinuationSigner, ProviderError,
    ProviderInvocation, ReasonCode,
};
use std::time::Duration;

/// Note-list page tokens carry the next upstream offset.
const NOTE_PAGES: ContinuationFamily = ContinuationFamily::new(
    "notes",
    "note-list-page",
    1,
    ContinuationLifetime::Generation,
    8,
)
.expires_after(Duration::from_secs(15 * 60));

/// Bounds the `pageToken` input in the action schema.
const PAGE_TOKEN_MAX_LENGTH: usize = NOTE_PAGES.max_token_bytes();

fn next_page_token(
    signer: &ContinuationSigner,
    request: &ProviderInvocation,
    configuration: &str,
    notebook: &str,
    page_size: u64,
    offset: u64,
) -> Result<String, ProviderError> {
    let binding = NOTE_PAGES
        .bind(request.context(), configuration)
        .text("notebook", notebook)
        .number("pageSize", page_size);
    signer
        .seal(&binding, &offset.to_be_bytes())
        .map_err(page_token_failure)
}

fn page_token_offset(
    signer: &ContinuationSigner,
    request: &ProviderInvocation,
    configuration: &str,
    notebook: &str,
    page_size: u64,
    token: &str,
) -> Result<u64, ProviderError> {
    let binding = NOTE_PAGES
        .bind(request.context(), configuration)
        .text("notebook", notebook)
        .number("pageSize", page_size);
    let payload = signer.open(&binding, token).map_err(page_token_failure)?;
    let offset = <[u8; 8]>::try_from(payload.as_slice()).map_err(|_| invalid_page_token())?;
    Ok(u64::from_be_bytes(offset))
}

fn invalid_page_token() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "invalid or expired page token, or a changed request; list again without it",
    )
}

fn page_token_failure(error: ContinuationError) -> ProviderError {
    match error {
        _ if error.is_token_rejection() => invalid_page_token(),
        ContinuationError::SigningUnavailable | ContinuationError::DurableKeyUnavailable => {
            ProviderError::error(
                ReasonCode::CursorSigningUnavailable,
                "page token signing is unavailable",
            )
        }
        _ => ProviderError::error(
            ReasonCode::OperationFailed,
            "page token could not be sealed",
        ),
    }
}
```

### Caps

Each family declares an explicit payload cap of at most 64 KiB.
`max_token_bytes()` is the exact encoded size of a token carrying the largest
payload, so the action schema can bound the token input by it. An oversized
payload or token is an error; nothing is ever truncated. A family that relays
an upstream token of undocumented size derives its cap from the response limit
instead; see [relayed upstream cursors](#relayed-upstream-cursors).

### Errors

`ContinuationError::is_token_rejection()` separates a token the caller must not
reuse (invalid, tampered, rebound, obsolete version, expired or too large) from a
Broker-side failure. Report rejections as a caller error such as `input_invalid`
with `decision = deny`, and a missing signing key as `cursor_signing_unavailable`.

### Relayed upstream cursors

When an upstream service issues its own page token, the provider seals that
token instead of passing it through. `ContinuationSigner::seal_relayed(&binding,
upstream_query, upstream_token)` seals the token as text, and `open_relayed`
returns it. With `Some(upstream_query)`, the token also carries a keyed
commitment to the upstream query that the provider composed for the page under
the current authorization. When a later grant change recomposes that query,
opening fails with `ContinuationError::UpstreamQueryChanged`, and the upstream
token is never sent with a different query. Relayed tokens open only as relayed
tokens with the same commitment choice. The commitment
(`UPSTREAM_QUERY_COMMITMENT_BYTES`) counts toward the payload cap.

An upstream that documents no maximum token size gets no invented cap. The
response limit already bounds the response the upstream token arrives in and the
result the continuation leaves in. Declare the family's expiry and prefix, then
size it with
`family.with_max_payload_bytes(family.max_payload_bytes_within(response_limit))`.
The continuation then always fits the result it is returned in.

A family whose tokens must be read during scope resolution, before the host
admits a credential mode, declares `.opened_during_scope_resolution()`.
Confluence draft handles name the space to authorize this way. Scope resolution
binds the token with `family.bind_scope(&request, configuration)` and opens it
with `ContinuationSigner::open_during_scope_resolution`. That binding covers
only what scope resolution knows: the service, the action (unless shared), the
execution context, the configuration and the provider's fields. The token's owner
travels inside it as a keyed ownership commitment. Scope resolution accepts the
token only when the current principal could own it, and after admission the
provider opens it again with `open`, which checks the admitted credential mode
and principal.

## Reasons and outcomes

Every response and audit record carries one `reasonCode` string. A provider
reports a standard reason from the provider-emittable subset or one of its own
domain reasons. The host checks every reported outcome at the hook that
produced it.

### Standard reasons a provider may report

The host runs four hooks and supplies the phase: scope resolution (S), body
admission (A), the invocation result (I) and credential verification (V). Each
provider-emittable standard reason fixes its HTTP status, the decisions it
allows and the hooks it may come from:

| Hooks | Reasons |
| --- | --- |
| S, A, I, V | `input_invalid`, `body_malformed`, `service_action_denied`, `scope_unresolved`, `locator_invalid`, `credential_not_provisioned`, `credential_invalid`, `git_ref_denied`, `webhook_destination_denied`, `resource_not_found`, `verification_mismatch` (deny), `version_conflict`, `body_size_denied`, `attachment_size_denied`, `attachment_integrity_mismatch`, `body_format_unsupported`, `response_format_unsupported`, `attachment_media_type_denied`, `upstream_unauthorized`, `upstream_forbidden`, `upstream_failed`, `upstream_rate_limited`, `upstream_connection_failed`, `upstream_protocol_failed`, `upstream_timeout`, `operation_failed`, `operation_cancelled` |
| S, A, I | `invalid_draft_handle`, `cursor_signing_unavailable` |
| I only | `mutation_verification_failed`, and `verification_mismatch` with `decision = allow` and its verification result |

The decisions each reason allows are in the
[provider-reported reason table](http-api.md#provider-reported-standard-reasons).
`ProviderError::deny` and `ProviderError::error` construct standard failures, and
the decision is fixed at construction. `ReasonCode::permits_provider_failure`,
`permits_provider_allow` and `permits_late_stream` answer the same questions in
tests. Every other standard reason, such as caller authentication, Broker rate
limits or management failures, is reported only by the host. A listed hook does
not authorize upstream work in that hook, and lookup failures keep their
concealment.

`upstream_rate_limited` must carry the upstream rate-limit result that
`upstream_rate_limited(service, retry_after)` builds, naming the invoked service.

### Domain reasons

A provider may define failure reasons for its own domain as static
`ProviderReasonDefinition`s, listed on its registration with
`with_domain_reasons` and reported with `ProviderError::domain(&DEFINITION,
message)`:

```text
pub static NOTE_ARCHIVED: ProviderReasonDefinition =
    ProviderReasonDefinition::deny("notes_note_archived", ProviderFailureStatus::Conflict);
```

- The code matches `^[a-z][a-z0-9_]{0,63}$` and starts with the provider's
  kind (hyphens written as underscores) followed by `_` and a nonempty name.
- Each definition fixes one decision, `deny` or `error`, and one status from
  `ProviderFailureStatus`: 400 or 404 (CLI exit 3), 403, 409, 413 or 415 (exit
  2), 424, 502 or 504 (exit 4), and 500 or 503 (exit 5). There is no allow,
  success, redirect, authentication challenge, rate-limit or cancellation
  outcome, and a domain status never adds a `Retry-After` header.
- Before serving, the host rejects a code without the kind's prefix, a code
  that another selected provider or a standard reason already uses, and domain
  reasons on a kind whose prefix starts `broker_` or leaves no room for a name
  within 64 bytes. Such kinds may still register without domain reasons.
  Overlapping prefixes such as `gitlab` and `gitlab_dedicated` coexist while
  their full codes differ.
- The host compares a reported definition by value with the registration's own.
  A same-spelled definition that the provider did not register, or one with a
  different outcome, is a contract failure.

Responses, audit records and audit filters carry the code as a plain string,
which stays readable after the provider is no longer linked. A provider's domain
reason inventory and each fixed outcome are part of its compatibility contract
(see [compatibility](#compatibility-policy)).

### Late stream failures

A raw download that fails after its response started reports a
`ProviderStreamError` with a reason code only; the host keeps its committed
response and its own late-failure decision and records the code in the terminal
audit record. Standard codes are limited to `attachment_size_denied`,
`upstream_connection_failed`, `upstream_protocol_failed` and `upstream_timeout`;
the provider's domain reasons are also accepted.

### Upstream traces

A trace classification uses a reason the enclosing hook may report, a registered
domain reason, or the client's declared status reason; it confers no decision.
The host captures the hook when the request is sent, including from work carried
with `InvocationScope`, and never infers the phase from the reason. A transport
failure's classification is the client's own.

### Contract failures

Any other outcome becomes the host's `broker_provider_contract_failed` (HTTP
500, `decision = error`) with a fixed message and an internal diagnostic code.
The provider's own code, message and result are discarded. An invocation's
contract failure also reports `executionState = "unknown"` and
`retrySafe = false`, because the provider may already have acted upstream.

Host cooperation ports mark their failures with `host::port_failure`, so a
provider passes them on unchanged within that port's allowlist: a delegated
lease's failures, and the SDK's own `ProviderStateError` and
`AuthorityMismatch`. Ordinary provider code never calls `port_failure`.

### Outcomes and receipts

A successful invocation returns `ProviderResult::new(result)`, with optional
`with_stream` for a single-consumption raw download body, `with_audit` for safe
provider audit data, `with_upstream` for the upstream status and duration, and
`with_object_ids`. Build streams with
`ProviderResultStream::from_stream`, bound each chunk, and add
`with_expected_size` when the upstream declared a length. A stream is handed to
the host once; it is never buffered into base64 JSON or replayed. Provider audit
data cannot replace host-owned identity, admission, decision or provenance
fields.

Errors can carry a bounded `result` with `with_result`, and upstream facts with
`with_upstream`. Report each outcome as what it is:

- **Confirmed rejection**: the upstream refused and nothing changed. Report the
  matching deny or error reason.
- **Proven unsent**: `UpstreamError::NotSent`, so nothing reached the upstream.
- **Applied**: success, with safe locators of what changed.
- **Partial**: a batch in which some writes applied. Keep the batch's `status`,
  per-item results and failures in the error result.
- **Unverified**: the write applied but its read-back failed. Report
  `mutation_verification_failed` with `mutationStatus: "applied_unverified"`,
  `retrySafe: false`, the `verificationStage` and `safeLocators`.

Neither the host nor the CLI replays an operation: not after a failed
read-back, a timeout, cancellation, forced shutdown or a local output failure.
A provider must not repeat a mutation itself either, except through a
documented explicit recovery such as Gmail's single 401 recovery. Use `SingleAttempt`
clients for requests that must not repeat.

## Testing

### SDK test support

Enable the SDK's `test-support` feature in a provider's development
dependencies. It adds construction helpers only and never changes runtime
behavior:

- `TestHost` lends a `BuildContext` with configurable limits, attribution and
  stable signing key, and a deterministic, offline client factory. Its clients
  trust only an embedded test CA, ignore proxy environment variables, use a
  configured service proxy only when it has no credential references, grant the
  literal loopback route only for a literal loopback base URL, and never follow
  redirects. `built_clients()` records each requested label, base URL, profile
  and route.
- `ScopeRequestFixture` builds a `ScopeRequest` for an anonymous caller in the
  `internal` context, with an optional lookup credential.
- `InvocationBuilder` builds an `AdmittedRequest` (`admitted()`) or a
  `ProviderInvocation` (`build()`) the way the host admits them: authority,
  credential mode, static or delegated credentials, body parts, private
  attributes and state.
- `basic_credential`, `bearer_credential`, `delegated_binding_id`,
  `test_signing_key` and `credential_token` construct and inspect host values.
- `in_invocation_hook(service, action, future)` runs a future as the host runs
  an invocation hook, so upstream traces are checked as they would be in the
  Broker. It does not include the provider's domain reasons.
- `install_trace_capture()` installs one capturing dispatcher for the test
  binary. `TraceCaptureDispatcher::start()` then records only the events inside
  its span, including work carried by `InvocationScope`.
  `take_upstream_requests()` returns the upstream trace events.
- `DescribedProvider` lets a test provider state its own descriptor so it can
  be injected without a configuration.

### Conformance reference

`agent-access-conformance` is a test-only provider that uses every extension
point: a namespace-capable resource type with an action-input projection and
configured roots, typed configuration, a managed credential profile, JSON,
raw-download and multipart-upload actions, embedded and whole-result
presentation, and an endpoint type whose private key a single-attempt action
consumes. It depends only on the SDK. Its unit tests show how to drive each
shape with `TestHost`, `InvocationBuilder` and a mock upstream, and the host's
`tests::conformance` suite registers it beside the shipped providers to prove
that a provider needs no host changes. Use it as the reference for an
independent provider build; it is never linked into a release.

### Host acceptance tests

The host's `test-support` feature provides isolated Broker applications for
acceptance tests. `test_support::IsolatedBroker::new(composition, identity)`
starts an assembly's composition on a real configuration file through the same
startup as `serve`: validation, state locks, readiness, reload publication and
operation drain, on loopback listeners with ephemeral ports. It installs no
signal handler or global log subscriber; `RunningBroker::reload`, `shutdown` and
`join` stand in for the process signals, and `audit()` and `managed_store()`
give read-only store views. `ProviderFixture` serves a test provider for a
selected and configured kind in place of the one its registration would build;
configuration validation, admission and generation ownership still apply. It is
a fixture control, not an embedding API. Release builds never enable either
test-support feature. See [testing](testing.md) for the commands.

## Compatibility policy

The SDK, host composition interface, test-support interfaces and shipped
workspace packages share one release train and the workspace version. A
downstream provider crate keeps its own version and release ownership.

- Within a compatible line, a patch release preserves the supported source
  contracts and module-acceptance behavior: composition, shipped module
  selection, test support, descriptor validation, public dependency types and
  documented lifecycle semantics.
- An incompatible change advances the minor version on the 0.x line, and the
  changelog documents the required source and behavior changes. Old interfaces
  are removed rather than kept behind wrappers or parallel parsers.
- Adding a required method to an implementable trait is breaking. A default
  method is compatible only if it preserves the documented semantics.
- Supported types are built through constructors and builders, so a new field
  is compatible. Extendable enums, such as `CredentialView`,
  `InvocationAuthority`, `ExecutionAccess` and `ContinuationLifetime`, are
  non-exhaustive; end every match on one with an arm that rejects what the
  provider does not support, never one that treats it as success or as another
  variant. Making an item exhaustive, or changing an intentionally exhaustive
  one such as `Decision`, `CredentialMode` or `ProviderFailureStatus`, is
  incompatible.
- Third-party types in SDK signatures tie the SDK to those packages' versions.
  `agent_access_provider::deps` re-exports every third-party type and macro a
  provider must name to implement the SDK traits, such as the `async_trait`
  attribute, `deps::reqwest::Response`, `deps::http::Method` and
  `deps::url::Url`, so a provider builds against the SDK's versions without
  naming those packages. A provider that needs more of a package, such as the
  `serde_json::json!` macro, or that derives `serde` traits, depends on the same
  semver line directly, and Cargo resolves one copy. An incompatible release of
  one of these packages is an SDK compatibility event; the crate documentation
  lists the packages and their lines.
- A provider's domain reason inventory and each definition's outcome are part
  of the provider's own contract. Adding, removing or renaming a domain reason,
  including the first one, is an incompatible provider release, so that a
  supposedly compatible upgrade cannot newly claim a code another module uses.
- Security fixes that must reject previously accepted behavior say so
  explicitly.

`0.2.0` is the first released baseline of the
[public API inventory](../api/README.md). Release review compares the
inventory with the previous release on the same line; a compile-surface diff
does not replace descriptor, lifecycle and feature behavior checks. The tested toolchain is the repository's pinned Rust toolchain;
no wider minimum supported Rust version is implied.

## Worked example

This provider serves a synthetic notes service at `https://notes.example.com`.
It has one read action, `note.view`, scoped to a notebook resource. It uses a
static bearer token, reads a bounded JSON response and declares one domain
reason. It is derived from the development `fake` and conformance providers.
Every Rust block on this page compiles against the current SDK; the blocks in
this section form one crate's `src/lib.rs`.

### Manifest

A provider in its own repository pins the SDK by the canonical Git URL and a
full 40-character revision; see
[canonical pins](downstream-assembly.md#canonical-pins). The `async_trait`
attribute and the `reqwest` and `url` types come from the SDK's `deps` module;
the crate depends directly only on `serde` for its derives and on `serde_json`
for the `json!` macro, on the SDK's semver lines.

```toml
[package]
name = "example-notes"
version = "0.1.0"
edition = "2024"

[dependencies]
agent-access-provider = { git = "https://github.com/kcosr/agent-access-broker.git", rev = "<full 40-character commit>" }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[dev-dependencies]
agent-access-provider = { git = "https://github.com/kcosr/agent-access-broker.git", rev = "<full 40-character commit>", features = ["test-support"] }
tokio = { version = "1", features = ["macros", "rt"] }
wiremock = "0.6"
```

### Registration, resource type and configuration

```rust
use agent_access_provider::deps::async_trait;
use agent_access_provider::deps::http::Method;
use agent_access_provider::deps::reqwest::Response;
use agent_access_provider::deps::url::Url;
use agent_access_provider::{
    ActionDescriptor, BackendConfig, BackendRegistration, BuildContext, ClientProfile,
    CredentialDescriptor, CredentialView, EgressDeclaration, EgressProxyConfig, Provider,
    ProviderBuildError, ProviderError, ProviderFailureStatus, ProviderInvocation,
    ProviderReasonDefinition, ProviderResult, ReasonCode, ResourceScopeCapabilities,
    ResourceScopes, ResourceType, ResourceTypeDescriptor, ScopeRequest, ScopeResolution,
    ServiceDescriptor, UpstreamCall, UpstreamClient, UpstreamClientSpec, ValidationContext,
    complete_upstream_trace, module_metadata, parse_backend_config, take_upstream_trace,
    validate_egress_proxy_config, validate_upstream_allowlist, validate_upstream_base_url,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

const KIND: &str = "notes";
const LABEL: &str = "providers.notes";

/// The registration an assembly selects.
pub static NOTES_BACKEND: BackendRegistration = BackendRegistration::new(
    module_metadata!(),
    KIND,
    parse_backend_config::<NotesConfig>,
)
.with_resource_types(&[&NOTEBOOK_RESOURCE])
.with_domain_reasons(&[&NOTE_ARCHIVED]);

/// The upstream keeps archived notes but no longer serves them.
pub static NOTE_ARCHIVED: ProviderReasonDefinition =
    ProviderReasonDefinition::deny("notes_note_archived", ProviderFailureStatus::Conflict);

/// Notebooks, named like `team-handbook`.
pub static NOTEBOOK_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("notes_notebook"),
    "Notebook",
    "Notebooks",
    "team-handbook",
    is_notebook_name,
);

fn is_notebook_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `[providers.notes]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotesConfig {
    pub base_url: String,
    pub allowed_upstream_hosts: Vec<String>,
    #[serde(default)]
    pub egress_proxy: Option<EgressProxyConfig>,
}

impl BackendConfig for NotesConfig {
    fn kind(&self) -> &'static str {
        KIND
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
    }

    fn descriptor(&self) -> ServiceDescriptor {
        notes_descriptor()
    }

    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        self.egress_proxy
            .iter()
            .map(|proxy| (format!("{LABEL}.egress_proxy"), proxy))
            .collect()
    }

    fn build(&self, host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        let base = Url::parse(&format!("{}/", self.base_url.trim_end_matches('/')))
            .map_err(|_| ProviderBuildError::invalid(format!("{LABEL}.base_url is invalid")))?;
        let client = UpstreamClient::build(
            UpstreamClientSpec::new(
                LABEL,
                KIND,
                &base,
                EgressDeclaration::Ordinary(self.egress_proxy.as_ref()),
                &self.allowed_upstream_hosts,
                ClientProfile::Request,
            ),
            host.clients(),
        )?;
        Ok(Arc::new(NotesProvider {
            client,
            max_response_bytes: host.limits().max_upstream_response_bytes,
        }))
    }
}
```

### Descriptor

```rust
/// The notes service. It depends on nothing but constants, so offline
/// validation can call it before a provider exists.
pub fn notes_descriptor() -> ServiceDescriptor {
    ServiceDescriptor::new(KIND, "Notes")
        .with_resource_scopes(BTreeMap::from([(
            "notebook".to_owned(),
            ResourceScopeCapabilities::new(
                NOTEBOOK_RESOURCE.id().clone(),
                vec!["exact".to_owned(), "all".to_owned()],
            ),
        )]))
        .with_actions(vec![
            ActionDescriptor::new(
                "note.view",
                "View one note in a notebook",
                json!({
                    "type": "object",
                    "required": ["notebook", "note"],
                    "properties": {
                        "notebook": {"type": "string", "description": "Notebook name, such as team-handbook"},
                        "note": {"type": "string", "pattern": "^[0-9]{1,12}$"}
                    },
                    "additionalProperties": false
                }),
            )
            .read_only()
            .scope("notebook")
            .credential_modes(["service", "per_user"]),
        ])
        .with_credentials(
            CredentialDescriptor::default()
                .service_kinds(&["bearer_token"])
                .profile("api_token", "bearer_token"),
        )
}
```

### Provider

```rust
struct NotesProvider {
    client: UpstreamClient,
    max_response_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoteInputs {
    notebook: String,
    note: String,
}

fn invalid(message: &str) -> ProviderError {
    ProviderError::deny(ReasonCode::InputInvalid, message)
}

fn note_inputs(action: &str, inputs: &Value) -> Result<NoteInputs, ProviderError> {
    if action != "note.view" {
        return Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "notes action is not supported",
        ));
    }
    let inputs: NoteInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| invalid("notes inputs are invalid"))?;
    if !is_notebook_name(&inputs.notebook) {
        return Err(invalid("notebook name is invalid"));
    }
    if inputs.note.is_empty() || !inputs.note.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("note ID is invalid"));
    }
    Ok(inputs)
}

impl NotesProvider {
    /// Reads a JSON body within the response limit.
    async fn read_json(&self, mut response: Response) -> Result<Value, ProviderError> {
        let protocol = |message| ProviderError::error(ReasonCode::UpstreamProtocolFailed, message);
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| {
            ProviderError::error(
                ReasonCode::UpstreamConnectionFailed,
                "notes response failed",
            )
        })? {
            if (body.len() + chunk.len()) as u64 > self.max_response_bytes {
                return Err(protocol("notes response exceeds the response limit"));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| protocol("notes response is not JSON"))
    }
}

#[async_trait]
impl Provider for NotesProvider {
    /// The notebook comes from the inputs; no upstream lookup is needed.
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        let inputs = note_inputs(request.action(), request.inputs())?;
        Ok(ScopeResolution::resources(ResourceScopes::from([(
            "notebook".to_owned(),
            vec![inputs.notebook],
        )])))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        let inputs = note_inputs(request.action(), request.inputs())?;
        // Act on the admitted resource, and only when it is the one named.
        let admitted = request
            .resource_scopes()?
            .get("notebook")
            .map(Vec::as_slice);
        if admitted != Some(std::slice::from_ref(&inputs.notebook)) {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "the admitted notebook does not match the request",
            ));
        }
        // `CredentialView` is non-exhaustive: every other view is rejected.
        let Some(CredentialView::Bearer { token }) = request
            .execution()
            .static_credential()
            .map(|credential| credential.view())
        else {
            return Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "notes needs a bearer token",
            ));
        };

        // Built from the client base, so the token stays on its origin.
        let mut url = self.client.base().clone();
        url.path_segments_mut()
            .expect("base URLs have a path")
            .pop_if_empty()
            .extend([
                "notebooks",
                inputs.notebook.as_str(),
                "notes",
                inputs.note.as_str(),
            ]);
        let started = Instant::now();
        let mut response = self
            .client
            .send(
                self.client.request(Method::GET, url).bearer_auth(token),
                UpstreamCall::new("note.view"),
            )
            .await
            .map_err(|error| ProviderError::error(error.reason_code(), "notes request failed"))?;
        let status = response.status().as_u16();
        let failure = match status {
            200 => None,
            401 => Some(ProviderError::deny(
                ReasonCode::UpstreamUnauthorized,
                "notes rejected the credential",
            )),
            403 => Some(ProviderError::deny(
                ReasonCode::UpstreamForbidden,
                "notes denied the request",
            )),
            404 => Some(ProviderError::deny(
                ReasonCode::ResourceNotFound,
                "note not found",
            )),
            410 => Some(ProviderError::domain(
                &NOTE_ARCHIVED,
                "the note is archived",
            )),
            _ => Some(ProviderError::error(
                ReasonCode::UpstreamFailed,
                "notes request failed",
            )),
        };
        if let Some(error) = failure {
            complete_upstream_trace(&mut response, Some(error.reason_code()));
            return Err(error.with_upstream(Some(status), Some(elapsed_ms(started))));
        }

        // Classify the trace once the body has been read.
        let trace = take_upstream_trace(&mut response);
        let outcome = self.read_json(response).await;
        if let Some(trace) = trace {
            trace.complete(outcome.as_ref().err().map(ProviderError::reason_code));
        }
        let note = outcome?;
        Ok(
            ProviderResult::new(json!({"notebook": inputs.notebook, "note": note}))
                .with_audit(
                    json!({"provider": KIND, "operation": "note.view", "note": inputs.note}),
                )
                .with_upstream(Some(status), Some(elapsed_ms(started)))
                .with_object_ids(json!({"notebook": inputs.notebook, "note": inputs.note})),
        )
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
```

### Tests

The tests build the provider through `TestHost`, resolve scopes with
`ScopeRequestFixture` and invoke it against a local mock upstream with
`InvocationBuilder`, inside an invocation hook as the Broker runs it.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::test_support::{
        InvocationBuilder, ScopeRequestFixture, TestHost, bearer_credential, in_invocation_hook,
    };
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn provider(base_url: &str) -> Arc<dyn Provider> {
        let config = NotesConfig {
            base_url: base_url.to_owned(),
            allowed_upstream_hosts: vec![format!("{base_url}/**")],
            egress_proxy: None,
        };
        config.build(&TestHost::default().context()).unwrap()
    }

    fn invocation(note: &str) -> ProviderInvocation {
        InvocationBuilder::new("notes", "note.view")
            .inputs(json!({"notebook": "team-handbook", "note": note}))
            .resources(ResourceScopes::from([(
                "notebook".to_owned(),
                vec!["team-handbook".to_owned()],
            )]))
            .credential(bearer_credential("notes-token"))
            .build()
    }

    #[test]
    fn the_descriptor_is_valid() {
        notes_descriptor().validate().unwrap();
    }

    #[tokio::test]
    async fn scope_resolution_names_the_notebook_locally() {
        let provider = provider("https://notes.example.com");
        let fixture = ScopeRequestFixture::new(
            "notes",
            "note.view",
            json!({"notebook": "team-handbook", "note": "42"}),
        );
        let resolution = provider.resolve_scopes(fixture.request()).await.unwrap();
        assert_eq!(resolution.scopes()["notebook"], ["team-handbook"]);
        assert!(resolution.state().is_none());
    }

    #[tokio::test]
    async fn a_note_is_read_with_the_bearer_token() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/notebooks/team-handbook/notes/42"))
            .and(header("authorization", "Bearer notes-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"title": "Welcome"})))
            .expect(1)
            .mount(&upstream)
            .await;
        let provider = provider(&upstream.uri());
        let result = in_invocation_hook("notes", "note.view", provider.invoke(invocation("42")))
            .await
            .unwrap();
        assert_eq!(result.result["note"]["title"], "Welcome");
        assert_eq!(result.upstream_status, Some(200));
    }

    #[tokio::test]
    async fn an_archived_note_reports_the_domain_reason() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(410))
            .mount(&upstream)
            .await;
        let provider = provider(&upstream.uri());
        let error = provider.invoke(invocation("7")).await.unwrap_err();
        assert_eq!(error.reason_code().domain(), Some(&NOTE_ARCHIVED));
        assert_eq!(error.reason_code().http_status(), 409);
    }

    #[tokio::test]
    async fn a_missing_bearer_token_is_denied_before_any_request() {
        let provider = provider("https://notes.example.com");
        let request = InvocationBuilder::from(invocation("42"))
            .execution(agent_access_provider::ExecutionAccess::None)
            .build();
        let error = provider.invoke(request).await.unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::CredentialNotProvisioned);
    }
}
```

### Configuring it

Once an assembly selects `NOTES_BACKEND`, an operator configures the service and
its credential like any other provider; see
[the configuration reference](configuration.md#credentials) and
[resources](resources.md) for credentials, resources and grants.

```toml
[providers.notes]
base_url = "https://notes.example.com"
allowed_upstream_hosts = ["https://notes.example.com/**"]
```
