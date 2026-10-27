# Agent Access Broker — Architecture and runtime contract

For trusted username authentication on HTTP MCP, registered fingerprint identity
on existing invocation surfaces, explicit managed bindings, shared
identity-access pause and per-path Enabled and Read-only controls, see
[managed identity](managed-identity.md). Named callers
authenticate attesters; Broker resolves humans and applies current permissions.
Issued Broker tokens retain their independent authorization boundaries.

This document is the architecture and conceptual contract for the Agent Access
Broker. It describes the credential boundary, the request lifecycle, the split
between the core engine and the providers, the naming contracts, and the
identity, policy, credential, audit, limits, egress-proxy, gateway, and security
models.

HTTP routes and response envelopes are detailed in
[docs/http-api.md](http-api.md); the CLI is in [docs/cli.md](cli.md);
the local stdio MCP adapter is in [docs/mcp.md](mcp.md);
configuration keys are in [docs/configuration.md](configuration.md); per-provider
behavior is in [docs/providers.md](providers.md); the broader agent containment
and egress-boundary rationale is in [docs/security-model.md](security-model.md);
managed-store database, encryption, and audit database details are in
[docs/database.md](database.md). Writing a native provider is covered by the
[provider SDK guide](provider-sdk.md), and building another distribution from
the host by the [downstream assembly guide](downstream-assembly.md).

## MCP connection views

Aggregate MCP and service-specific connections share one bounded registry for
listing, canonical dispatch targets and action details. `/mcp/<service>` and
`mcp serve --service <service>` select an immutable view and preserve raw provider
names; transport mode independently determines local-file capabilities. Pure
adapter naming hooks derive imported names from accepted metadata. Readiness is
computed before caller filtering and published with the immutable runtime,
without a name table, extra discovery or credential lookup. HTTP routes share
one endpoint and bind sessions to the view. Current authorization, credential
selection, revision fences, limits and audit remain in their existing owners.
See the [MCP contract](mcp.md) for connection setup, naming, readiness and transport
boundaries.

## Contents

- [Purpose and the credential boundary](#purpose-and-the-credential-boundary)
- [Workspace and crate responsibilities](#workspace-and-crate-responsibilities)
- [Naming contracts](#naming-contracts)
- [Provider model](#provider-model)
- [Request lifecycle](#request-lifecycle)
- [Identity model](#identity-model)
- [Policy model (deny-by-default)](#policy-model-deny-by-default)
- [Credential model (service, per_user, lookup)](#credential-model-service-per_user-lookup)
- [Persistent storage model](#persistent-storage-model)
- [Audit and redaction model](#audit-and-redaction-model)
- [Observability and correlation](#observability-and-correlation)
- [Operational limits](#operational-limits)
- [Egress proxy model](#egress-proxy-model)
- [Dynamic config reload](#dynamic-config-reload)
- [Process shutdown](#process-shutdown)
- [Security posture](#security-posture)

## Purpose and the credential boundary

The broker mediates agent and user access to upstream services — Jira,
Confluence, CloudBees CI, GitLab REST, Gmail, Teams, reviewed imported MCP/OpenAPI
services, and host-matched Git HTTP gateways — so that the caller never holds
the broker-selected execution credential. The broker
resolves and holds the secret material; the CLI and any other client receive
only the authorized result.

The broker also provides an agent-specific capability boundary. Native service
permissions answer which user or service account may access a project, space, or
API. Broker policy answers the additional agent question: which non-deterministic
tool may exercise which service action, on which resolved resource scope, with
which validation, limits, credential mode, and audit trail.

Agents use a stable service/action interface instead of choosing between vendor
CLIs, raw REST endpoints, tenant URLs, gateway URLs, and API versions. Provider
code owns service-specific `/v1/invoke` details and converts them into
broker-scoped operations. Gateway code owns host-matched protocol traffic such
as Git smart HTTP and classifies it into the same service/action/scope policy
model before upstream credentials are selected.

The execution credential exists only inside the `ProviderInvocation` handed to a
provider for a single call. It is never placed in the response to the caller,
never serializes, and its `Debug` representation shows only the credential kind
(`ExecutionCredential { kind: "bearer_token", .. }`). The same redaction applies
to proxy credentials (`EgressProxyConfig`). The provider cannot read the
material either: static credentials and delegated access have no plaintext
accessor. The provider hands an opaque `UpstreamAuthorization` to the upstream
client's send method, and the client adds the sensitive header to the request
it builds immediately before dispatch, so the provider never holds a request
carrying the credential (see
[static credentials](provider-sdk.md#static-credentials)).

Execution credentials are resolved only **after** identity admission, scope
resolution, deny-by-default policy authorization, and credential-mode selection
have all succeeded. No credential is touched on a path that has not first cleared
authorization, except for the minimal pre-authorization metadata lookup used to
resolve Jira, Confluence, and GitLab REST scopes. That lookup uses either a
separate read-only lookup credential or the caller's per-user credential
according to the policy shape described under
[Credential model](#credential-model-service-per_user-lookup), and only once a
candidate grant exists.

## Workspace and crate responsibilities

The Rust workspace's crates share one workspace version, and the repository
also includes a same-origin browser portal frontend:

- **`agent-access-provider`** — the backend contract: service descriptors
  (`descriptor.rs`), resource types (`resource.rs`), the `Provider` trait and
  its invocation, result, and error types, standard reason codes and the subset
  providers may report (`reason.rs`), provider-owned domain reasons and the
  reason handles errors, streams, and traces carry (`domain_reason.rs`), the
  hook contract the host checks provider outcomes against (`contract.rs`),
  upstream throttling (`upstream_rate_limit.rs`: bounded `Retry-After` parsing,
  the shared `upstream_rate_limited` error, and the applied-unverified
  `mutation_verification_failed` for throttling after an applied write), the
  OAuth dialect contract (`oauth_dialect.rs`), delegated credentials
  (`delegated.rs`), and the host services backends use: upstream HTTP clients
  (`upstream.rs`), egress declarations and sanitized routes
  (`egress_config.rs`), upstream allowlists, correlation headers, upstream
  trace events (`trace.rs`), and opaque token signing (`signing.rs`). Its
  crate root exports every supported item explicitly, with presentation items
  only under `presentation`. Its public `host` module (`host.rs`) holds the
  host cooperation ports: the upstream client factory contract and the build
  context, the values only the host constructs for providers (scope requests,
  static execution credentials, admitted requests, spooled body parts and the
  final invocation), the initial correlation, hook and deadline scopes,
  service-scoped signer wrapping, delegated-lease wrapping and the host-origin
  failure port. `deps` re-exports the third-party types and macros those
  signatures name. The SDK resolves no secret references, loads no TLS files
  and reads no process environment.
- **`agent-access-core`** — the library: the request runtime
  (`runtime.rs`), the audit writer and its storage backends
  (`runtime/audit_jsonl.rs`, `runtime/audit_sqlite/`), audit queries
  (`audit_query.rs`), the backend registry (`backends.rs`), the managed
  credential store (`managed_store.rs`), config parsing and validation, host
  secret-reference resolution (`config_error.rs`), host network construction
  (`network.rs`: outbound TLS trust, egress proxy selection and the per-caller
  upstream client factories), and the response envelope types (`lib.rs`). It
  contains no backend and does not re-export the backend contract; the host,
  the binary, and the CLI depend on `agent-access-provider` directly. Its
  internal `imports` module owns the import adapter contract: imported
  service/action definitions, bounded import schemas, the `ImportedAdapter`
  seam, and the opaque `ImportedAdapterRegistration` that the shipped adapter
  crates build with an internal free function. That contract is Broker
  implementation, not a provider-author interface.
- **Import adapter crates** — `agent-access-mcp-upstream`,
  `agent-access-openapi-upstream` and `agent-access-command-import` implement
  the internal import contract and depend on core. Each exports
  `registration()`; the binary selects imports only through it. The MCP
  registration contributes its `mcp_oauth` companion dialect as the
  import-authentication role, and selecting that dialect again is rejected as a
  duplicate. OpenAPI and command imports declare no companion. Command imports
  use `command:<name>` endpoints approved in `[command_imports]`; core passes the
  approved entry and the accepted service metadata to the adapter, and runs a
  command import's calls through its command hook with a core-built request
  instead of `Provider::invoke`. Every `describe`, `invoke` and `verify` run
  starts one process under a supervisor holding a slot of the command's
  concurrency budget. Core keeps the budgets in a command registry that each
  runtime generation inherits, as it does import dispatch fences, so every
  import and generation of a command shares one budget; the fence also
  changes when the command's `[command_imports]` entry does.
- **`agent-access-content`** — rich-content formats shared by backends:
  bounded ADF, Confluence storage, and GitLab Markdown rendering; bounded
  Markdown/plain-text conversion into those formats; and attribution footers.
- **Backend crates** — `agent-access-jira`, `agent-access-confluence`,
  `agent-access-gitlab`, `agent-access-cloudbees-ci`, `agent-access-gmail`,
  `agent-access-teams`, and the development
  `agent-access-fake` depend on `agent-access-provider` (Jira, Confluence, and
  GitLab also on `agent-access-content`; Jira and Confluence on
  `agent-access-atlassian`), never on core; the broker binary registers them.
- **`agent-access-conformance`** — a test-only backend (not published, not
  linked by the broker binary) that uses every extension point of the backend
  contract; broker acceptance tests register it to prove a backend needs no
  host changes. See the [conformance reference](provider-sdk.md#conformance-reference).
- **`agent-access-atlassian`** — a native module crate: the `atlassian` OAuth
  dialect, which the broker binary registers, and the helpers shared by the
  Jira and Confluence backends: the vendor-level token profiles, the one route
  classifier that sends each credential to the route its token type selects
  (tenant host or Atlassian gateway) and refuses one without a route,
  route-coverage validation per credential source, request authorization, the
  tenant/gateway client routes, the route fingerprint their relayed
  continuations bind, and the credential binding (`bind_atlassian_access`) of
  every continuation and draft handle.
- **`agent-access-broker-host`** — the broker host library: module
  composition (`BrokerComposition`), the application (`BrokerApplication`:
  command parsing, configuration validation, audit verification, and the
  `serve` lifecycle with listeners, signals, reload, and bounded shutdown), HTTP
  routers, request decoding, host-matched gateway dispatch, source/proxy-chain
  derivation, dynamic config reload, management routing, HTTP MCP serving, and
  Microsoft membership renewal (`membership_renewal.rs`, with the ID-token
  validator it shares with sign-in in `oidc_id_token.rs`).
  It depends on core and never on a backend or import adapter. Its public API
  is the composition, the application, the assembly identity and the build
  status; its routers and reload and runtime state are private, so other
  crates, including their tests, start a broker only through the application.
  The `test-support` feature adds `test_support::IsolatedBroker`, which runs a
  composition through that same startup, reload and drain for acceptance
  tests.
- **`agent-access-broker`** — the service binary: a thin assembly that selects
  the modules it links (`composition()` in `backends.rs`), stamps its assembly
  identity and the release commit of its workspace modules (`build_identity()`
  in `build_info.rs`), and runs the host application (`main.rs`). Its library
  exports only those two functions, which the binary and the acceptance tests
  pass to the host. The host checks that identity against the composition and
  derives the build status served at `/v1/broker/status`.
- **`agent-access`** — the CLI binary that lowers commands to broker HTTP calls
  (`main.rs` plus integration tests under `tests/`).
- **`apps/portal`** — the React browser management portal built into static
  assets and served from the broker public listener when `[portal]` is enabled.

Core owns the engine and the conceptual contract. The host owns the network
surface and the process lifecycle; the broker binary selects the modules it links. The CLI never sees broker-held execution
credentials and never makes authorization decisions; it is a thin client over the broker's HTTP API.

Crate dependencies follow those roles. An assembly, upstream or downstream,
links the host and the modules it selects; providers depend only on the SDK and
ordinary helper libraries:

```mermaid
flowchart TD
    Assembly[agent-access-broker assembly] --> Host[agent-access-broker-host]
    Downstream[Downstream assembly] --> Host
    Assembly --> Natives[Native provider crates]
    Downstream --> Natives
    Downstream --> Own[Downstream provider crates]
    Assembly --> Adapters[Import adapters: MCP and OpenAPI]
    Downstream --> Adapters
    Host --> Core[agent-access-core]
    Host --> SDK[agent-access-provider SDK]
    Adapters --> Core
    Core --> SDK
    Natives --> SDK
    Own --> SDK
    Natives --> Helpers[Helper: content]
    Helpers --> SDK
    Reference[Conformance reference, tests only] --> SDK
    CLI[agent-access CLI] --> Core
    CLI --> SDK
```

Every workspace crate declares one role (`sdk`, `core`, `host`, `assembly`,
`cli`, `native`, `reference`, `adapter`, or `helper`), and
`node scripts/check-crate-boundaries.mjs` rejects dependency edges that cross
them: the SDK depends on no workspace crate, natives, the reference and helpers
never reach core, the host, an assembly, the CLI or an adapter, and the
production closures of core and the host contain no native, adapter or
reference crate. See [testing](testing.md) for the exact rules, the
[provider SDK guide](provider-sdk.md) for the supported provider surface, and
the [downstream assembly guide](downstream-assembly.md) for building another
distribution.

At run time, requests flow through those components:

```mermaid
flowchart LR
    Agent[Agent or user] --> CLI[agent-access CLI]
    Agent --> Http[Direct broker HTTP client]
    CLI --> Broker[Broker host application]
    Http --> Broker
    Broker --> Core[agent-access-core runtime]
    Core --> Jira[Jira provider]
    Core --> Confluence[Confluence provider]
    Core --> HttpSvc[Reviewed imported MCP/OpenAPI adapters]
    Broker --> Gateway[Git HTTP gateway dispatch]
    Core --> Store[Managed store]
    Core --> Audit[Audit store: SQLite or JSONL]
    Jira --> Upstream1[Jira API]
    Confluence --> Upstream2[Confluence API]
    HttpSvc --> Upstream3[Operator-approved upstream]
    Gateway --> Upstream4[Git upstream]
```

### Composition and process lifecycle

An assembly builds one `BrokerComposition` from the native registrations,
OAuth dialects and import adapter registrations it links. Building validates the
selections together and produces an immutable registry that every command and
runtime generation shares; nothing rebuilds it later. `BrokerApplication::new`
checks the assembly's [identity](#assembly-identity) against the composition
and derives the build status. `run_from_env` then owns command parsing,
logging, the Tokio runtime, `config validate`, `audit verify` and `serve`, and
returns an exit status instead of exiting: `3` for an invalid composition,
identity or configuration.

`serve` loads and validates the configuration through the selected parsers,
acquires the state locks, builds the first runtime generation (each configured
provider is built for it), then binds the listeners and starts serving. A
[reload](#dynamic-config-reload) validates a candidate configuration and builds
a new generation within the same composition; operations keep the generation
that admitted them. Changing what is linked requires a new build and a restart.
[Shutdown](#process-shutdown) drains listeners, closes HTTP MCP sessions, then
drains operations, command-import processes and audit within a bounded budget.

### Core vs provider responsibilities

The core runtime owns identity admission, the lookup-before-policy gate, scope
resolution orchestration, deny-by-default policy selection, credential
resolution, audit, redaction, limits, and the egress-proxy decision. A provider
owns its action catalog, its input schemas, its locator and key grammar, its
query-language parsing and canonical re-emission, and the construction and
execution of the upstream request given a resolved scope set and an execution
credential. The provider receives an already-resolved, already-authorized scope
set; it does not consult policy.

## Naming contracts

- **Service names** match `^[a-z][a-z0-9_-]{0,62}$`. The built-in providers are
  `jira`, `confluence`, `gitlab`, and `cloudbees_ci`; Git gateway services and the test-only
  `fake` provider use the same grammar.
- **Identity source names** match `^[A-Za-z0-9._-]{1,128}$` and must be unique.
  `browser-session` is reserved in any letter case for portal sign-in sessions.
- **Policy subjects** are `user:<principal>` or `group:<group>`;
  `user:anonymous` and `group:anonymous` are ordinary subjects with no special
  treatment.
- **Request-id header** `X-Agent-Access-Request-Id` is required on every `/v1`
  endpoint except `/v1/healthz` and `/v1/readyz`, and must be `1..=128` chars of
  `[A-Za-z0-9._-]`.
- **Provider keys/locators** follow per-provider grammars (Jira project/issue
  keys, Confluence page/space/attachment IDs); see
  [docs/providers.md](providers.md).

There are no `/v1/providers/*` typed routes. Typed CLI commands (for example
`jira issue view`) lower to `POST /v1/invoke/{service}/{action}`; no typed HTTP
routes are registered on the broker.

## Provider model

A provider advertises a set of **actions**, each carrying its **scope types**
and its **credential modes** (`service`, `per_user`). The runtime asks a provider
to resolve scopes for an action, then authorizes the resolved scope set against
policy, then asks the provider to execute.

### Backend registration

The broker binary selects the modules it links through `composition()` in the
broker crate: native backends, OAuth dialects, and import adapters (as the
opaque registrations their crates' `registration()` returns), validated once
into an immutable `BrokerComposition` that every command and runtime
generation shares. Building it rejects invalid identifiers and duplicate
backend kinds, resource types, dialects, and adapters; an import's companion
dialect counts as selected, so selecting it again with `.oauth(..)` is a
duplicate. Each `BackendRegistration` is a `static` built with its `const`
constructor and builder methods. It names the declaring package (name and
version, captured with `module_metadata!()`), a kind, the resource types the
backend defines, a strict parser for its `[providers.<kind>]` table, and whether
it is a development fixture. OAuth dialect and import adapter registrations
carry the same package metadata. Parsing a configuration routes each provider table
to its backend's parser and rejects unregistered kinds; the registry also
supplies the resource type registry (the broker's own `git_repository` type
plus every backend's types, in registration order). Each runtime generation
builds its effective registry from it and from the resource types its imports
accepted, recording which backend, import, or the broker owns each type; the
generation publishes that registry together with its imported catalog, service
descriptors and policy snapshot, and a type's owner validates the private
attribute values of its resources. Startup builds the registry from stored
import metadata before it validates stored resources. Development fixtures are
ordinary registrations: the binary selects the `oauth_stub` records backend
last, so its `oauth_collection` type lists last, and selects the `stub` OAuth
dialect alongside the production dialects. An empty registry has neither.
A parsed table is a `BackendConfig`: it validates itself against a narrow view
of the rest of the configuration (deployment environment, broker limits, and
the credential kinds configured for its service), derives its service
descriptor, lists its egress proxies for startup preflight, and builds its
provider from a `BuildContext`: limits, the host's upstream client factory,
attribution, and the optional stable signing key, scoped to the backend's
service so one backend's tokens never verify for another. Building is
synchronous and offline: it prepares clients and capabilities but never
contacts an upstream, verifies a credential or refreshes OAuth. A failure is a
`ProviderBuildError` carrying safe configuration diagnostics; when the host's
own network construction failed, the host keeps its cause, such as a missing
proxy credential reference. Configuration parsing, validation, and provider
construction never name a backend kind; development fixtures additionally
require `deployment.enable_fake_service`.

Backends reach their upstream through `UpstreamClient`s built through that
factory, which apply the rules every backend shares. A backend declares each
client's label, base URL, egress declaration (ordinary routing with its
configured service proxy, or the literal-loopback request described under
[Egress proxy model](#egress-proxy-model)) and profile; core constructs the
client with the generation's outbound TLS trust and selected route, never
follows redirects on its own, and bounds time by profile: a whole-request
timeout for ordinary requests (with automatic retries disabled for
single-attempt and explicitly bounded clients), none for streamed downloads
(the backend bounds each chunk), and a connect timeout for uploads, whose
bodies fail after the streaming idle timeout without progress. Backends see
only the sanitized route (mode and proxy origin) for audit, never proxy
credentials. Every request sent through the client, including each hop of
a redirect chain followed with `get_following_redirects`, must match the
backend's `allowed_upstream_hosts`. Credentials stay on the client's base
origin: the client refuses, before sending, any request to another origin that
carries an `Authorization`, `Proxy-Authorization` or `Cookie` header or a header
value marked sensitive, as proven unsent (see
[credentials and origins](provider-sdk.md#credentials-and-origins)). The
redirect helper presents the backend's authorization only on hops within the
chain's authorized path on that origin: the client's base, or a prefix the
backend names, such as an Atlassian site's `/ex/<product>/<cloudId>/` path on the
gateway. With an authorization, a hop on the base origin outside that path fails
the chain before it is sent. An authorization can come from a per-hop
authorizer, which Jira and Confluence use to revalidate delegated access
immediately before each authorized hop. Redirect
hops to other origins carry correlation headers only when the backend opts in
(Jira and Confluence do, for Atlassian media hosts; CloudBees CI does not, for
artifact storage). Each request records one
`upstream_request_completed` trace, either when the backend has classified the
response or when the response is dropped. The trace captures the provider hook
that sent the request, including from work moved onto other tasks with
`InvocationScope`. The backend's classification, or a status reason its client
declared, must be one that hook may report, a registered domain reason, or a
host port's failure; any other, or one made outside a provider hook, is
recorded as `broker_provider_contract_failed`. A transport failure's
classification is the client's own. Backends keep their own protocol:
URLs, authentication schemes, status and body handling, and any extra checks
on redirect targets.

### Continuation tokens

The SDK provides a continuation envelope (`ContinuationFamily`,
`ContinuationBinding`, `ContinuationSigner`) for native actions that return a
resumable cursor, page token or handle. Every native provider that returns such
a token uses it: CloudBees CI log cursors and job-list tokens, GitLab REST page tokens, Gmail and
Jira search page tokens, and Confluence search cursors, list tokens and draft
handles. A provider declares each token family once: its service and purpose, a
version, an explicit payload cap (a family relaying an upstream token may
instead derive it at construction from a configured limit), an optional expiry,
and a signing lifetime:

- **generation**: a key generated with the provider instance, so a reload or
  restart invalidates the tokens even when a stable key is configured;
- **stable when configured**: the service-scoped stable key derived from
  `broker_tokens.hash_key_ref` when one is configured, otherwise the
  generation key;
- **durable**: only the stable key; sealing or opening fails without one.

A token is bound to the admitted service and action (a handle family may span
the service's actions), the host-selected execution context, the credential
mode, the principal (a family that deliberately shares service-mode tokens
binds it only in per-user mode), the provider's configuration fingerprint, and
the resource identifiers and normalized query, filter and output settings the
provider adds. Delegated families also bind the lease's `DelegatedBindingId`,
target and audience, which routine token refresh keeps. Providers of services
whose credential connections can select either a token or OAuth (GitLab, Jira
and Confluence) bind the execution material's method in every family: a static
credential's kind, or the lease's binding, target and audience, plus the
gateway cloud ID for Atlassian gateway routes, so an Atlassian scoped API token
(Basic on the gateway) and a classic one (Basic on the site) never share
tokens. A method switch, account
replacement, disconnect and reconnect, or tenant change therefore invalidates
their tokens, while routine refresh and, for stable-key families, a restart
keep them; static token values are not bound. The binding is a
canonical, length-delimited encoding whose digest enters the HMAC context with
the service, purpose and version; the token itself carries only the version,
the expiry, the provider payload and the MAC. Any other binding, purpose, key
or version rejects the token, and obsolete versions are never decoded. The
encoded size cap is derived exactly from the payload cap; an oversized payload
or token is an error, never truncated. The effective grant boundary is not
bound: the host authorizes every continuation under current policy and the
provider re-applies its containment and result checks. Each provider's
documentation states its families' bindings and lifetimes.

A family that relays an upstream service's own page token seals it as text,
optionally with a keyed commitment to the upstream query the provider composed
under current authorization; when a grant change recomposes that query, the
token is rejected as belonging to a different query instead of being sent
upstream with the new one. Such a family may size its tokens from the
provider's response limit instead of a declared cap, since the upstream token
arrives in a bounded upstream response and the continuation leaves in a
bounded result.

A family whose tokens are read during scope resolution, before the host admits
a credential mode (Confluence draft handles), binds only what scope resolution
knows: service, action or handle scope, execution context, configuration and
the provider's fields. Its owner travels in the token as a keyed ownership
commitment: scope resolution accepts the token only when the current principal
could own it, and the provider opens it again after admission, when the
commitment must match the admitted credential mode and principal. Confluence
draft handles also carry a keyed commitment (`ContinuationSigner::commit`) to
the execution material they were minted with, which scope resolution cannot
know; it is checked when the handle is opened after admission.

### Assembly identity

The executable supplies an `AssemblyIdentity` with its composition to
`BrokerApplication::new`: its name, version and command description, a
bounded qualification label (`unqualified` unless the assembler declares one),
the source revisions it supplies for itself, the host and the SDK, and a module
provenance map keyed by registered crate name and version. Each revision is a
full Git object ID marked as declared or backed by the assembler's build
evidence; an omitted revision is reported as unavailable, never inferred. The
host rejects, as a composition error that exits `3`, malformed fields, map
entries naming a package that registers no module (including the host or SDK
themselves), repeated entries, and conflicting revisions. It derives the build
status served at `/v1/broker/status`: the assembly, the host and SDK packages,
and the compiled module inventory with every role each package registers, in
canonical order, plus an inventory fingerprint over the host, SDK and modules
with their revisions and provenance. The status lists what is compiled in, not
what is configured, and no reload changes it. The `broker_starting` event
carries the assembly identity and that fingerprint.

The assembly identity names the aggregate HTTP MCP server and the program in
state-lock holder metadata. Lock file names, the configuration path, state and
keys never depend on it. Imported MCP connections identify the client as the
host implementation (`agent-access-broker-host` and its version), not the
assembly or the adapter package. The upstream `agent-access-broker` stamps a
release build's verified commit, from `AGENT_ACCESS_BUILD_COMMIT`, as
evidence-backed for itself, the host, the SDK and each of its workspace modules.

### Adding a backend

A backend is a crate that depends only on `agent-access-provider` and exports
one `BackendRegistration`; selecting it in an assembly's composition is the only
host change. The [provider SDK guide](provider-sdk.md) is the provider-author
reference: the supported surface and trust model, registration and
configuration, descriptors and typed resources, scope resolution and provider
state, admitted authority and credentials, governed HTTP, continuation tokens,
reasons and outcomes, testing with the SDK test support and the conformance
reference, the compatibility policy, and a worked example.

A backend builds SDK values through constructors and builders, not struct
literals: registrations, resource types, reason definitions and presentations
are `const` statics, and results, descriptors and OAuth values use `new` with
`with_*` builders. Only the shared configuration tables, such as
`AttachmentLimitsConfig`, are deserialized or built from `Default` with struct
update syntax. Extendable SDK enums are non-exhaustive, so a backend's matches
end with a fallback arm that rejects what it does not support, such as an
unknown credential kind. The policy and the intentionally exhaustive items are
listed in the [inventory guide](../api/README.md#construction-and-exhaustiveness-policy).

### Provider hook contract

The runtime runs each provider hook (scope resolution including lookup, body
admission, invocation, credential verification) under a host-supplied
`HookContext`: service, action, phase, and the domain reasons pinned with the
prepared operation's provider. It checks only the hook's own future, not host
work around it such as lease revalidation or attribute decryption. A failure
passes when it is a registered domain definition (compared by value), a host
port's failure within that port's allowlist (the delegated lease, or the SDK's
admitted-operation accessors), or a provider-reportable standard reason for
the phase and decision, with `upstream_rate_limited` carrying its rate-limit
result and allow limited to an invocation's `verification_mismatch` with its
result. Anything else becomes `broker_provider_contract_failed` with a fixed
message and an internal diagnostic code; an invocation's failure adds an
unknown, not retry-safe execution state, and lookup concealment still applies.
Late result-stream failures are checked against the code-only subset and the
domain reasons, never a host port's reason. Imported services have no domain
reasons. Their adapters' administrative discovery runs as a
credential-verification hook of the imported service; an adapter reports
invalid settings or document destinations as a typed configuration failure,
which the host reports as `config_validation_failed`.

### Service descriptors

Each service has one authoritative `ServiceDescriptor`. A built-in backend
derives it from its typed configuration alone (`jira_descriptor`,
`confluence_descriptor`, `gitlab_descriptor`, `cloudbees_ci_descriptor`, and
the development `fake` and `oauth_stub` backends); configured
Git gateways get a descriptor from their gateway configuration. Providers do
not describe themselves: the runtime pairs each provider it builds with its
configuration's descriptor (a `ServiceProvider`), so offline configuration
validation, TOML and managed policy validation, runtime admission, discovery,
the runtime catalog, OpenAPI, the send schema, and managed credential forms all
read the same descriptor instead of parallel per-service tables. The runtime
validates every descriptor once per configuration generation and caches it; the
per-request path never rebuilds an action catalog.

Validation rejects a descriptor before activation (and in offline `config
validate`) when an action's input schema is not an object schema that compiles
as JSON Schema, when an upload locator is not an input, when a sensitive output
is not a JSON pointer into `/result`, when an action resolves its scope by
lookup without declaring one, when a raw-download action declares a response
presentation, or when a scope binds an unregistered resource type or offers a
selector that type does not support.

An action's descriptor also carries its response presentation: the embedded
upstream bodies that `readContentFormat` normalizes (an owner path and a body
codec each) and, optionally, a whole-result Markdown renderer for
`responseFormat = "markdown"`. The presentation engine in
`agent-access-provider` applies them under one shared render budget and bounds
the serialized result; each backend supplies its codecs and templates, and the
rich-content format renderers live in `agent-access-content`. The catalog's
advertised read and response formats derive from the same presentation.

A descriptor declares the service's resource scopes and the resource type each
one authorizes, and for every action its input schema, resource scope (if any),
credential modes, lookup requirement (none, execution-time only, or before
policy to resolve scope), its optional native search enforcement mode, upstream resource
ownership, JSON/multipart-upload/raw-download I/O, explicit `read_only`,
sensitive output pointers, optional extended `documentation`,
optional explicit `listingOf` enumeration metadata,
attribution capability, and whether it issues durable handles that need a stable
signing key. At service level it declares accepted service credential kinds,
managed credential profiles, whether invocations need a broker-selected
execution credential, and the embedded-body presentation limit. Responses from
actions that declare sensitive outputs are sent with `Cache-Control: no-store`.

Action `documentation` is a provider-owned JSON object for detailed usage,
grammar, limits, and examples. Capabilities, runtime catalogs, and detailed MCP
discovery (`actions_describe` and `services_describe`) expose it; OpenAPI/send
projections use `x-agent-access-documentation`. It stays outside MCP tool
definitions and input schemas. Initial tool descriptions remain concise and
point to `actions_describe` with canonical service/action arguments, independent
of tool names assigned by a client or connection view.

Read classification defaults to false and is explicitly opted into by reviewed
backend descriptors; action names and presentation capabilities do not infer it.
Runtime, discovery, and management catalogs publish `readOnly`, and OpenAPI/send
variants publish `x-agent-access-read-only`. This metadata classifies upstream
reads for grant selection and never gates local output. It grants nothing, but
it is the ceiling of a
[read-only identity path](#trusted-human-identity-and-mcp-admission): such a
path can use only actions classified as reads. A backend that reclassifies a
native action therefore changes read-only access, and the release notes call out
every such change. JSON and multipart-upload action responses support local
file/metadata destinations, including mutations. Dedicated raw downloads retain
their streaming contract.

Scoped native read actions can separately opt into reporting universal reach.
The host accepts this only for ordinary resource authorization, without native
search, imported/command enforcement or private resource attributes. After
source admission and execution credential resolution, it derives ordinary
effective clauses from the admission's policy snapshot, ceilings and token
restrictions, retains only the selected mode's winning reach, and proves that
the union of their single-target reach covers the universal selector. It
preserves competing modes and grant-local exclusions; enumerating registered
projects or finding one broad grant is insufficient.

The resulting immutable `universal_reach()` hint permits the provider to disclose
metadata about other resources embedded in the same upstream response. It
does not change the exact admitted source scopes or authorize additional
requests or credential acquisition. Jira uses this only for `issue.view`
embedded links, parent and subtasks, all under the same disclosure decision.
These references do not establish complete epic ancestry or descendants.
The proof depends on project being that action's sole
target-dependent admission input: adding issue-level, issue-type or
attribute-bound authority requires revisiting the contract. It does not prove
current target identity, upstream visibility or successful lookup on a later
direct view. The hint defaults to false and is not projected into client
catalogs, OpenAPI or send schemas.

The grant picker separates Read-only and Write-capable actions, with independent
All/None controls for search matches. Grant listings derive a Write-capable
checkmark from their explicit action selections. Unreviewed actions are treated
as potentially writable. Neither filtering nor classification changes silently
modify grants, and future tools are not automatically selected.

CLI and stdio MCP output handling owns local paths; broker invoke schemas and
HTTP MCP accept none. The CLI renders its normal successful action representation;
`send` and MCP save complete JSON envelopes. The shared local writer uses a
private temporary file reserved before provider dispatch, including downloads,
and atomic replacement, returning a bounded receipt with
correlation/status identifiers plus path, byte count, digest, content type, and
declared sensitivity. Ordinary response content is omitted from that receipt;
raw-download receipts retain broker download metadata. Limits and pagination
remain unchanged, and file output never expands the resource/action grant.
Confirmed operation success followed by local output failure is reported as two
separate outcomes with request identifiers and a nonzero CLI/error MCP result.
The client never stores the payload for recovery or retries an operation to save
its response. A post-replacement directory-sync failure reports that the local
destination has already changed.
Invalid destinations fail before invocation. Unverified mutations retain their
unverified status through response and metadata output, with bounded,
non-sensitive reconciliation metadata rather than the full result. Exit code
alone never establishes whether a mutation was dispatched or is safe to retry.

An action may also advertise `upstreamResourceOwnership` as static capability
metadata. When a concealed `scope_unresolved` result repeats that value under
`hints`, it still describes only the action's ownership model. The value is
fixed independently of the requested locator and must never encode resource
existence, ownership of a particular object, or an authorization outcome.

- **Jira** (`jira`) — twenty-four actions: `project.list`, `project.view`, `issue_type.list`, `issue.view`, `issue.create`,
  `issue.child.create`, `issue.update`, `issue.parent.set`,
  `issue.dependency.add`, `search`,
  `comment.list`, `comment.view`, `comment.add`, `comment.reply`, `comment.update`,
  `comment.delete`, `comment.property.list`, `comment.property.get`,
  `comment.property.set`, `comment.property.delete`, `attachment.add`,
  `attachment.download`, `attachment.list`, `verify`. Policy scope is the
  containing `project`. `project.list`, `project.view`, `issue_type.list`, `issue.create`, and `search` do not
  require pre-authorization metadata lookup. `project.list` scans the live project
  collection under bounded work limits, filters current project keys against
  normalized action authority, and seals confidential continuations bound to that
  authority. `project.view` authorizes an exact project before fetching details,
  searchable fields and optional project metadata with the execution credential.
  Its field operators intersect Jira's discovery with the bounded JQL grammar;
  custom-field search uses stable `cf[ID]` references and retains search's project
  containment. `issue_type.list` returns one page
  of creation metadata using the execution credential, with IDs, names,
  descriptions, subtask flags, and explicit continuation offsets.
  `attachment.list` is a single fetch, not paginated. Issue
  description and comment writes use canonical `content` plus an explicit
  `contentFormat`. `issue.create`, `issue.child.create`, `issue.update`,
  `comment.add`, `comment.reply`, and `comment.update` accept `adf`, `markdown`,
  or `plain_text`; normalized input is converted to ADF (Atlassian Document
  Format, a `{ "type": "doc", "version": 1, "content": [...] }` JSON
  document). Comment property actions require an issue locator and are limited
  to broker-owned key prefixes.
  Jira normalized reads cover seven actions whose
  results declare ADF advertise `readContentFormats = [native, markdown, text]`:
  `issue.view`, `issue.create`, `issue.update`, `comment.view`, `comment.add`,
  `comment.reply`, and `comment.update`. Eleven non-streaming retrieval actions
  advertise `responseFormats = [json, markdown]`: `project.list`, `project.view`, `issue_type.list`, `issue.view`, `search`,
  `comment.list`, `comment.view`, `comment.property.list`,
  `comment.property.get`, `attachment.list`, and `verify`.
- **Confluence** (`confluence`) — space listing, page, blog, attachment,
  verification, and comment actions. The separately granted, read-only
  `space.list` enumerates current spaces with the selected execution credential,
  filters canonical keys through normalized space authority before projection,
  and requires no lookup access. URL aliases affect validated links only. Page actions include `page.view`, `search`, `page.create`,
  `page.update`, the separately granted `page.move`, `attachment.add`,
  `attachment.download`, `attachment.list`, and `verify`; blog actions mirror
  them under `blog.*`; draft actions are
  explicit under `page.draft.*` and `blog.draft.*` for create, stage, view,
  update, publish, discard, verify, and new-draft attachment add/list/download;
  comment actions are split into `page.footer_comment.*`,
  `page.inline_comment.*`, `blog.footer_comment.*`, and
  `blog.inline_comment.*`, including list, view, add where supported, update,
  delete, and reply flows. Policy scope is the containing `space`. Current content
  actions remain current-only. Draft actions authorize their containing space,
  using signed broker draft handles after create/stage. Page search
  remains page-only and blog search is a separate action that injects
  `type = blogpost`. Page and page-draft creation optionally place content below
  a resolved same-space parent and use space-homepage placement otherwise.
  Existing page hierarchy changes use `page.move`, are same-space only,
  support `before`, `after`, and `append` placement, and verify the parent and
  direct-child order by readback. Create actions resolve
  the target space directly from inputs. Update actions are optimistic-concurrency.
  Search, blog search, attachment and comment list actions are cursor-paginated
  with broker-signed continuation tokens that relay Confluence's cursor. Space
  listing uses bounded single-attempt requests and shared request/body budgets;
  its confidential continuation preserves original expiry and binds current
  authority, inputs, and route configuration on every resume. See
  [space listing](providers-confluence.md#live-space-listing). Twenty
  current page/blog, draft, and comment mutations use canonical `content` plus
  explicit `contentFormat`. Markdown and
  plain text are converted to constrained storage HTML; native storage remains
  a string, and current page create/update also retain native
  `atlas_doc_format` JSON when enabled. Twenty-six Confluence actions whose
  results declare storage or ADF bodies advertise embedded `native`,
  `markdown`, and `text`: current page/blog view, page/blog draft view, every
  page/blog footer/inline comment list/view/reply-list read, footer-comment
  adds, footer/inline comment updates, and footer/inline reply adds. Twenty-seven
  non-streaming retrieval actions advertise whole-result `json` and `markdown`:
  space list, current page/blog view/search/verify, page/blog draft view/verify, current and
  draft attachment lists, and every page/blog footer/inline comment
  list/view/reply-list read. Body-free search and attachment results remain
  body-free, and formatting performs no additional provider call.
- **GitLab REST** (`gitlab`) — repository-scoped project, issue, merge-request,
  review discussion, current/historical diff, branch, protected branch, file,
  REST commit, CI pipeline, and CI job actions.
  The scope type is `repository`, expressed as the project's current GitLab
  path, which lookup resolves from an old path of a moved project too. Merge
  requires a caller-supplied current merge-request head SHA and delegates final
  branch protection, approval, and CI decisions to GitLab. Direct branch, file,
  and commit writes and CI execution actions reject default and protected
  branches, file mutations use last-commit checks when GitLab exposes them, and
  raw file/job-trace downloads use the broker raw-download stream path.
  Sixteen issue-description, merge-request-description, note, discussion,
  draft, and review-summary mutations use canonical `content` plus explicit
  `contentFormat`. Native
  Markdown is preserved before attribution; `plain_text` is deterministically
  escaped so CommonMark and GitLab-specific syntax remains literal.
  GitLab actions whose results declare issue/MR descriptions or note/
  discussion-note bodies advertise embedded `native`, `markdown`, and `text`:
  issue view/search/create/update and note list/add/update; merge-request
  view/search/create/update and note list/add/update; discussion
  list/add/inline-add/view/resolve/reopen and discussion-note add/update; and
  draft-note list/view/add/update. Non-streaming GitLab
  retrievals advertise whole-result `json` and `markdown`: project view; issue
  view/search/note list; merge-request view/search/note list/discussion
  list/view, reviewer/commit/pipeline lists, current structured diffs and diff
  version list/view and draft-note list/view;
  branch and protected-branch list/view; protected-branch verify; file view;
  commit list/view; pipeline list/view; and job list/view. Raw file and job-trace
  downloads, raw current-MR diff, and all mutations remain ineligible for
  whole-result Markdown. Review positions preserve the exact diff SHA triplet,
  paths, lines/range, and historical association rather than synthesizing a
  current-line mapping.
  Direct inline and positioned draft writes require a fresh expected head and
  complete non-null diff SHA triplet, derive native anchors from strict
  coordinates, and fail closed on stale or unprovable positions. Replies target
  a discussion ID and remain valid for outdated threads. Draft ownership follows
  the active upstream credential: per-user mode isolates a human reviewer,
  whereas service mode intentionally shares a bot-owned draft set.
  Draft CRUD and single/all publication are separate policy actions.
  A verified single-draft publication returns the exact resulting non-null
  `discussionId` and `noteId`, established by bounded before/after discussion
  readback rather than timestamp, ID ordering, or body-only guessing.
  `review.submit` requires GitLab 19.2+, publishes the current-owner snapshot,
  then verifies `reviewed` or `requested_changes`; neither state is formal
  approval, and zero-draft summary submission remains valid. An unassigned
  actor fails with `version_conflict` before publication.
- **Imported services** — reviewed MCP HTTP tools and OpenAPI operations use
  persisted action definitions, operator-approved destinations, ordinary
  action/context grants, and single-attempt execution. They have no broker
  resource scopes; the selected upstream credential sets the business-data
  boundary. MCP discovery, verification and invocation each prefer `2026-07-28`
  and permit one `2025-11-25` initialization attempt on a bounded startup
  rejection. The host transport owns selection, deadlines, credential fences
  and the single tool dispatch; the pinned SDK handles the selected lifecycle.
  Negotiated versions are recorded in existing metadata/audit fields. Legacy
  sessions are private to one operation, with best-effort cleanup of initialized
  and eligible rejected-probe sessions within a shared two-second budget and
  the parent deadline. Cleanup never changes a known outcome or rejects an OAuth
  token. Existing imports and OAuth connections require no migration or consent.
  Import eligibility for personal OAuth comes from the selected import kind's
  companion: the binding must name that companion's dialect, and the companion
  supplies each registration's validated approved resource, which must equal
  the endpoint along with the profile's target and audience. Selecting another
  dialect never makes it eligible for an import.
  The adapter supports bounded JSON and finite SSE responses; server requests
  (including legacy `ping`), stream resumption and tool replay are unsupported.
  A legacy disconnect does not prove upstream cancellation. Redirects are
  rejected. See
  [imported services](imported-services.md) and [OpenAPI imports](imported-openapi.md).

  Swagger 2.0 and OpenAPI 3.1 JSON readers normalize operations inside the same
  `openapi_http` adapter, sharing bounded schema compilation, frozen-plan
  validation and HTTP execution. JSON and scalar URL-encoded bodies use that
  common dispatch boundary. A generic offline adapter credential contract
  declares execution and dedicated-slot material requirements; core uses it for
  encrypted persistence, personal profiles, local availability and management
  input descriptions. Basic uses existing username/token storage and SDK
  placement. Prepared credential writes check the exact import record in the
  store and retain the admitted snapshot under the host publication lock,
  including personal and administered writes.

  URL and uploaded JSON sources enter that same compiler. The generic adapter
  source contract selects retained document input without core interpreting
  protocol settings. Route metadata marks the upload as `raw_json`, preserving its
  exact-byte requirement in OpenAPI and excluding it from generic JSON `send`.
  Uploaded raw bytes live in a bounded per-service store row,
  separate from catalog definitions. Preparation compiles outside the database;
  the mutation owner checks the admitted snapshot and service/catalog revisions,
  then commits source bytes, preview and quarantine together before publication.
  Invalid or stale replacements change none of them. Offline refresh loads the
  retained source; execution and startup use the accepted plans. Uploads resolve
  relative destinations against the separately approved API endpoint and never
  turn filenames or external references into fetches.

- **CloudBees CI** (`cloudbees_ci`) — separately granted, read-only `job.list`
  filters live recursive inventory through normalized job authority. It proves
  descendant reachability before fetching containers, preserves independent
  allows and exclusions, and encrypts bounded traversal paths/offsets in fixed
  15-minute continuations. Its JSON-only results report explicit completion or
  incomplete coverage at depth/state/upstream range limits. Other typed actions
  view jobs and builds,
  read bounded console-log head/tail/literal-search excerpts with verified
  continuation cursors and test summaries, list and download archived artifacts,
  inspect a queued build, and trigger a non-parameterized build.
  Additional reads expose Pipeline stages and nodes, bounded node logs, pending
  input prompts, and detailed test previews. Full console logs and JSON test
  reports use the broker's raw download stream path, as artifacts do. Each
  download requires its own action grant on the same job resource. Fixed
  controller aliases prevent caller-chosen origins. All actions authorize the
  combined `controller/full/job/name` resource; queue reads prove task identity
  before disclosure. See [the provider contract](providers-cloudbees-ci.md).

Jira and Confluence send each credential to the route its token type selects.
The runtime lends a credential as the token profile it was stored or configured
as (`ExecutionCredential::profile()`), and one fallible classifier in
`agent-access-atlassian` decides every route, for requests, verification,
downloads and continuation binding alike: a classic API token
(`atlassian-api-token`) takes the tenant host; a scoped API token
(`atlassian-scoped-api-token`, Basic), a bearer token
(`atlassian-bearer-token`) and OAuth take the Atlassian gateway
(`api.atlassian.com`) on the configured cloud ID; a credential without a
profile takes its kind's route. An unknown profile, a profile/kind mismatch and
a gateway credential without a valid `cloud_id` are refused before anything is
sent, as `credential_not_provisioned`, the reason continuation binding reports
for the same credential. The gateway route exists exactly when `cloud_id` is set, which must then
be a UUID. Validation checks, per configured credential source, that the
allowlist covers every API base the product uses on that source's route, with
`base_covered_by_patterns` over the runtime allowlist grammar; coverage proves
reachability, while each request is still checked against the allowlist.
Credentials of different types therefore coexist in one deployment, such as
people on OAuth beside service accounts' classic and service-account tokens.
All three Atlassian profiles are route-bound, so a Git gateway never presents
one.

Response presentation is common invoke metadata, not provider input. JSON and
multipart `InvokeRequest` envelopes may carry top-level `readContentFormat`
(`native`, `markdown`, or `text`) and `responseFormat` (`json` or `markdown`)
beside `inputs`. Omission is identical to `native` plus `json`. The request is a
closed object, and neither field is forwarded upstream. A non-native embedded
format cannot be combined with whole-result Markdown. Unsupported
action/format combinations fail with `response_format_unsupported` before
authorization, credential selection, or provider execution.

Embedded formatting preserves the native field and adds `renderedBody` beside
its owning result entity. Whole-result formatting receives the already-produced
result, performs no additional fetch or pagination, and replaces `result` with
`{ "format": "markdown", "value": "..." }` inside the normal response
envelope. Its typed templates include every meaningful present field in stable
order and never expose raw ADF or Confluence storage HTML. GitLab embedded
Markdown is byte-for-byte native; its text renderer and whole-result composer
parse under fixed bounds, suppress active raw HTML, and close body structures
before rendering subsequent result metadata.

## Request lifecycle

Invocation preparation runs a fixed sequence. Each failure point produces one
terminal audit record and response. Ordinary JSON HTTP and HTTP MCP calls use a
shared supervised operation owner; preparation itself does not append a record,
so cancellation cannot race preparation failure into duplicate finalization.

The operation owner retains the admitted runtime snapshot and concurrency permits
through preparation, provider execution, verification and acknowledged audit.
Response delivery is separate: dropping the HTTP/MCP response waiter does not drop
the provider future. Explicit MCP cancellation has an atomic gate before provider
execution. Once execution starts, cancellation is advisory and bounded completion
continues. Preparation/provider panics are converted to sanitized operation errors;
a timeout before a result is ready, or forced shutdown after dispatch, reports an
unknown outcome without claiming rollback or retry safety. Mutations are never
automatically replayed.

HTTP MCP adds its own absolute `mcp.operation_timeout_ms` deadline shared by
rate waiting and execution. The existing
`limits.request_timeout_ms` still bounds individual upstream requests; HTTP request bodies, including multipart uploads, also have the independent
`limits.request_body_timeout_ms` total receive deadline. Final audit
acknowledgement is outside cancellation selection so a queued terminal append
cannot be abandoned and then retried as a second terminal outcome.

Imported MCP passes the host deadline into its operation context and marks session
cleanup only after capturing the provider outcome. If the ordinary HTTP MCP
deadline expires during that cleanup phase, the supervisor polls the same provider
future once more without waiting. Cleanup stops at the deadline and returns the
captured outcome for the response and terminal audit. A still-pending future
retains the timeout outcome; this adds no grace period, detached cleanup task or
second dispatch. Forced shutdown retains the existing unknown-outcome behavior,
including when cleanup is in progress.

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller
    participant B as Broker runtime
    participant I as Identity source
    participant P as Provider
    participant A as Policy
    participant R as Credential resolver
    participant U as Upstream service
    participant L as Audit sink

    C->>B: Invoke service/action with structured inputs
    B->>B: Resolve attested execution context
    B->>I: Resolve principal and groups
    B->>B: Charge the (principal, service) invocation window
    B->>A: Plan lookup credential when metadata lookup is required
    B->>A: Build clause authority for native search actions
    B->>R: Load shared lookup or caller per-user lookup credential
    B->>P: Resolve resource scope or compose scoped search
    B->>A: Authorize service/action/scope
    B->>R: Load selected execution credential
    B->>P: Execute provider invocation
    P->>U: Provider-owned upstream request
    U-->>P: Upstream response
    B->>L: Append redacted audit record
    B-->>C: Response envelope or approved raw stream
```

1. **Execution-context admission.** The broker resolves exactly one context from
   fixed `X-Agent-Access-Context` before token lookup. Missing strict-mode,
   malformed, duplicate, or unknown values fail closed without policy lookup or
   upstream work.
2. **Invocation rate admission.** After identity resolution and ingress
   concurrency admission, a request for a configured service can wait in FIFO
   order within `max_wait` and its absolute request deadline. It retains existing
   request slots and is charged once only when admitted to the caller's
   `(principal, service)` rolling window (see
   [operational limits](#operational-limits)). A rejection is `rate_limited`
   (429) with retry guidance and one audit record; it performs no policy,
   lookup, credential, or upstream work. Requests later denied by policy still
   count. Unknown services skip the charge and fail at the next step.
3. **Provider lookup.** An unknown service denies with `ServiceActionDenied`
   (403).
4. **Identity admission.** A broker-issued token must be of class `AgentInvoke`;
   a token of any other class is denied with `BrokerTokenClassDenied` (403). If
   `managed_store.require_registered_principal_for_invocation` is set, the
   principal must be registered.
5. **Broker-token caveats.** An `AgentInvoke` token's `allowedServices`, finite
   `allowedExecutionContexts`, and optional `serviceRestrictions` can narrow
   the service, context, action, and canonical resource set, but never create a
   grant. An absent caveat does not narrow its corresponding dimension.
   A malformed stored caveat fails closed. Action restrictions run before
   lookup or credential work; finite resources are checked after
   canonical resolution, and search authorization is intersected before the
   upstream query.
6. **Lookup-before-policy gate.** For actions that need metadata lookup to
   resolve scopes, the runtime first plans from grants matching the caller,
   service, action, and execution context. If no grant matches, it denies with
   `ScopeUnresolved` without performing any upstream lookup.
7. **Pre-scope lookup access.** When required, the runtime uses the caller's
   `per_user` credential when no service-mode grant can be viable for the
   caller/action: their token, or a lease on their OAuth connection, acquired
   here (refreshing when due) because a candidate grant exists. If a
   service-mode grant can be viable, it uses the shared
   `credentials.lookup.<service>` credential for the pre-authorization metadata
   lookup.
8. **Scope resolution.** For native search actions, the runtime builds the
   search boundary from policy and skips provider scope lookup; the provider
   receives the complete boundary (scope type and normalized resource clauses)
   as its admitted `InvocationAuthority::Search`, never the envelope's lossy
   `["*"]` summary. The matched grants stay with the broker and appear only in
   the audit record's `searchAuthorization`. For
   other actions, the provider's single `resolve_scopes` hook receives the
   action, validated inputs, host-selected execution context, minimal caller
   identity, correlation, and only the lookup access the runtime selected; it
   never receives execution authority or an execution credential. It
   returns canonical scopes and optional in-process `ProviderState`. That state
   stays with the prepared operation, which pins the provider instance, so it
   never reaches another generation's provider. Body-part admission explicitly
   keeps, replaces, or clears it; the runtime never inspects, serializes, or
   merges it. A provider whose own required state is missing or of another type
   fails closed with a `broker_provider_contract_failed` error.
9. **Deny-by-default policy selection.** The resolved scope set is authorized;
   the credential mode is selected from the surviving grant. A command import's
   action that names its resources in typed inputs is Broker-enforced and uses
   this selection. Its other actions are command-enforced: after the adapter's
   scope hook checks their inputs, the command authority planner passes the
   caller's top precedence band, each grant with its own credential mode and
   finite or all-except boundary, intersected with the agent token's resource
   restriction. It omits grants that end up empty, then grants whose
   credential mode the action does not support or whose credential is not
   locally available, never consults a lower band, and resolves no credential
   at admission. As for native selection, a grant whose selection reaches no
   enabled, context-eligible resource is not a candidate, so it never hides a
   lower band. Caller discovery uses the same planner. A Broker-enforced
   action names at most 1,000 distinct resources per call; more are invalid
   input. An import change that would leave a retained grant invalid at the
   next start is refused and names the grants to fix first.
10. **Execution-credential resolution.** The credential for the selected mode is
   loaded; for `per_user`, the method the service's credential connection
   selects for the caller's principal kind. A `per_user` operation whose scope
   resolution used the caller's token or lease keeps that same material. Final
   policy selecting `service` after a personal pre-scope lookup, static or
   delegated, is rejected as planning drift; the runtime never switches to
   service credentials.
11. **Lookup-access resolution.** If final policy selects `per_user`, any
   provider-side execution-time confirmation uses the caller's per-user
   material: the pre-scope token or lease, or else the execution token or
   lease. If final policy selects `service`, it uses the shared lookup
   credential.
12. **Admitted request.** The runtime builds one read-only, shared admitted
   context: service and action, execution context, minimal identity,
   correlation, the typed credential mode, and the exact authority from the
   action's validated contract (`ActionOnly`, `Resources` with the resolved
   canonical scopes, or `Search` with the complete boundary). Ordinary scoped
   actions never receive empty resource authority and action-only actions never
   receive resources. A provider asking for an authority its action was not
   admitted with fails closed with a `broker_provider_contract_failed` error.
   An eligible opted-in native read also receives the host's immutable
   same-mode universal-reach hint; its ordinary resource authority is unchanged.
   Multipart admission sees this context with the inputs and selected
   credentials, but no body data or decrypted private attributes.
13. **Provider invoke**, then **finalize/audit**. The final invocation is built
   only after staging: the body is consumed, the revision fences run, and only
   the admitted resource's private attributes are decrypted. Its fields are
   private and read through accessors, and it never serializes. A command
   import's call first waits, until its command deadline (the earlier of
   admission plus the command's `timeout` and the host operation deadline),
   for a slot of its command's concurrency budget, then runs these final checks
   and calls the command hook, which hands the slot to the supervisor of the
   one process it starts. A call that gets no slot fails `upstream_timeout`,
   and one that finds the budget closed by shutdown fails
   `operation_cancelled`; a write that never started a process reports
   `not_applied`.

Lookup material is never returned to the caller; the execution credential is
placed only into the `ProviderInvocation`.

## Identity model

Identity has three **modes**, two **authority modes**, and two active source
kinds.

**Modes.**

- `anonymous` — returns `IdentityContext::anonymous()` immediately, before any
  source is consulted.
- `required` / `optional` — iterate the configured sources in config order; the
  first source that returns `Resolved` wins.

When a source header was present but no source resolved, the result is `Invalid`
(401, `identity_invalid`). When no header was present at all, `optional` falls
back to anonymous and `required` returns `Required` (401, `identity_required`).

**The anonymous principal** is `{ principal: "anonymous", principal_subject:
None, groups: ["anonymous"], authenticated: false, source: None }`. It never
receives configured or managed group memberships.

**Authority modes.**

- `identity.authority = "toml"` — static principals and named groups are
  declared in the broker TOML. Policy subjects that name `user:` or `group:`
  entries must reference declared TOML principals or groups, except for the
  anonymous subject.
- `identity.authority = "managed"` — principals, groups, and group memberships
  come from the managed store. Static TOML principals and TOML groups are
  rejected.

`policy.authority = "toml"` loads service policy grants from broker TOML.
`policy.authority = "managed"` requires managed identity authority and a managed
store, rejects TOML `[[policy.grants]]`, and loads active service policy grants
from the managed store at startup and reload. Managed grant write APIs, CLI
commands, and portal editing are separate management features.

**Source kinds.**

- `static_principals` — a raw token maps to exactly one principal; the subject
  equals the principal; there is no token class, id, or scopes.
- `broker_tokens` — attempted only when the token starts with `aab_`. It yields
  `token_class`, `token_id`, and `token_scopes`; the subject is `None`.

**Per-source scheme** is `raw` or `Bearer`. For `Bearer` the value must begin
with the literal `Bearer ` before trimming; an empty resulting token is
`Invalid`.

**Group membership.** In TOML authority, `[[identity.groups]]` declares named
groups with `id`, `status`, and a static `members` list. All group IDs are
visible in management catalogs, but only `active` group memberships are used for
policy matching. In managed authority, groups are first-class managed-store
rows. Effective managed membership is the union of explicit local membership and
current Microsoft-derived membership; policy matching uses only effective
memberships whose group row has `status = "active"`. Management views retain the
source and freshness of each contribution so removing a local membership can
truthfully report that a Microsoft contribution still keeps it effective.
Membership rows can be edited for disabled managed principals, but disabled
principals cannot authenticate or exercise group-derived policy until re-enabled.

Microsoft-derived membership comes only from group object IDs in a validated ID
token. Administrators map those IDs to managed groups. Each successful Microsoft
login replaces that login method's external membership evidence with a complete
snapshot that expires after the configured finite TTL (eight hours by default);
an empty complete snapshot is valid and removes earlier Microsoft contributions.
With [membership renewal](#microsoft-membership-renewal) enabled, a refreshed ID
token can replace it too, and both writers order their evidence by Microsoft's
`iat`.
Claim overage or malformed group claims deny login rather than treating the list
as empty. A just-in-time principal is created only when at least one claimed
group maps to an active managed group.
Existing explicitly linked principals may sign in with no mapped groups and keep
any independent local membership. Microsoft group mappings never assign the
managed `admin` role.

Administrators may opt each managed group into automatic local membership for
new Microsoft users with the database-owned
`auto_enroll_new_microsoft_users` flag (default false). JIT first applies its
existing admission check, then selects all active opted-in groups and adds
ordinary local membership in the principal/login/session creation transaction.
These memberships are persistent and independent of Microsoft evidence,
including when a group has both local and Microsoft contributions. Existing
linked accounts and subsequent sign-ins do not trigger enrollment; removed
memberships are never restored automatically. Disabled groups retain the flag
and resume enrollment for future new accounts when re-enabled, with no backfill.
Concurrent group edits serialize with account creation. The creation commit is
the once-only boundary, even if later audit or cookie delivery fails.

The transaction returns the enrolled IDs for the successful login audit's
`autoEnrolledGroupIds`. Group flag changes use mandatory audit preflight plus a
supplemental `success` record under the existing group operation, with old/new
values captured in the mutation transaction. Audit is a separate store;
completion emission is not crash-atomic with the managed write, and a completion
audit failure does not undo or report failure for a committed group mutation.

### Microsoft membership renewal

`browser_auth.oidc.microsoft.membership_renewal` (default `false`) adds
on-demand renewal of Microsoft group evidence. Sign-in then also requests
`offline_access`, and its transaction upserts the login method's
`oidc_membership_renewals` record: the returned refresh token together with the
sign-in ID token's `sub`, exact `aud`, `azp`, `auth_time` and the SHA-256 of the
flow's nonce, AES-256-GCM encrypted, or an ended `not_issued` record when no
usable token came back. Requests then renew that evidence during identity
admission; nothing runs on a timer, so an idle person is never renewed. The
[operator guide](operator-guide.md#microsoft-membership-renewal) describes the
operational behavior and outcomes, and [the
store](database.md#microsoft-oidc-state-and-membership) the record.

**Hint and context.** Membership is still read synchronously under the store
mutex, so the outbound call never happens inside identity resolution or any
store transaction. Instead resolution returns a `MembershipRenewalHint`, read in
the same store call as the membership: the login method ID, its evidence
`valid_until`, the record's state, token version and `next_attempt_after`. It
exists only for an enabled `user` with an active Microsoft login method whose
record is `active`, `retrying` or `blocked`, while the provider is enabled. Ingress
middleware on the public and gateway routers gives every request a task-local
`RenewalContext`, which allows one wait per request; later admissions in the same
request make only the non-blocking checks.

**Admission.** `admit_membership_renewal` runs after resolution in
`resolve_identity_blocking` (HTTP invocation, discovery, specs and management by
token), the browser-cookie helper (portal and cookie management, session reads
and password change), HTTP MCP intake after intake resolution and before
protocol handling, and the Git gateway's Basic-token and forwarded-identity
branches. Body admission resolves identity without renewal, so the handler's
admission is the single renewal point of a request. With `ahead` a quarter of
the TTL, evidence valid for longer needs nothing; evidence inside `ahead` starts
a speculative renewal while the request proceeds; expired or absent evidence
waits once, for at most 15 seconds. After every wait, whatever its outcome, the
entry point checks the identity once more: ordinary credentials (Broker tokens,
browser sessions, Git Basic tokens) are resolved again from the same credential,
and attested identities (identity token, username bindings, forwarded Git
identity) revalidate their original proof and caller-security epoch; a new
proof is never substituted. Later revalidations in the same request, such as the
MCP pin or final admission, read the store and see the renewed evidence. This
is the one exception to discovery's read-only rule: discovery renews the
caller's own membership but never contacts upstream services or refreshes OAuth
connections.

**Flights.** A process-wide registry on the reloadable state, which survives
reloads, maps each login method to at most one in-flight renewal. A request
first joins an existing flight; only without one does it consider starting one,
which is refused during shutdown, while the provider throttle set by a 429 is
active, or before the hint's `next_attempt_after`. At most eight redemptions run
at once; a waiting flight queues for a permit until its request's deadline (at
most 256 queued), and a speculative flight starts only with a free permit. Each
flight runs in its own tracked task in the triggering request's tracing span,
so a waiter's cancellation never aborts it.

**One renewal.** After its permit, a flight rechecks the provider settings and
throttle, then starts its attempt durably in one immediate transaction
(`start_oidc_membership_renewal` through `token_store_call_from_snapshot`): the
provider enabled at the flight's configuration generation, the method active,
the principal an enabled `user`, the record not ended, `next_attempt_after`
passed, the last attempt at least 60 seconds ago and the evidence still inside
`ahead`. It records `last_attempt_at`, which nothing clears, and decrypts the
payload. An audit preflight follows; without a writable audit store Microsoft is
not contacted. The redemption posts `grant_type=refresh_token` with
`client_secret_post` and the sign-in scopes to the discovered token endpoint over
`MicrosoftOidcHttpClient`, whose token request keeps the HTTP status and
`Retry-After` even when the body fails or exceeds its bound
(`microsoft_oidc::renewal` in core). Only the status, `Retry-After`, Microsoft's
`error` and numeric `error_codes`, or the ID, refresh and access tokens of a 200
are taken from the response; the access token only checks `at_hash`. The ID
token passes the validator the sign-in callback uses (`oidc_id_token.rs`),
parameterized by a reference: the callback requires the flow's nonce, and
renewal requires the stored `sub`, exact `aud`, `azp` presence and value, an
absent or equal `auth_time` and nonce, and the login method's Broker subject.
A different `sub` or user Object ID is an identity mismatch; any other
difference is an invalid response. Classification follows the precedence in
the operator guide's outcome table.

**Ordering and fences.** The record's `observation_iat` is the highest raw `iat`
of any trusted observation by either writer. Complete groups replace the
evidence only from a strictly newer token, every trusted observation raises the
watermark, and the TTL still counts from `min(iat, now)`, so a Microsoft clock
ahead of the Broker's can neither reorder observations nor lengthen evidence.
Each outcome write, success or failure, runs in one immediate transaction
through `token_store_call_from_snapshot` and requires the snapshot to be
current, the same provider generation, tenant and client, the method active with
the same principal and subject, an enabled `user`, and the token version read at
attempt start. A failed fence writes nothing, so a sign-in, unlink, disable,
reload or configuration change during a renewal supersedes it. Once submitted,
the write runs to completion in its independent owner, and the same tracked task
appends the supplemental `oidc.membership.renewed` or
`oidc.membership.renewal_failed` record. Like other supplemental audit, that
append follows the commit and can fail without undoing it.

**Shutdown.** When drain begins, the registry stops new flights and cancels
flights that have not submitted their outcome write; they write nothing more.
After operations drain, shutdown waits within the remaining budget (at least
100 ms) for submitted writes and their audit records before the audit store
closes, and logs `oidc_membership_renewal_unfinished` with the login method and
phase of each renewal still running, since one that commits afterwards has no
audit record. Like every blocking managed-store write, each outcome write
holds its snapshot's state locks until it returns, even when runtime shutdown
drops the task waiting for it (see
[Single-node deployment contract](#single-node-deployment-contract)).

## Trusted human identity and MCP admission

`X-Agent-Access-User` selects one typed username ingress mode before ordinary
principal authentication. A direct caller uses `Authorization` and fixed context;
a relayed caller uses `X-Agent-Access-Caller-Authorization` and its fixed/asserted
context contract. Both require an explicit namespace and exact managed name
binding. This mode is invocation-only on HTTP MCP; all other routes reject the
user header. The shared human gate controls both usernames and fingerprints,
independently of token inventory, issued tokens and browser sign-in.

Each path also has its own settings: a username binding has Enabled and
Read-only, and the identity token, one record per human, has Enabled and
Read-only. A disabled binding or token resolves like an unknown name or
fingerprint. Both identity sources converge on one attested identity with
synthetic `agent_invoke` caveats for every configured context, and the admitted
path's read-only setting travels with it as `identitySource.readOnlyAccess`
(serialized into invocation audit and bound into discovery cursors, but never
into `token_scopes` or stored token caveats). One agent-invoke ceiling rule
judges each action for invocation, Git admission, caller discovery and resource
clauses: execution context, then the read-only class ceiling, then service and
action caveats. On a read-only path an action must have a runtime catalog
descriptor this host serves with `read_only = true`; a missing descriptor is a
write. The rule runs before grant selection and removes no grants, so a
permitted read selects the same grant as on a full-access path. A refusal is
`ServiceActionDenied` ("identity access is read-only") with an `identityAccess`
audit payload, before credential lookup, OAuth leasing, scope resolution or
dispatch; an unknown action on a read-only path receives the same denial. Git
push is refused at receive-pack discovery and POST before the body is parsed,
keeping the classified repository scope; the POST's unread body is only
discarded. An attested identity without valid synthetic caveats lists nothing
and is denied. HTTP MCP resolves hidden tools
through the caller-filtered registry, so a write call there is an unknown tool,
and `initialize` and `server/discover` add a read-only sentence to the server
instructions. A request is judged against the runtime snapshot it was admitted
with.

MCP carries a private identity proof from initial resolution through body
intake, session ownership and final governed admission. It pins human
incarnation/gate version, identity kind, binding ID/version or inventory
revision, the path's read-only setting, and caller security epoch. Final
admission atomically checks current managed identity state and current caller
security before credential or provider work. A changed mapping rejects the
original request; it never changes its principal. Database and caller versions
prevent disable/enable, read-only changes, pause/resume and A→B→A changes from
restoring old session authority. Every Enabled or Read-only change advances the
binding version or inventory revision, and secret rotation keeps both settings.
Username proofs do not depend on inventory revisions.

Confirmed stale proofs are removed in background cleanup and before the session
cap, without cancelling independently admitted work. Unavailable state is not
proof of staleness. A completed pause prevents later admission but does not undo
operations already admitted. See [MCP lifetime](mcp.md#trusted-identity-and-session-lifetime)
and [database invariants](database.md#managed-identity-access-and-bindings).

## Execution-context boundary

The fixed `X-Agent-Access-Context` header is a trusted ingress attribute, not a
credential or ordinary caller-controlled policy input. Broker authenticates a
named trusted caller before accepting context or identity assertions on HTTP,
MCP and Git. Each caller has fixed or asserted context capabilities and a separate
identity-forwarding permission. Header-free clients use ordinary authentication
at the same endpoint. Unauthenticated context assertions are rejected, including
when no callers are configured. See [Trusted callers](trusted-callers.md).

Every governed request resolves to one concrete safe slug. With
`[execution_context]` absent, only a missing header is accepted and resolves to
built-in `default`; a present header is rejected. A configured
`default_context` is a conservative fallback for contextless callers, including
direct clients sharing a trusted-caller endpoint. Asserted callers cannot use
that fallback, and fixed callers receive their configured value. With no direct
default, missing direct-client context fails closed. Duplicate, list-shaped, malformed, or unknown values
always fail closed. The header is reserved from identity, CSRF, and configured
HTTP client-header settings and is never forwarded upstream.

Every normalized TOML or managed grant has a nonempty finite context list.
Context intersects subject, service, action, resource scope, and credential
mode. Agent-token issuance requires a finite `allowedExecutionContexts` caveat
containing one or more effective contexts; it can only narrow this grant set.
Resolution of a stored token without this caveat still enforces current grants,
but the token does not independently restrict execution context. Stored caveats
cannot be amended. When deployment security depends on copied-token containment,
revoke tokens without this caveat and issue replacements with finite contexts.

An agent token may additionally store one `serviceRestrictions` entry per
selected service. Each entry contains an action list and optional `resources`
references to catalog entries and groups. Omission follows grants; a present
empty selection permits no resource access. Group references are live, while
the token's selected IDs remain immutable. Resource context and enabled-state
changes take effect on subsequent requests. The token boundary intersects
current policy and does not participate in grant ranking or credential selection.

The principal-scoped agent-token options projection describes effective
services, actions, resource availability, and execution contexts without
creating a grant. It also names each configured service (display name and
gateway broker hosts) and classifies each action as reviewed read-only or not;
those properties of the configured service never depend on the caller's
execution context or grants. The portal uses it for **My access > Access** and selects all current
contexts by default when opening issuance. Simple issuance omits service,
action, and resource caveats and therefore follows later policy changes inside
the selected context ceiling. Advanced issuance deliberately adds those
immutable caveats and requires an explicit review before the token is revealed.

## Policy model (deny-by-default)

`policy.default_decision` must equal `deny`. An unknown service (no provider) and
an empty candidate set both deny with `ServiceActionDenied` (403).

**Candidate grants.** Active service policy grants carry a non-empty `subjects`
list and finite non-empty `executionContexts`, and expand to one concrete
candidate per subject. Disabled managed grants
may be temporarily subjectless, but subjectless grants never enter runtime
candidate evaluation. A candidate is a grant subject that matches the identity
(`subject_rank` 2 for a user match, 1 for a group match), whose `service` and
`action` and execution context match, and whose
`resources` selection authorizes **every** resolved target. Grants are not
stitched: a single authored grant and concrete subject candidate must authorize
the service, the action, and the entire resolved scope set on its own.

**Resource matching.** Resources have typed exact, namespace, or all selectors.
GitLab REST and Git HTTP use the same canonical repository names and resource
entries. Jira uses projects, Confluence uses spaces, and CloudBees CI uses
controller-alias/full-job-name resources. CloudBees job selectors use exact,
strict descendant namespace, or all. No issue/page policy
scopes are supported. An all or namespace entry covers matching upstream objects
without catalog registration.

A grant unions its direct selections and selected groups' inclusions, retains
enabled entries permitted in the request context, and subtracts all selected
groups' exclusions. Exclusions apply even if their entry is disabled or its
contexts do not include the request context. Their effect is local to that grant;
a separate grant can authorize the target. Tokens compile the same boundaries
and intersect them with grants. See [resources.md](resources.md).

**Effective access.** Concrete-operation previews retain separate clauses
covering complete requests. Optional `excludedRequests` boundaries encode
higher-band and conflicting-mode candidates: a condition suppresses a clause
only when it covers every target of the request. This differs from the clause's
ordinary exclusions, which reject any matching target. A higher grant for A
alone must not shadow a lower grant for A and B on a request that targets both.
Search retains its action-specific planning rules. See the
[preview response contract](http-api.md) for the wire shape.

**Precedence** (`top_policy_band`). Candidates are sorted by `subject_rank`
descending, then `priority` descending (default 0), then authored grant order
ascending, then subject order within that grant ascending; only candidates at
the best `subject_rank` **and** best `priority` survive. User grants always beat
group grants before priority is considered — a higher-priority group grant never
overrides a user grant.

**Ambiguity.** If the surviving top band yields more than one distinct
`credential_mode`, the request is denied as `ServiceActionDenied` with reason
"ambiguous credential mode precedence". Static config validation independently
rejects duplicate same-subject grants and overlapping containment-scope grants
with differing modes, except lookup-backed wildcard-vs-finite overlaps that can
be resolved after authoritative metadata lookup. A command import's
command-enforced actions are exempt from both: every grant of their top band is
passed with its own credential mode, so mixed modes are not ambiguous.

Lookup-backed actions still resolve authoritative scope before this final
ambiguity check. For example, a same-precedence Jira band with a `per_user`
project wildcard and a finite `service` project grant uses the shared lookup
credential for pre-authorization metadata lookup. If the resolved project
matches both grants, final policy denies as ambiguous. If it matches only the
wildcard grant, final policy selects `per_user`, and provider-side confirmation
uses the caller's per-user credential.

**Wildcards and empty access.** An explicit `all` resource selector covers
new upstream resources. Empty selections, empty groups, disabled positive
entries, and context-ineligible entries never create unrestricted access.

### Search authorization planning

Jira and Confluence search planning compiles each eligible grant's inclusion
minus exclusion boundary before combining grants under the existing precedence
and credential rules. Project and space scopes can be finite values or all
except finite exclusions. Token restrictions intersect the result. This is not
a global subtraction across grants: another eligible grant can restore access
excluded by the first grant.

The provider constrains JQL/CQL before upstream pagination and counts and checks
returned project/space containment against the same boundary. Missing or
ambiguous containment fails closed. Audit and effective access retain symbolic
exceptions rather than describing all-except as unrestricted all.

Omitted `projects` or `spaces` use this effective authorization boundary;
explicit selections only narrow it. The query AST represents an absent caller
filter explicitly, so empty and ordering-only JQL/CQL can browse authorized
resources. Finite boundaries inject an inclusion predicate, all-except retains
an exclusion predicate, and unrestricted all adds no resource predicate. Caller
filters remain grouped and ordering follows all injected predicates.

Jira's enhanced search endpoint requires a bounded query. Empty or ordering-only
JQL therefore requires finite authorized projects, either from policy or an
explicit selection; all/all-except access requires explicit projects or a caller
filter. Confluence always retains the action's page/blog content-type predicate,
including with unrestricted all-space access. Empty text-mode queries remain
invalid. Malformed syntax, unsupported grammar, and query complexity limits use
`input_invalid` with safe syntax guidance; authorization and returned-resource
containment failures retain their existing classifications.

### Discovery filtering

Caller discovery first evaluates current policy, execution context and token
restrictions, then inspects the credentials required by each effective action and
resource region. Missing or locally unusable execution or lookup material hides
that authority from service details, action/resource lists, runtime catalog,
OpenAPI/send schemas, and native MCP tools. An unavailable winning grant still
suppresses lower-ranked grants: discovery never falls back to shared authority.
A [token-only action](#credential-model-service-per_user-lookup) is hidden in
each region whose winning `per_user` grant would use the caller's OAuth
connection, without a requirement, and stays listed for regions a `service`
grant wins.
Search actions retain their action-wide credential selection. Providers that do
not require a separate execution credential need no dummy secret.

Policy-visible services retain `availability` (`available`, `partial`,
`unavailable`, or `unknown`) and safe reason/mode/remediation requirements. An
unavailable service has no actions or resource scope metadata. Unknown local
availability also hides the affected authority. Unauthorized services remain
absent. Management, setup eligibility and policy/token previews use policy-only
metadata so absent credentials cannot prevent onboarding.

Checks read static file/environment references, personal file-store entries,
managed encrypted credentials and imported execution slots using their execution
validation rules. Managed checks do not record usage or verification. OAuth
checks the exact binding, current connection, consent/refresh blockers, scopes
and target; a locally eligible refreshable family can remain available with an
expired access token. Discovery never acquires or refreshes credential tokens or
contacts upstream services. Its identity admission may renew the caller's own
Microsoft membership ([membership renewal](#microsoft-membership-renewal)),
which is not upstream service access. Results are reused within a service's
discovery request and rechecked on the next request.

Resource-access discovery uses credential-filtered effective clauses from one
policy snapshot, reporting single-target coverage separately per action and type
and explicitly marking unscoped actions. The response includes its admitted
execution context and service credential availability. Scoped entries identify
request checks, native query/result containment, or grants delegated to a command
for enforcement; Broker does not filter that command's output. Restricted broad
selectors retain useful granted narrower entries. Registered exact references are a
separate collection; only those references are paginated or prefix-filtered.
Every page repeats the full access summary and available explicit `listingOf`
enumeration hints within that service, including multiple actions for one type.
A listing has its own grants and credentials, so its results
cannot stand in for another action's authority. The same implementation handles
native, imported, and command-backed services; it infers no scopes or listing
capabilities from action names. The summary is advisory: invocation rechecks
credentials, upstream access and all targets together. Empty singleton coverage
does not rule out an allowed compound request. Pagination binds identity, context,
policy/config state, filters, effective clauses and registered row content.
A cursor belongs to the Broker runtime that issued it and becomes invalid after
reload or restart. Multi-instance deployments need session affinity so every
page reaches the issuing instance; otherwise restart without the cursor.

The access summary is complete and unpaginated on every page. The reference
`limit` does not bound the whole response. Action and resource-type filters can
reduce its size, but even a single action is not guaranteed to fit. MCP and CLI
transport size limits fail closed rather than return partial access.
See [caller discovery](resources.md#caller-discovery) for oversized-response alternatives.

Native MCP lists are rebuilt when requested; no list-change push notification is sent,
so clients must refresh discovery or reconnect after credential changes.

CLI and the five local MCP discovery helpers share projection code over broker
capability sources. Provider descriptions and raw schemas are broker-owned;
local MCP wrapper schemas reuse the native tool projection. Full service
visibility includes separate execution surfaces, whereas native MCP execution
and augmented invoke-action detail use caller runtime catalog visibility.

### Service-scoped policy management

Managed principals hold one role and an independent self-service flag; see
[Account roles and self-service](roles.md) for the complete authorization matrix.
When identity and policy authority are both `managed`, an administrator assigns
one or more configured services directly to an account whose role is
`service_policy_manager`. A manager can inspect, create, validate, edit, enable,
disable, and delete otherwise-valid grants for those services. Only an admin
can change service assignments or move grants between services. Groups continue
to participate in invocation policy but cannot confer management authority.

A single store snapshot resolves role, principal status, self-service, and direct
service scopes for each admission. Read and write policy scopes are different
types. Auditors receive global read scopes and no write scopes. Assignments for
absent services are dormant; leaving the manager role deletes assignments,
while disabling the principal retains them. Management access does not grant
invocation access or credential access. Personal operations also require the
self-service flag, and token creation/resume, credential writes, and OAuth
connection writes recheck it transactionally.

## Credential model (service, per_user, lookup)

The execution credential **mode** comes from the matched policy grant
(`service` or `per_user`); it is never hardcoded per provider or per user. After
the mode is selected, availability checks consult the service's credential
descriptor. Services requiring execution credentials need the corresponding
`credentials.service.<svc>` or `credentials.per_user.<svc>` entry; absent material
denies with `CredentialNotProvisioned` (403). A backend explicitly declaring no
execution credential can use service mode without a dummy credential. Teams uses
this path with its admitted resource's signed endpoint.

**Credential kinds.**

- `basic_api_token` loads `username_ref` + `token_ref` for a service or lookup
  credential; a stored token of a basic-kind profile holds both.
- `bearer_token` loads `token_ref` only, or a stored token of a bearer-kind
  profile.
- The runtime and test support are the only constructors of
  `ExecutionCredential`, so each kind always carries its required material.
  Providers read it through a typed view (`Basic { username, token }` or
  `Bearer { token }`); `Debug` shows only the kind, and it never serializes.
- A provider receives `ExecutionAccess`: `None` (a backend declaring no
  execution credential), `Static`, or `Delegated`. Static and delegated material
  never coexist. Lookup material arrives separately as `LookupAccess`
  (`Static` or `Delegated`) and never stands in for execution material. The selected credential mode reaches the
  provider as the typed `CredentialMode` (`service` or `per_user` on the wire).

**`per_user` `secret_store`** (provider `local_file`) requires an authenticated
identity and matches the exact principal first, then the exact
`principal_subject`. An empty, unreadable, or invalid store fails closed
(`CredentialNotProvisioned` or `CredentialInvalid`).

**`per_user` `connection`** names a **credential connection**
(`credentials.connections.<id>`): one per-principal credential slot that
several services can consume, such as one GitLab token for GitLab REST and the
GitLab Git gateway, or one Atlassian API token for Jira and Confluence, which
declare the same `atlassian-api-token`, `atlassian-scoped-api-token` and
`atlassian-bearer-token` profiles.
The connection decides how a principal authenticates; each
consuming service's grants still decide what the principal may do. One
configuration-only function, `select(connection, principal_kind)`, returns the
method: a stored token of one of the token profiles a list accepts, the
principal's OAuth connection for the connection's `oauth` registration and
profile, or nothing. `user` principals use OAuth when the connection sets it,
and otherwise a stored token of a `token_profiles` profile; `service_account`
and `system` principals share one list, `service_account_token_profiles` when
set and otherwise `token_profiles`, so a kind change between them keeps their
token, and never use OAuth (beside `oauth`, `token_profiles` is theirs alone,
and without it they have no method). A connection without `oauth` or a list
accepts its implicit type: the one profile its consumers could accept, which
startup, reload and every imported-catalog publication resolve into the
effective connection beside the other connection checks, so `select` reads
configuration only; none, or several, fails validation. A connection whose list
has several profiles lets the saver choose one; the stored row keeps the
profile it was saved as. A configured static principal takes the kind of the active managed
principal with its ID, read once per authentication; other static principals
and anonymous callers have none. The principal kind travels on the identity
from `principals.kind` (never defaulted; unknown kinds select nothing). Selection never reads stored material, and there
is no fallback between methods. Runtime execution, both lookup phases, the Git
gateway, discovery and readiness, management, consent admission, verification,
backend validation and the command-import paths all use this one selection.
Imports with a supported, allowed personal binding publish a single-consumer
connection under the imported service ID that mirrors that binding. See
[credential connections](configuration.md#credential-connections).

Services sharing a connection must act on one upstream. Each backend or gateway
declares an `UpstreamAuthority` in its service descriptor: a normalized origin
and instance path, with an optional tenant and tenant gateway (GitLab REST the
instance of its `api_base_url`, a Git gateway its `upstream_base_url`, Jira and
Confluence their site with the cloud ID and, with a cloud ID, the Atlassian
gateway, an HTTP import its endpoint, the development `oauth_stub` service its
`base_url`). A token connection's consumers must all declare authorities naming
the same instance (`UpstreamAuthority::same_instance`): the same origin,
instance path, tenant and tenant gateway, so Jira and Confluence with different
cloud IDs never share a stored token.
An OAuth connection's registration dialect checks each consumer's authority
against the resource the registration grants through
`OAuthDialect::check_consumer_authority`, which accepts by default; the `gitlab`
dialect accepts only consumers on its registration's instance. The checks
run at offline validation, at startup and reload, and at every imported-catalog
publication, including import creation, without contacting upstream. Stored
tokens are not bound to an authority, so a later base-URL change sends them to
the new instance, as a provider base-URL change always has.

A **token** selection loads the authenticated principal's row
`(principal, connection, default)`, requires the selected list to accept the
row's stored profile, decrypts the secret with the credential encryption key
ring, and enforces metadata expiry (`CredentialExpired`) plus active status. The
provider receives the credential as the row's own profile
(`ExecutionCredential::profile()`), for execution, both lookup phases and
verification alike; a shared `credentials.service` or `credentials.lookup`
credential is received as the `profile` its entry names, if any. A row whose
profile the owner's current list does not accept is retained: kept, listed as
not used and never read, until a configuration accepts its profile again.
A profile a provider marks route-bound may be presented only by that provider:
a connection listing one cannot have a Git gateway consumer, and the Git
gateway and Git verification refuse a credential whose profile any published
service marks route-bound, or that no published service declares, before
sending anything. A missing row resolves to `CredentialNotFound` (404); a
principal for which the connection selects nothing is denied with
`CredentialNotProvisioned`.

An **OAuth** selection is a delegated credential: access the caller granted the
broker through an [OAuth connection](oauth.md), keyed by owner and
registration, so connections sharing a registration share it. It applies only
to services whose descriptor declares `CredentialDescriptor::delegated`, with a
short description of what connecting allows; management shows it under the
service's display name, so it names no service itself.
The runtime acquires the caller's current access from the OAuth manager
(refreshing it when due) inside the invocation's correlation context, and only
once a candidate grant exists: after policy admits the invocation, or for a
pre-authorization lookup the lookup plan assigns to the caller's `per_user`
credential. An invocation without a candidate grant never obtains or refreshes
upstream access. One invocation holds at most one lease: a lease acquired for
scope resolution is the one execution and its lookups use, and otherwise the
lease acquired after final policy serves execution's lookups too. The provider
receives it as `ExecutionAccess::Delegated` and `LookupAccess::Delegated`, a
lease it can read (`access()`: token, target, audience, version, expiry) and,
after an upstream 401, replace once per invocation
(`recover_after_unauthorized`), whether the 401 answered a lookup or
execution. Immediately before
dispatch the runtime revalidates the lease: access revoked, disconnected, or
awaiting new consent since preparation stops the invocation, and access
superseded by another invocation's refresh moves to the current version.
Providers never hold the OAuth manager or refresh material.

The Git gateway is the host's own delegated consumer. A gateway that allows
`per_user` declares delegated credentials; each Git HTTP request acquires the
caller's lease after policy, then revalidates it and pins it to the gateway's
own `upstream_base_url` instance and the profile's audience before every
upstream attempt, and presents it through `upstream_token_auth`. Ref discovery
recovers once from an upstream 401; pack POSTs reject the version they
presented and fail without replaying their bodies. Upstream rejection and a
connection needing reconnect answer HTTP 403 `credential_invalid` with a
plain-text message naming the portal reconnect, never 401, so Git does not
erase the Broker token from its credential helper. See
[Git gateway OAuth connections](git-http-gateway.md#oauth-connections).

**Token-only actions.** A native backend marks an action whose upstream
accepts only a token, never delegated access, with
`ActionDescriptor::token_only`; imported descriptors never carry it. The check
uses the credential mode each grant region selects, after grant precedence:
the action is ineligible only where the winning grant is `per_user` and the
caller's connection selects OAuth. A `service` region with its static
credential, and a `per_user` region whose connection selects a stored token,
keep it usable. Every selection applies the check beside the action's
supported modes: native selection, search planning, the command-enforced
planner (which omits an ineligible grant as it omits an unsupported mode) and
the discovery clauses. An ineligible winning grant still suppresses lower
grants, so there is no fallback to another region or credential. When the
pre-scope lookup plan is to use the caller's own credential, final policy can
select only `per_user`, so an ineligible action is denied before any
acquisition, refresh or lookup; without a pre-scope lookup it is denied after
policy selection and before acquisition. After a shared pre-scope lookup, a
winning ineligible `per_user` grant is denied by final policy, concealed as
`scope_unresolved` like every final-policy denial of a lookup-resolved action.
The other denials report `credential_not_provisioned`.

**Lookup credentials** (`credentials.lookup.<service>`, `read_only = true`) are
separate read-only credentials used before authorization solely to resolve
scopes when service-mode lookup-backed policy can be viable. They are never
returned to the caller. In per-user-only Jira, Confluence, and GitLab REST
policy paths, the runtime uses the caller's `per_user` execution credential (a
token or an OAuth lease) for pre-authorization metadata lookup instead of
requiring `credentials.lookup.<service>`.

Static config validation is conservative: Jira, Confluence, and GitLab REST
configs require `credentials.lookup.<service>` when any lookup-backed grant for
that service uses `credential_mode = "service"`, even if a higher-priority
`per_user` grant would shadow it for a particular caller at runtime.

Config keys for every credential kind are in
[docs/configuration.md](configuration.md).

### Private resource execution attributes

Resource-type descriptors may declare private string attributes, their labels,
requiredness, and validation. Backend configuration validates deployment-specific
constraints such as the Teams environment-origin allowlist. Exact managed entries
hold encrypted values in separate rows; public resource definitions, exports, and
discovery contain no plaintext. Admin create/patch validates attributes and commits
their material versions with resource metadata and the policy revision.

Snapshots carry versioned private bindings. After ordinary authorization, the
runtime captures the exact resource identity/type/alias and versions. Dispatch
atomically rechecks that binding, configured material, enabled state, and context
before decrypting into a nonserialized, Debug-redacted invocation field. Providers
receive only that resource's values and cannot query the store for other secrets.
Changed bindings fail rather than adopting a replacement endpoint. Rewrap preserves
logical versions, and an already dispatched request cannot be recalled. See
[resource attributes](database.md#encrypted-resource-attributes).

## Persistent storage model

The managed store is an optional SQLite database configured by
`managed_store.type = "sqlite"` and an absolute `managed_store.path`. It is
opened with foreign keys enabled, a five-second busy timeout, and WAL journaling.
`auto_migrate` defaults to `false`, requiring the current schema at startup.
When explicitly enabled, startup may initialize an empty database or apply pending
forward migrations to a recognized, supported migration-ledger prefix. Admission
verifies migration identifiers, immutable checksums, and SQLite structure. Stores
predating the supported baseline, unknown migrations, and schema drift are rejected
without modification. Reload never creates or migrates a database. See the
[schema model](database.md#schema-model) for supported versions and the
[upgrade runbook](operator-guide.md#upgrade-and-rollback) for backup and rollback.

This section summarizes the conceptual model. The table-level schema, token
hashing, credential encryption, key readiness, rewrap, and backup model are
documented in [docs/database.md](database.md).

The durable tables are:

- `principals`, `groups`, and `principal_groups` - managed identities with a
  singular role and self-service flag, first-class groups, membership,
  active/disabled state, timestamps, and creator metadata. Direct service-policy
  assignments are held separately in `service_policy_management_assignments`.
- `broker_tokens` - HMAC-hashed broker tokens, token class
  (`agent_invoke`, `user_manage`, `admin`), scopes JSON, expiry/revocation
  fields, nullable pause metadata for `agent_invoke` tokens, `last_used_at`,
  and issuer. Raw broker token values are returned only at issue
  time and are not stored.
- `rights` - scoped management rights for self-service credential operations.
  Credential rights such as `credentials:self:write` support optional
  service and credential-name bounds, expiry, revocation, issuer, and reason.
  A credential connection's rights are those on `(connection, default)`.
  OAuth does not use these rights; personal setup uses current `per_user` grants.
- `credentials` - per-user credential metadata and lifecycle fields keyed by
  `(owner_kind, owner_principal_id, service, name)`. A credential connection's
  token rows use the connection ID as `service` and `default` as `name`; rows
  the configuration does not select stay stored, unread, until deleted. Public
  API responses omit `secret_backend`, `secret_ref`, and `material_version`.
- `credential_secret_material` - encrypted secret bytes, nonce, and key id for
  the credential's `sqlite_encrypted` secret reference. It is linked one-to-one
  to `credentials` and cascades when a credential row is deleted.
- `principal_login_methods` - local-password and Microsoft OIDC authenticators
  for managed principals. Local passwords use Argon2id PHC hashes over peppered
  password digests. A Microsoft method is uniquely and immutably bound to the
  configured tenant ID plus Microsoft user object ID.
- `local_password_failures` - failed local-password verifications and lockouts
  counted per `(principal, source)`, where the source is the client IPv4
  address or IPv6 /64 prefix (IPv4-mapped and `64:ff9b::/96` NAT64 addresses
  use their embedded IPv4 address), so a lockout never blocks the user's other
  sources. Each principal keeps at most 256 per-source rows plus one overflow
  row shared by further sources, and rows of unregistered principal IDs are
  evicted first under a global row cap, so rotating sources cannot avoid
  lockout or grow the table without bound.
- `browser_sessions` - browser cookie sessions linked to existing
  `broker_tokens` rows. A browser session is represented by a `user_manage`
  broker token plus login-method metadata; the raw token is carried only in an
  HttpOnly cookie and is not returned in JSON.
- `oidc_provider_state`, `oidc_authorization_flows`, and
  `oidc_subject_flow_watermarks` - the configured Microsoft provider generation,
  encrypted single-use browser flows, and ordering guards against stale callback
  replacement.
- `external_group_bindings`, `oidc_membership_refresh_state`, and
  `external_principal_groups` - Microsoft group-to-managed-group mappings and
  finite membership evidence used to compute effective groups.
- `oidc_membership_renewals` - per Microsoft login method, the encrypted
  refresh token, renewal state, attempt and failure timestamps, and the
  `observation_iat` watermark of [membership renewal](#microsoft-membership-renewal).

The managed `credentials` table holds user-owned credentials; imported shared
execution/discovery/transport secrets use separate service-owned encrypted slots.
Identity tokens, OAuth state, and private resource attributes have their own
encrypted stores under the same key ring. Each credential
upsert validates non-secret metadata, creates a new `material_version`, encrypts
the JSON secret with AES-256-GCM, and authenticates the ciphertext with AAD that
binds the schema version, credential id, owner, service, name, profile,
credential kind, secret reference, material version, and key id. Updating a
secret preserves the `secret_ref` but replaces the ciphertext, nonce, key id,
and material version; verification updates attempt, success, status, and
sanitized failure-reason metadata only if the material version has not changed.
Successful verification sets `last_verified_at` and clears
`last_verification_error_code`; failed upstream verification sets
`verification_status = verification_failed` and `last_verification_attempt_at`
without changing `last_verified_at`. The admin rewrap operation decrypts active
credentials with one key id and rewrites their secret material under another key
without changing credential metadata or material versions.

Browser login is a human self-service entry point layered on the managed-store
model, not a replacement authorization system. It supports local passwords and
one configured, single-tenant Microsoft Entra OIDC provider. Either method
issues a browser session backed by a `user_manage` broker token. Admin-set local
passwords are temporary by default: a session with `passwordChangeRequired =
true` may only inspect session state, log out, or change the password.

Principal kind is a security boundary. A `user` may have login methods, browser
sessions, management tokens, and an admin role. A `service_account` is a
noninteractive workload identity: administrators manage it, and it may own
groups, grants, credentials, and `agent_invoke` tokens, but it cannot have a
local password or Microsoft login, start a browser session, receive an admin
role, or receive `user_manage`/`admin` tokens. These checks live in managed-store
issuance and resolution, so a stale login or management-token row cannot become
usable after a principal is changed to `service_account`.

Cookie-authenticated browser sessions may call read-only discovery,
self-service credential/token management, and own-record audit query routes
after that requirement is cleared; state-changing self-service calls require
CSRF protection. Browser sessions for active principals with DB role `admin`
may change broker state; sessions for `admin` or `auditor` may read administrative
metadata and safe previews. Sessions with current service policy
management scope may call the policy and admin audit query routes for assigned
services. Management calls other than `GET` reads require CSRF, including the
read-only `POST` previews, validation, verification and reveal. Browser sessions
cannot invoke provider actions directly. A request is a browser session only when
the sign-in cookie authenticated it: an issued `user_manage` token never gains the
session's administration, browser-only OAuth routes, CSRF check or forced password
change, whatever its identity source.

Microsoft login uses authorization code flow with PKCE and nonce verification.
The broker persists encrypted, expiring authorization-flow state, binds it to a
separate HttpOnly browser cookie, and claims it once before completing the code
exchange; replay, mismatched state/cookie, and stale callbacks fail closed. ID
token validation pins the configured tenant, client audience, issuer, signature,
nonce, and immutable `tid` plus `oid` identity. Email, preferred username, and
display name are attributes only: they never identify or merge a principal and
only initialize a newly created principal's profile. The broker does not query
Microsoft Graph.

An administrator can link a principal directly to a Microsoft user object ID or
unlink that method. Otherwise, a first successful login creates a principal only
when at least one claimed Microsoft group has an active mapping to an active
managed group. An existing binding may log in with a complete empty or unmapped
group list. Successful callbacks atomically refresh Microsoft-derived group
evidence for the configured finite TTL, unless a renewal already stored evidence
from a newer token, and create the browser session. The
resulting effective groups combine current Microsoft evidence with explicit
local memberships; neither an external mapping nor an OIDC login method grants
the managed `admin` role.

Microsoft discovery and key refresh are provider-scoped. If Microsoft is
unavailable, the session endpoint reports that login option unavailable and OIDC
login fails without making the broker globally unready or disabling local login.
Broker logout revokes only the broker browser session; it does not perform a
Microsoft federated logout.

The first-use path can be fully database-backed. When
`management.initial_admin.mode = "create_if_empty"` and the managed store has no
principals, startup creates the configured `user` principal, grants DB role
`admin`, and creates a local-password login method that must be changed on first
login. Once any principal exists, that bootstrap path no longer mutates the
store.

Local passwords and Microsoft bindings are independent authenticators on one
principal. Microsoft linking does not convert a local account, and JIT starts
with only a Microsoft method. Admin reset requires an active local method;
creating or re-enabling one requires the explicit enable operation and
acknowledgment of a separate Broker sign-in path. Reset cannot silently add or
reactivate local sign-in. Self-service requires the current local password and
an active local method, regardless of the method used by the current session.
A self-service change preserves a current Microsoft session; a local session
is replaced after the change. Sign-in method summaries expose only method
states, independently of principal disablement or source lockouts.

Local password reset or disable revokes existing browser sessions for that
principal and login method. The password pepper is loaded from
`browser_auth.local_password.pepper_ref`, and the CSRF key used to derive
per-session CSRF tokens is loaded from `browser_auth.csrf_key_ref`; neither key
is stored in SQLite. Microsoft client and flow-encryption secrets are likewise
loaded through secret references rather than stored in the managed database.

Lifecycle is stateful rather than append-only. Principals are disabled and
re-enabled in place. Owners and administrators may manually pause and resume
`agent_invoke` tokens without changing their secret, caveats, expiry, or
dynamically resolved grants; invocation checks pause state before policy or
upstream work.
Effective token state is derived in the order Revoked, Expired, Paused, Active.
Pause is reversible and does not protect a disclosed secret, while revocation
is permanent and wins concurrent transitions. A request admitted before pause
commits may finish; the next admission is denied. Broker tokens and rights are
revoked by setting `revoked_at`/`revoked_by` and are also checked for expiry at
use time. Credential
deletion removes the credential row and its encrypted material through the
foreign-key cascade. The store does not automatically prune expired or revoked
tokens or remove paused tokens, expired rights, disabled principals, or expired
credentials; those
records remain visible to management APIs until a management path changes or
deletes them.

Agent-token boundaries are immutable as well as lifecycle-independent. Pause
and resume preserve them exactly, and revocation remains terminal. There is no
boundary patch operation: issue a replacement token when its service, action,
resource, context, or expiry ceiling must change.

The managed store is not the audit log. Invocation, management, and reload audit
records are written through the audit store configured by `[audit]` (`type` and
`path`): a standalone SQLite audit database or size-rotated JSONL files. The
managed store has no audit or event table, and `audit.path` must not name the
managed-store database. Audit retention applies only to the audit store, while
the managed store keeps only operational state needed for identity, token
admission, management rights, and managed credentials.

## Audit and redaction model

The broker writes one redacted `AuditRecord` per outcome to the audit store
configured by `[audit]`. The record is camelCase and carries: `auditId`,
`nodeId`, `timestamp`, `agentRequestId`, `brokerRequestId`,
`configGeneration`, `policyGeneration`, `principal`, `principalSubject`,
`groups`, `service`, `action`, `resourceScopes`, `matchedGrant`,
`credentialMode` (`Option<Option<String>>`: `service`/`per_user` on allow, null
for admin records), `credentialConnection` (the credential connection a personal
credential came from; present when the selected mode is `per_user`, when a
command call passes a `per_user` grant even though mixed modes leave
`credentialMode` null, or when a pre-authorization lookup used the caller's
token or OAuth lease, even if policy then denies the call with no credential
mode; absent when only service credentials are used or for management and
authentication records), `decision`, `reasonCode`, `upstreamStatus`,
`upstreamDurationMs`, `objectIds`, `identitySource`, optional `callerId`, `source`,
`executionContext`, `searchAuthorization` (search actions), `auditInputs`, and
`providerAudit`. When present, `matchedGrant` carries `subject`, `priority`,
`resources` (the grant's resource selection), `executionContexts`, and optional
grant metadata. TOML-backed grants include `configIndex`; managed-store grants
include `grantId` and `grantVersion`; all runtime-selected grants include the
`policyGeneration` for the snapshot used by the authorization decision. Search
records carry every grant of the matched band in
`searchAuthorization.matchedGrants`.

`callerId`, when present, names the authenticated trusted caller. It is separate
from the end principal and `identitySource`; an ordinary Broker token retains its
own token provenance. It never contains caller credentials or credential digests.
Username source name/kind is `trusted_user`, with `tokenHeader: "x-agent-access-user"`,
`tokenScheme: "asserted"`, invocation class, namespace and opaque binding ID.
Its token ID is absent. Raw failed usernames and private identity proofs never
appear in audit or ordinary traces.

**Record identity.** The audit writer assigns `auditId`, a UUIDv7 unique to the
record, and `nodeId`, the broker's effective node ID (`deployment.node_id`, or
the host name when unset), when it accepts a record for writing, not where the
record is built. Records of one request (a stream or gateway started record and
its terminal record, a management or auth preflight record and its outcome, and a
path-changing reload's records in the new and the old store) share
`brokerRequestId` but each has its own `auditId`. Together the two fields keep
records from several brokers distinguishable and safe to de-duplicate. Both
storage backends hold the same JSON: a SQLite row stores the record exactly as
the JSONL backend writes the line.

`auditInputs` lists the supplied values of the inputs an invocation's action
opts into audit (`ActionDescriptor::audit_input` for native providers, a command
action's `audit` list for command imports), in declaration order. Each entry has
`input`, `label` and `value`. A string longer than 1 KiB, or any other value
whose compact JSON is, is cut to 1 KiB as a string and marked `truncated: true`.
Integers beyond 2^53 are kept exact as decimal strings. The runtime captures
them once the action is resolved, so every later record of the request carries
them, including both records of a stream and owned interruption records;
records written earlier, such as rate-limit, body and identity rejections, have
none. The field is absent when there are no values.

`identitySource` carries name, type, header, scheme, plus `tokenClass` and
`tokenId`; attested identities add `readOnlyAccess`. Portal sign-in sessions
record name `browser-session`, type `broker_tokens`, header `Cookie` and scheme
`cookie`. `token_scopes` is `serde(skip)` and is never serialized into audit; raw
token values are never logged.

**Outcome records.** Normal operations write one record per outcome. An allow is
recorded at status 200; a deny or error is recorded at its reason's HTTP
status: a standard reason's fixed status or a domain reason's declared one. Identity failures are recorded with
`principal = "unknown"`. A failed `auth.local.login` records the submitted
principal ID only when it passes the principal key check; otherwise `principal`
is `anonymous`, `providerAudit.auth.claimedPrincipalInvalid` is `true`, and the
submitted value is not recorded. Mandatory audit admission is **fail-closed**,
whichever backend is configured: a required preflight append failure returns
`audit_unavailable` before mutation. A failure after an irreversible commit
must preserve the actual outcome rather than invite a retry. Password change
and authenticated logout persist `providerAudit.auth.phase = "preflight"` before
the store change and then append `phase = "success"`. If that supplemental
completion append fails, the successful response and normal replacement/cleared
cookie are preserved, the sink fault affects readiness, and a correlated
`auth_committed_write_audit_append_failed` event reports the missing completion.
Logout storage failure returns a sanitized error and leaves the cookie intact.
Streamed downloads append a started record before the response is returned and a
terminal record after the stream completes, fails, is dropped, or is canceled by
shutdown.

Credentialed gateway forwarding also uses paired audit records. A started record
with `decision = allow` and `providerAudit.gateway.phase = "started"` is
durably appended before upstream credentials are sent. The terminal record is
queued through reserved terminal-audit capacity and carries the upstream status,
duration, and gateway response-byte metadata. Audit consumers that count
completed gateway operations must distinguish the started phase from terminal
records. Matched-host classifier denials use synthetic
`action = "gateway.classify"`; that action is not policy-grantable and exists
only to classify pre-auth gateway denials.

**Management records.** Every management call is audited, including denials and
failures, except successful read-only operations. A successful plain read of
data the caller may see (no secret material returned, no upstream call, no
state change) writes no audit record and no replacement log event: session,
token, credential, and OAuth connection reads, status reads, principal, group,
right, token, and credential lists and inspections, policy status, catalog,
grant, resource, and service-manager reads, the effective-access and grant
validation dry runs, and audit queries. Auditing them would add records for
every portal page load and refresh, and because audit is fail-closed these
reads would stop working exactly when audit writes fail. The broker keeps one
explicit list of these operations, consulted by the shared success path, so
every other operation, including a new route, is audited until it is classified.
Some reads stay audited when they succeed: secret reveals
(`admin.principals.identity_token.reveal`,
`admin.policy.resources.attribute.reveal`), the whole-policy export
(`admin.policy.grants.export`), credential verification, which sends stored
secrets upstream (`credentials.verify`, `admin.credentials.verify`), and the
OAuth callback, which completes a connection. Denied and failed reads are
audited like other management errors, and mutations, logins, logouts, password
changes, OIDC, configuration reloads, and invocations are audited as before.
[http-api.md](http-api.md#management-audit) lists the unaudited operations.

Resource and resource-group create, update, and delete operations retain a
mandatory management preflight and append a supplemental `success` record after
the managed change commits and its policy is published. Their mutation owner
continues through completion emission after a client disconnect. The managed
transaction captures an allowlisted before/after snapshot, recorded names,
entity versions, policy revisions, and actual included/excluded membership
deltas. Private resource attributes and raw mutation bodies never enter this
projection. Bounded labels and member lists expose truncation flags and full
counts; see the
[change-record contract](http-api.md#resource-and-resource-group-change-records).

An allowed preflight is evidence of an attempt, not proof of mutation success.
Completion append failure preserves a committed HTTP success and emits the
correlated `management_committed_write_audit_append_failed` diagnostic. The
managed store and audit store commit separately; a process crash between them
can leave only preflight evidence. There is no transactional outbox or eventual
delivery guarantee for this supplemental record.

Portal labels remain historical; authorized catalog readers can follow them to
current objects at the ID. The existing audit JSON and full-text projection
accommodate these safe labels without a database migration or visibility change.

Audit storage I/O is isolated behind a dedicated writer thread, one per runtime
generation; writers for the same path in one process are serialized. Async
request handlers, stream polling, and stream `Drop` paths enqueue work and never
perform blocking audit storage calls directly. Normal audit appends wait for
writer acknowledgement and report writer errors, queue pressure, or enqueue
timeout. Mandatory preflights fail closed before dispatch or store mutation;
supplemental completion failures cannot undo a committed authentication or
resource-catalog change. Supervised JSON invocations probe audit readiness and reserve terminal
capacity before preparation/provider dispatch; their reserved append also waits
for acknowledgement. If finalization fails after execution, the error preserves
safe completion evidence and explicitly denies retry safety. Streaming responses
and credentialed gateway forwarding reserve terminal-audit queue capacity before the started audit record is accepted, so
terminal records have bounded writer capacity even when shutdown begins.
After preparation and before provider dispatch, command downloads also reserve
a dedicated stream-start audit slot. That reservation spans command-budget
waiting, process execution and response validation through acknowledgement of
the required started record; the terminal reservation stays with delivery. The
internal start pool equals the effective `audit.terminal_queue_capacity`, and
the writer channel includes its capacity alongside ordinary and terminal work.
Ordinary `audit.queue_capacity` covers queued work through acknowledgement and
is not held through command execution.
`audit.durability` controls whether records are ordinary page-cache-only writes,
`sync_data`, or `sync_all`; `write` is not crash-durable across an OS or host
failure. For JSONL the sync modes sync each record and also make rotation and
retained-file deletion metadata durable; for SQLite `write` maps to
`synchronous = NORMAL` and the sync modes to `synchronous = FULL`, which syncs
each batch commit.

**Redaction of the pre-authorization path.** On the lookup-before-policy path,
`redact_error_resource_scopes` empties the response envelope's `resourceScopes`
and normalizes the error to `ScopeUnresolved` (except input, locator, and
credential reason codes, and the delegated lease's own consent-pending,
refresh-busy and throttled-refresh failures, which describe the caller's OAuth
connection), while the audit record still records the real resolved
`resourceScopes`. Secrets never enter audit: `ExecutionCredential` and
`EgressProxyConfig` `Debug` impls redact, and only `tokenId` and `tokenClass`
appear in `identitySource`.

### Audit storage backends

`audit.type` selects one backend for the process; changing it requires a
restart. Only the storage step differs per backend: writing records, the health
probe, and retention. Queueing, acknowledgement, terminal capacity, and shutdown
drain are shared.

- **`jsonl`** appends one line per record to `audit.path`, rotates it to
  `<path>.<UTC timestamp>Z.<uuid>` at `rotate_bytes`, and at most once an hour
  deletes rotated files whose modification time is older than
  `retention_days`. Retention matches only that rotated-file name pattern, so
  it never deletes the state lock file or other files sharing the prefix. JSONL
  is not queryable; use it when a log shipper consumes the files.
- **`sqlite`** writes a standalone SQLite database at `audit.path`, separate
  from the managed store, with its own migration ledger and a random
  `database_id` fixed at creation. Startup creates and migrates it; reload never
  does. Each record is stored as its JSON plus derived query columns and a
  contentless full-text index entry. The writer commits batches of at most 256
  records and 16 MiB of prepared data (record JSON plus full-text text) in one
  transaction and acknowledges each record only after the commit that contains
  it. A record whose prepared size exceeds 16 MiB fails only its own append and
  logs `audit_record_too_large`; nothing is truncated. Retention deletes
  expired rows in slices of at most 2,000, followed by optional full-text merge,
  incremental vacuum, `PRAGMA optimize`, and a passive WAL checkpoint, each run
  as a bounded slice only when no audit work is queued. Optional slice failures
  are logged as `audit_maintenance_failed` and reported by admin
  `config.status`; they never affect readiness. The table-level schema is in
  [docs/database.md](database.md#audit-database).

**Writer health.** The writer records each failure class separately (append,
terminal write, JSONL rotation, retention prune, probe, and the sticky writer
exit) and readiness fails while any class is recorded. For JSONL, a successful
append clears append and terminal-write failures (and a rotation failure when
it rotates), a successful prune clears a prune failure, and a successful probe
clears every class except writer exit. For SQLite, a probe with nothing
recorded checks only file permissions, file identity, and the open connection,
and writes nothing. With a failure recorded, probes and successful commits
trigger a recovery attempt, at most once a second, and only the evidence for a
class clears it: append and terminal-write failures clear after a transaction
that re-inserts the largest failed batch inside a rolled-back savepoint and
then commits and syncs padding of the same size; a prune failure clears after
its delete slice succeeds on retry. A failed recovery attempt leaves the
recorded classes unchanged, and probes between attempts fail, so supervised
invocations are not dispatched. Failed records are never committed later,
because their requests have already failed.

### Audit queries

With `audit.type = "sqlite"` and management enabled, the audit store is also
queryable through `/v1/admin/audit/*` (admins, auditors, and service policy managers) and
`/v1/audit/*` (managed users with self-service enabled, for their own records), the matching
`agent-access admin audit` and `agent-access audit` commands, and the portal's
Audit and Activity pages. Each tier applies one visibility predicate inside
every query, and filters cannot widen it:

- global admins and auditors see every record;
- service policy managers see records whose scope service is one of the
  services they manage at the time of the request. A record's scope service is
  its `service`, except that `broker` records use
  `providerAudit.management.targetService` when present. Management
  admission rejections also use `broker` and have no scope service. The broker sets
  `targetService` on policy management that names a service or grant and on
  admin operations (`admin.*`) whose target names a service, such as manager
  assignments and service-limit overrides, or a credential connection with a
  single consuming service. Connection records list every consumer in
  `targetServices`; a change to a connection several services share has no
  scope service. Records
  without a scope service, such as users' own token, credential, and login
  activity, are never visible to this tier;
- managed users see records whose `principal` is their own, including records
  made with their agent tokens, whatever the scope service.

Agent-invoke tokens can use neither route family. Queries run on a
per-generation pool of read-only connections separate from the writer
connection, with bounded admission and a per-query deadline; in WAL mode they do
not block audit writes, although a long read can defer a WAL checkpoint.
Paging uses opaque cursors that carry the first request's normalized filters
and absolute time bounds and are bound to the route, the caller, and the audit
`database_id`; visibility is resolved again on every page. JSONL backends and
disabled audit leave the routes out of the runtime catalog, OpenAPI, and send
schema. The route contract is in [docs/http-api.md](http-api.md#audit-queries).

### Source and proxy-chain derivation

`SourceResolver` derives the audit `source` from the peer socket by default. A
single `Forwarded` header (else a single `X-Forwarded-For`) is consulted only
when the immediate peer matches a configured `trusted_proxies` entry, walking the
chain from the rightmost untrusted address. An untrusted peer ignores forwarded
headers and leaves `proxyChain` empty. Config validation rejects trusting all
proxies (`"*"` or a `/0` CIDR) in every environment.

## Observability and correlation

The production service observability surface is structured JSON tracing plus the
audit store. Only `agent-access-broker serve` installs the JSON subscriber;
CLI validation commands keep their human command-line output. The default
service filter is
`agent_access_broker=info,agent_access_broker_host=info,agent_access_core=info,agent_access_provider=info,axum=warn,tower=warn`, and
`RUST_LOG` can override it without adding broker config keys.

Every public and gateway HTTP request receives an `http.request` span. The span
carries the broker's `nodeId` and uses the listener label `public` or
`gateway`, method, matched route template when available, sanitized fixed
paths for health/readiness, peer address for TCP requests, request IDs,
service/action or operation, principal, decision, reason code, HTTP status, and
duration as they become known. Query strings are never
logged. Routes with caller-controlled values such as service, action, principal,
credential, token, group identifiers, or gateway repository paths use route
templates or sanitized fixed paths and omit the concrete path. HTTP config
reload/status events use `listener = "public"`; Unix `SIGUSR2` reload events use
`listener = "signal"`.

Stable structured events are emitted for startup/listener/shutdown, invokes,
stream start/terminal state, gateway forwarding, reload admission/outcome, audit
append failures, audit writer and maintenance problems, audit query failures
(`audit_query_failed`), ingress rate/concurrency rejections
(`request_limited`), and upstream HTTP outcomes. The `broker_listening`,
`config_reload_completed`, audit writer, and audit query failure events carry
`nodeId`.
Event fields use camelCase for broker concepts and dotted HTTP names such as
`http.statusCode` where that matches common tracing conventions. Events never
log upstream credentials, broker identity tokens, authorization headers,
cookies, request/response bodies, raw scope values, query strings, filenames, or
sensitive concrete path values. Confluence draft audit metadata also excludes
raw draft handles, page/blog body content, caller-supplied title mismatch
values, attachment filenames, attachment content hashes, and raw download URLs.

Native rich bodies, review summaries, patches, native line codes,
`renderedBody` values, whole-result Markdown, arbitrary comment-property
values, and pagination tokens are likewise excluded from
audit, tracing, logs, errors, and object identifiers. Audit may record bounded
format names, byte counts, and stable conversion outcomes without receiving the
rendered string.

The correlation model is the same pair of IDs used by envelopes and audit:
`agentRequestId` from the validated `X-Agent-Access-Request-Id` header and the
broker-generated `brokerRequestId`. `ProviderInvocation` carries those IDs in a
non-serialized correlation context. Broker-owned upstream Jira, Confluence, GitLab REST, and
CloudBees CI requests add `X-Agent-Access-Request-Id` and
`X-Agent-Access-Broker-Request-Id` after caller headers and before provider
authentication/signing. These headers belong to the host transport rather than
provider input; the broker writes the validated correlation values before
dispatch.

`InternalDiagnosticCode` is a closed, log-only classification for bounded
operator diagnostics. When present it is emitted as `diagnosticCode` only on
the terminal `invoke_completed` event, or on `audit_append_failed` when the
mandatory audit append prevents that completion event. It is correlated by the
same request-ID pair. The code is never serialized into a `ResponseEnvelope`,
provider result, HTTP header, request span, or durable audit record. Diagnostic
codes classify a parser or protocol stage without logging the rejected body,
locator, position values, credential, or other sensitive source data.

Jira, Confluence, and GitLab rich-content writes use a fixed security pipeline: validate
the closed input shape, explicit action-specific format, source type, source
structure, and source byte limit; validate native input or convert
Markdown/plain text under bounded parser and output budgets; append attribution
in the provider-native representation where that action already supports it;
validate the complete native document; enforce the final serialized native-body
byte limit; then submit upstream. Confluence normalized input targets a strict,
allowlisted storage-HTML subset and never trusts raw Markdown HTML. GitLab
Markdown stays native, while plain text is escaped so CommonMark and
GitLab-specific syntax remains literal. Neither
conversion nor limit enforcement truncates content. Oversized source or final
rich-content writes return
`body_size_denied` (HTTP 413), while an unsupported action/format pair returns
`body_format_unsupported` (HTTP 415).
GitLab additionally rejects deterministic command-like quick-action lines
outside fenced code and suggestion blocks before any rich-content write, so
ordinary prose cannot trigger hidden provider mutations or be stripped on
submission while fenced examples remain literal content.

GitLab review mutations add a readback proof step and are never retried
automatically. If the upstream write may have applied but the expected draft,
discussion, publication, or reviewer state cannot be proven, the broker returns
HTTP 409 with `decision = error`, `mutation_verification_failed`, a closed safe
locator result, and `retrySafe = false`. Callers refresh that state before
deciding whether another mutation is needed. Direct and single-item review
mutations treat an upstream 5xx after the request as applied-unverified.
After such an uncertain failure, or a redirect, publish-all and review-submit
re-read the owner-draft snapshot and reviewer state; they may return an
ordinary sanitized upstream failure only when that readback proves the
operation made no change, and otherwise use the 409 contract. A definitive
GitLab rejection of the mutation request (a 4xx or throttling) keeps its
ordinary error without a receipt or readback.

For `merge_request.draft_note.publish`, verified success specifically requires
and returns the exact resulting `discussionId` and `noteId`. If publication may
have applied but bounded readback cannot identify exactly one new note matching
the acting actor, normalized body, and semantic position, the response uses
`mutationStatus = "applied_unverified"`,
`verificationStage = "published_note_readback"`, and `retrySafe = false`;
initially only the original draft ID is safe to expose. The broker never guesses
the published locators and the caller must refresh rather than automatically
retry.

When content attribution is enabled, provider body-write paths append a visible
broker-owned footer after conversion and before final native validation and
upstream serialization. The footer uses the broker-generated
`brokerRequestId` as its human `Request ID`, and audit records redacted
attribution metadata without logging source, converted, or mutation-readback
body text. Attribution is part of the final body sent upstream, so provider
body byte caps are enforced after dedupe and append.

There is intentionally no `/metrics` route, metrics exporter, metrics config, or
metrics dependency in this surface. A later metrics design should decide the
listener, format, authentication model, and cardinality policy.

## Operational limits

`LimitsConfig` defaults; `upload_spool_dir` is required and has none:

| Limit | Default |
| --- | --- |
| `invocations.default` | 100 requests per `1m`, `max_wait = "0s"` (built in) |
| `auth_requests_per_principal_per_minute` | 100 |
| `auth_requests_per_source_per_minute` | 300 |
| `max_concurrent_requests` | 100 |
| `max_concurrent_requests_per_principal` | 10 |
| `max_http_body_bytes` | 536870912 (512 MiB) |
| `max_download_bytes` | 104857600 (100 MiB) |
| `max_upstream_response_bytes` | 536870912 (512 MiB) |
| `request_timeout_ms` | 30000 |
| `request_body_timeout_ms` | 300000 (five-minute receive deadline) |
| `streaming_idle_timeout_ms` | 30000 |
| `upload_spool_dir` | none (required) |
| `upload_spool_max_bytes` | 2147483648 (2 GiB = `max_http_body_bytes` × 4) |

**Service invocation limits.** Each principal's use of each backend service
is rate limited independently of transport admission and authentication budgets. Every `(principal, service)` pair
has one rolling window of at most `requests` admitted requests per `window`,
resolved on each admission from the principal's override (TOML
`principal_overrides` or the managed store, by identity authority), then
`[limits.invocations.services.<service>]`, then `[limits.invocations].default`,
then the built-in 100 per `1m`. Counted requests are `POST /v1/invoke` in every
IO form, HTTP MCP action tool calls, and Git gateway pack POSTs, each charged
once at admission. Every pack POST counts, including protocol v2 `ls-refs`
POSTs, additional fetch negotiation rounds, and a push's probe POST, so one Git
fetch or clone typically costs two or more and gateway limits need room for
that (a limit of 1 without waiting prevents v2 fetches). Discovery, specs, `/v1/me`,
management, MCP protocol messages, and Git ref discovery (`GET .../info/refs`)
are not counted. Service invocation limits are not keyed on the source address, because many
principals commonly share one (for example behind a shared ingress proxy).

The window is 60 sub-buckets of `window / 60`, each counted until its last
admitted request leaves the trailing window. It never admits more than
`requests` in any trailing window, is conservative by at most `window / 60`,
records only admitted requests, and keeps memory per key independent of
`requests`. Idle keys are pruned by an amortized sweep; there is no global key
capacity that could reject other principals. History survives reloads and resets
for a key only when its window length changes. Managed override changes reforecast
pending requests without extending deadlines. Actual runtime publication cancels
pending admission; already-admitted operations keep their snapshot semantics.
Global administrators
manage managed-store overrides through
`/v1/admin/principals/{principal}/service-limits`, which reports each configured
service's effective limit and whether an override supplies it; callers see
their own effective limits, without that distinction, as `/v1/me`
`serviceLimits`, filtered to the services `/v1/services` would show them.

`max_wait` resolves from the service, then default, then zero independently of
principal rate overrides. Positive waiting uses one FIFO queue per principal and
service across tokens/transports, before policy or credential work. REST and Git
wait before body parsing; HTTP MCP has already parsed its protocol message.
Forecasts honor conservative bucket history and accepted waiters. Rate capacity
must be due within the configured wait; timer latency may delay processing that
opportunity, while actual body/operation deadlines remain strict. HTTP MCP keeps
one absolute operation deadline across waiting and execution.

Waiters retain existing global/per-principal request and MCP response slots.
There is no new queue-count setting or aggregate service quota. Observed pending
cancellation, abandonment, runtime publication or shutdown removes the ticket
without a charge or dispatch; admission that wins the race keeps its charge.
The original identity is revalidated after admission without remapping it.
Detected connection loss affects pending admission only; unread bodies or proxies
can delay detection, so a client timeout may leave a request queued or executing.
Tracked admission owners retain terminal audit responsibility even after response
abandonment, transferring it to normal invocation ownership only on handoff.

Single-service detail adds caller-specific [live limits](http-api.md#live-service-limits)
through HTTP, CLI and existing MCP describe. Observation never changes limiter
state. REST detail has an independent bounded control pool with the configured
request caps; HTTP MCP keeps its existing control pool. Other lists/specs remain
static, anonymous detail omits limits, and no upstream quota is probed.

A rejection is HTTP 429 `rate_limited` with a complete message, a
`Retry-After` header, and the reserved `broker/request.admit` envelope without
a `result`. The correlated tuple establishes nonapplication; see
[trusted callers](trusted-callers.md#http-failures-before-provider-dispatch).
Other broker errors with `result.retryAfterSeconds` also carry `Retry-After`. The rejected
request's audit record carries `providerAudit.rateLimit`, and the
`request_limited` event carries the same detail plus the broker token ID. Retry
timing honors accepted waiters, and queue deadline expiry uses the same 429
contract. Proven pre-admission cancellation instead uses the original action's
`operation_cancelled`, `executionState: "not_dispatched"`, `retrySafe: true`.
A hard deadline already elapsed before grant or queue insertion retains the
surface timeout (REST 400 `body_malformed`, Git 400 `gateway_request_body_denied`,
HTTP MCP `operation_timeout` with Broker status 504), with the same host proof and
`deadlineKind` (`body` or `operation`) in result/audit; Git exposes its proof through audit.
Native HTTP MCP retains HTTP 200 JSON-RPC tool-error delivery.
This outcome is consistent before, during and just after initial settings
resolution; an infeasible future FIFO turn or queued expiry still uses 429.
Ordinary final audit/service events include bounded admission wait and outcome
metadata; successful waiting creates no rejection record.

**Authentication budgets.** Login, password changes, OIDC, unauthenticated
calls, invalid-session traffic, and anonymous access use independent
fixed 60-second authentication counters and the
`auth_requests_per_*_per_minute` settings. The source budget keys on the same
grouped source as local-password lockout (full IPv4 address, IPv6 /64 prefix,
embedded IPv4 for IPv4-mapped and NAT64 addresses), and the local-login
principal budget on `(principal, source)`. Ordinary control-plane routes check
identity before body extraction, charging anonymous/invalid identities once per
request. Verified identities remain exempt except for password login/change.
Authenticated API, browser, discovery, spec, and management traffic does not
consume authentication budgets. Global and
per-principal concurrency protection applies to every caller. All rate state is
local to the broker process; reloads retain it.

**HTTP bodies.** Global concurrency admission precedes body extraction; handlers
and supervised operations share the same lease. Health/readiness probes and
bodiless portal assets bypass this lease; HTTP MCP and single-service detail
use their independent bounded pools. Anonymous control-plane body reads are
limited to a quarter of global capacity (minimum one) and a source slot; verified
management identities instead use a separate per-principal body pool until
extraction finishes, capped by `max_concurrent_requests_per_principal`. Bodiless writes skip body
slots, keeping owner pause/revoke available during body saturation. Browser-auth bodies
have a 16 KiB cap and five-second receive ceiling; other control-plane bodies
allow 1 MiB, except authenticated imported-document uploads, which allow 4 MiB.
Anonymous uploads retain the 1 MiB cap. All non-authentication control-plane
bodies, including uploads, have a fifteen-second total receive ceiling. A smaller
configured receive deadline still applies.
Invocation JSON and streamed files retain the configured transfer cap, while
multipart JSON metadata is capped at 1 MiB. Invocation and Git bodies use the
total `request_body_timeout_ms` deadline; public idle timing uses the global
streaming setting and Git uses its matched gateway setting. An admitted
invocation or Git pack POST answered with its body unread, such as an upload
refused after its metadata or a push refused after its command prefix, lingers
on its HTTP/1.1 connection: one of the server's connection tasks discards the
rest without parsing or forwarding it, stopping once 8 MiB have been read (the
received frame that crosses 8 MiB is read whole), after five seconds, or at the
invocation transfer cap or body deadline, so the client can finish sending and
read the response instead of meeting a reset. A body still held when the
response is ready, such as a pack an upstream request that answered early or
failed is still sending, is awaited within the same deadline and discarded
once that holder drops it unfinished; one that ends while held releases the
wait at once. The task holds the request's global and per-principal
concurrency permits until it ends, never past that deadline; graceful shutdown
waits for it and forced shutdown cancels it. A remainder beyond those bounds,
or a body that already failed, still closes the connection unread. Refusals
before admission never read the body. HTTP MCP retains its independent intake admission.
Local-password hashes run outside the managed
SQLite mutex with two login/change jobs and one reserved administrative job per
store, plus a fresh account/password-state check before commit.

**Raw downloads.** `max_download_bytes` bounds every raw download the Broker
delivers, whatever bound the provider applies. Providers reject a declared
length over their cap and stop reading upstream past it; the host independently
counts the bytes of each provider stream as it delivers them, without buffering.
The chunk that would take the body past the limit is not delivered: the stream
fails there with `attachment_size_denied`, the reason the SDK's bounded downloads
report for this limit, and stops reading the provider's stream. An in-memory body
over the limit fails before its first byte. The failure is a late stream failure:
the committed 200 response ends without completing its body, and the stream's
terminal audit record is `failed` with `decision = error`, the reason, and the
delivered byte count and digest. The CLI and stdio MCP report such a download as
failed and leave an existing destination unchanged.

Accepted command actions with `download: true` use the same raw transport after
the adapter validates a complete base64 JSON response and decodes it in memory.
An explicit per-command `max_download_bytes` enables this capability and bounds
decoded bytes; the derived envelope cap must also fit the global upstream limit.
The shared command budget spans the process and response worker within the
original deadline, then releases before delivery. Independently owned command
invocations retain shutdown visibility if their HTTP waiter disconnects.
Global/principal request permits remain held through the response body and each
yielded byte owner, bounding retained files even if a chunk outlives the body.
The common host path caps the complete encoded metadata header at 16,384 bytes,
returns JSON on refusal and cancels the unused stream. These transport rules also
apply to native downloads. See [command download bounds](command-imports.md#download-bounds)
and [HTTP negotiation](http-api.md#raw-download-negotiation).

All numeric limits must be non-zero; invocation limits accept 1 to 1,000,000
requests and windows from `1s` to `1d`.

Git HTTP gateway transfers use `request_timeout_ms` for upstream connection
liveness and `streaming_idle_timeout_ms` for stalled request uploads, upstream
response header waits, and response body streaming. Inbound packs also have the
total `request_body_timeout_ms` receive deadline. Outbound pack responses remain
bounded by idle timeout, byte caps, rate limits, and concurrency limits rather
than a total download deadline.

**Cross-section consistency.** Per-provider `attachments.max_total_bytes` and
`attachments.max_bytes` must not exceed `limits.max_http_body_bytes` (with
`max_bytes <= max_total_bytes`); `attachments.max_download_bytes` must not exceed
`limits.max_download_bytes`; and an HTTP route's `max_response_body_bytes` must
not exceed `limits.max_upstream_response_bytes`.

**Audit limits.** `[audit]` is optional (absent means audit is disabled); when
present, `type` (`sqlite` or `jsonl`) and `path` are required. `rotate_bytes`
is valid only for `jsonl` and defaults to 104857600 (100 MiB) there;
`retention_days` defaults to 30; `queue_capacity` defaults to 1024;
`terminal_queue_capacity` defaults to `limits.max_concurrent_requests`;
`enqueue_timeout_ms` defaults to 1000; and `durability` defaults to `write`.
Numeric audit limits must be non-zero, and an explicit terminal queue capacity
must be at least `limits.max_concurrent_requests` when audit is enabled. The full limits and
audit config tables are in [docs/configuration.md](configuration.md).

### Single-node deployment contract

Local-state broker deployments are single-node. Rate and concurrency buckets,
audit writes (JSONL append/rotation or the SQLite audit database's single
writer connection), upload-spool byte accounting, and the SQLite managed store
are local to one broker process.

Before `serve` binds the public listener, the broker creates or validates
broker-owned local state directories, derives canonical lock
identities, and acquires non-blocking exclusive advisory locks for every
configured managed store, the configured audit path (JSONL file or SQLite audit
database), and the upload spool directory. Lock identity is based on canonical
local paths, not config string spelling, and stale unlocked lock files left by
dead processes are reused. Lock holder metadata includes the holding
executable's assembly name and version and the node ID; lock file names never
depend on the executable, so differently named executables still exclude each
other on one state set. The
offline `agent-access-broker audit verify` command takes the same audit lock,
so it runs only while no broker owns that database.

Two broker processes may run on the same host only when their managed-store,
audit, and upload-spool lock sets are disjoint. Sharing any one of those
paths fails closed at startup or reload admission. The lock files are local
guardrails for this deployment contract, not a distributed consensus mechanism
or an active-active clustering design.

Dynamic reload preserves the same ownership model. Candidate state locks are
acquired before candidate runtime state is opened or probed. Unchanged lock
targets reuse the active generation's handles; old snapshots retain their lock
handles until in-flight requests that cloned those snapshots complete.

The host runs its blocking managed-store calls with the state locks of the
snapshot whose store they use, held until the call returns. This covers
token-store, policy and import mutations, management calls, local password
sign-in and change, browser-session revocation, Microsoft sign-in flow records,
and identity resolution, which records a broker token's last use. The blocking
worker owns its own reference to those locks, so a request that a reload has
left on an older snapshot keeps that snapshot's locks, and Tokio shutdown cannot
release them by dropping the request or the task waiting for the call. No other
process can take the state while such a write may still run.

## Egress proxy model

Resolution precedence is exactly:

1. `NO_PROXY` / `no_proxy` match → **Direct**.
2. Environment proxy for the upstream scheme (`HTTPS_PROXY` / `HTTP_PROXY`) →
   **Environment**.
3. Per-provider or per-service `egress_proxy` block → **Service**.
4. Global `network.egress_proxy` → **Global**.
5. Otherwise → **Direct**.

Environment proxy variables are snapshotted once at startup; `HTTPS_PROXY` and
`NO_PROXY` prefer the uppercase variant, while `http_proxy` resolution prefers
the lowercase variant over `HTTP_PROXY`. TOML proxy blocks reload with config.

Proxy URLs are origins only: `http`/`https`, a required host, no path beyond `/`,
no query, no fragment, and no embedded userinfo. `username_ref` and
`password_ref` must both be present together and be `env:` or `file:` refs. An
`http` (non-`https`) proxy URL combined with either credential ref is rejected.

The egress proxy is applied to Jira, Confluence, GitLab REST, CloudBees CI, attachment
streaming, Git HTTP gateways, and the
`api.atlassian.com` gateway.
The audit `egressProxy` value records the mode plus a sanitized origin.

Core owns route selection. Every client a provider, import adapter or the OAuth
manager uses comes from a client factory that core constructs for one caller
category and runtime generation: the host's OAuth manager, a particular native
registration together with its development-only marker, or an import adapter.
A client's label or provider identity never changes its category. A client
declares either ordinary routing (the precedence above, with its configured
service proxy) or a request for a direct route to a literal IPv4/IPv6 loopback
base URL. Core grants that request only to OAuth clients and to development-only
native registrations the deployment enables (`deployment.enable_fake_service`
outside production), and only for a literal loopback IP address; it fails the
client's construction otherwise. Production native providers and shipped import
adapters therefore use ordinary proxy and `NO_PROXY` selection even for loopback
destinations, and host names such as `localhost` never receive the exception.
Startup preflights every configured proxy, including credential references,
even when a captured environment proxy would take precedence.

## Outbound TLS trust

`network.outbound_tls` selects `system` (the default), `custom`, or
`system_plus_custom` for every Broker-owned HTTPS client. Custom modes require
one PEM bundle; system mode forbids a bundle. The core prepares an immutable
Rustls client configuration during runtime construction and gives Reqwest that
preconfigured backend. Parsed roots and the verifier are shared across clients;
Reqwest's TLS builder options and implicit root selection are bypassed. The core
owns the ring crypto provider, safe TLS 1.2/1.3 defaults, chain and hostname
verification, and HTTP/1.1 ALPN. Cargo feature unification cannot add WebPKI
or native roots to the selected policy. Provider request and streaming clients, Git gateway
clients created later, and Microsoft OIDC all use the same runtime snapshot.
HTTPS egress proxies share that client trust. CLI-to-Broker TLS remains configured
by the CLI's separate `service.tls` block.

Trust loading and client construction must succeed before a candidate can be
published. A reload refreshes root material even when the configured path is
unchanged; a failed candidate preserves the active roots. Request paths never
read certificate files. See [configuration](configuration.md#networkoutbound_tls)
for the native-store and custom-bundle contracts.

## Dynamic config reload

Two triggers run the same reload admission path:

- `POST /v1/admin/config/reload` on the public admin-management API.
- On Unix, the `SIGUSR2` signal (`SignalKind::user_defined2`), via
  `reload_from_signal` — suitable for systemd `ExecReload`. The signal task is a
  no-op on non-Unix platforms.

HTTP reload and status use normal admin-management identity, authorization,
CSRF, response-envelope, and audit rules. Managed admin tokens and browser
sessions require the managed store; explicit classless static TOML admin
identities can use config reload/status without a managed store only when that
bootstrap/recovery mode is explicitly enabled. The reload/status request and
response shapes are in [docs/http-api.md](http-api.md).

Reload is atomic and execution-context admission is generation-coherent with
the candidate runtime snapshot. Removing a value still referenced by an active
TOML or managed grant rejects the candidate. Disabled or deleted managed grants
do not block reload; they remain visible with stale contexts and cannot be
enabled until repaired. Token caveats do not block reload either: a token bound
only to a retired value becomes stale and unusable. Removing
`[execution_context]` after active grants use explicit contexts is not a
rollback path.

The audit backend and node identity are fixed for the process. Reload rejects a
change of `audit.type` (including adding or removing `[audit]`) or of the
effective node ID with `config_admission_failed`; those changes require a
restart. A new `audit.path` with the same type is opened and validated before
activation, and the reload record is written to the new store (required) and
the old store (best effort). Reload never creates or migrates a SQLite audit
database, so a new SQLite path must name a current database that a broker
startup created. Other `[audit]` settings apply to the new generation's writer.
Audit queries use the reader pool of the generation that admitted the request.

## Process shutdown

On `SIGTERM` or `SIGINT`, the broker enters a single graceful shutdown path. The
public listener stops accepting new connections, in-flight HTTP work drains
within `--shutdown-timeout-ms`, and `SIGUSR2` reload handling exits. Pending rate
admission closes at drain start: no further rate grants occur, queued tickets
are removed without dispatch, and tracked admission owners finalize before the
audit writer closes. Already-admitted operation draining is unchanged. If listener
drain exceeds the timeout, open streaming downloads are marked canceled so their
writer-backed terminal audit records are queued when the stream wrappers drop,
and the connections still open are cut off: each listener cancels its connection
tasks and waits for them to end. The audit writer registry then receives the
remaining shutdown budget to drain and join its writer threads; terminal audit
durability after a forced timeout is best-effort if that final writer drain also
expires.
The JSON-operation supervisor preserves operation admission for requests already
rate-admitted before shutdown while the listeners drain, including requests still
reading their bodies.
It closes operation admission after listener drain, or when the shutdown budget
reaches its reserved final phase (the final quarter, capped at one second). That
phase bounds forced-stop unknown-outcome finalization without extending the hard
shutdown deadline. Disconnected operations
remain tracked and keep permits until finalization; shutdown does not overlook
them merely because their response connection disappeared. Command-import
processes can outlive their operation, so after operation draining the shared
command registry closes: a call that reaches its command afterwards fails
without starting a process, every live process supervisor is asked to kill its
process group and leader, and shutdown waits within the remaining budget (at
least 100 ms) until each has reaped its process and returned its concurrency
permit, reporting those that have not. Microsoft
[membership renewals](#microsoft-membership-renewal) stop starting when drain
begins; shutdown then waits within the remaining budget (at least 100 ms) for
submitted renewal writes and their audit records, logging each one that does
not finish. The audit writer shuts
down after that. Unfinished finalization is reported explicitly;
process kill, host loss, or unavailable audit storage cannot be made durable by
an in-memory supervisor.

HTTP MCP sessions outlive the connections that use them, and each holds the
broker state. Once the listeners have ended, so in-flight MCP responses have been
delivered or cut off, shutdown closes every session still open within the
remaining budget (at least 100 ms), before it waits for operations; a close that
does not finish is logged as `mcp_session_shutdown_unfinished`. Closing a
session never cancels an admitted operation. An MCP response body holds only its
capacity lease and delivery deadline, never a runtime generation, so a response
a client has not read cannot keep that generation or its state locks alive.

Startup rejects a zero shutdown timeout or a timeout above 300 seconds, and
admin config status reports the active `shutdownTimeoutMs`.

## Security posture

- **Agent egress boundary.** The intended deployment path is agent-to-broker and
  broker-to-upstream. Direct agent egress to protected upstreams is outside the
  normal brokered path and should be treated as a migration or break-glass
  exception by deployment policy.
- **Redirects.** All three providers follow redirects manually, limited to
  allowlisted hosts, and drop upstream auth on cross-origin hops. Atlassian
  attachment downloads present it only within the route's site (the tenant host,
  or the configured cloud ID's gateway path) and refuse a redirect to another
  site on the same origin. Both Atlassian providers reject redirect responses on
  non-content (body) endpoints.
- **Atlassian routes.** Each Jira/Confluence credential takes the route its
  token type selects: classic API tokens the tenant host; scoped API tokens,
  bearer tokens and OAuth the Atlassian gateway, which requires
  `providers.<svc>.cloud_id` (validated UUID). Unknown profiles, profile/kind
  mismatches and an unavailable gateway are refused before anything is sent,
  and validation requires the allowlist to cover each configured credential's
  route.
- **Query languages.** Provider-supplied JQL and CQL are parsed into broker-owned
  ASTs and re-emitted canonically with broker-injected scope predicates. Results
  are revalidated against the authorized scope, and no partial results are
  returned — a single result outside the authorized scope fails the whole
  response.
- **Credential boundary.** The execution credential, or the delegated
  credential lease, lives only inside the `ProviderInvocation`, never in a
  response and never in audit.

The security rationale and direct-token comparison are in
[docs/security-model.md](security-model.md). Per-provider details are in
[docs/providers.md](providers.md).

## GitLab downstream credential issuance

The [bot provisioning contract](gitlab-bot-provisioning.md) adds project-scoped
identity/token operations to the existing provider runtime. Execution
credentials remain Broker-held. Newly issued credentials are deliberate secret
outputs, annotated in runtime specs and omitted from metadata reads and audit.
Their subsequent direct use is governed by GitLab, independently of Broker grants.

## Delegated upstream connections

[The OAuth foundation](oauth.md) adds browser-owned connection consent and
on-demand versioned token leases beneath typed per-user actions. Refresh
material remains encrypted in the managed store, outside invocation tokens and
agent containers. Production integrations include Google for Gmail, GitLab for
GitLab REST and GitLab Git gateways sharing one connection per instance,
Atlassian for Jira and Confluence through the Atlassian gateway, and approved
imported MCP OAuth registrations. An independent development-only test provider
exercises collection resources and lifecycle fault recovery.

Personal OAuth setup requires self-service, a credential connection that selects
OAuth for the owner, and a matching active `per_user` action grant on a service
that uses it, for the owner or their current groups. Resource and
execution-context availability and invocation precedence do not govern setup;
invocation still evaluates them independently. Existing bound connections remain
inspectable and locally disconnectable after grant loss.

Core's OAuth manager owns consent flows, credential encryption, refresh
coordination, refresh fences and retry budgets. Consent start, claim and install
resolve the current runtime and check the exact service/registration/profile
binding. Managed grants and current effective membership are read within the
slot transaction, using the same setup predicate as TOML-backed runtime policy.
A denied matching flow is retired without clearing the previous connection's
revalidation requirements. Credential rights do not participate in OAuth.

The wire protocol of one family of authorization servers is an `OAuthDialect`
from the backend contract crate:
it validates registrations, lists the URLs a registration may reach, builds
authorization URLs, names the callback issuer, and performs code exchange,
refresh, identity and target discovery, sending each request at most once and
classifying failures. The manager's fences rely on that classification: a
dialect reports a retry-after, permission, or request rejection only when the
authorization server guarantees the grant was not consumed. Dialects register
with the binary through the backend registry, like backends; core registers
none of its own, and this binary selects `google`, `gitlab`, `atlassian`,
`mcp_oauth` and the development-only `stub` dialect from `agent-access-fake`. Dialect requests go through an
`UpstreamClient` with OAuth's own bounds (15 seconds total, 5 seconds to
connect), the registration's allowlist, and upstream traces. The manager
builds them through its host OAuth client factory, one client per approved
destination origin, so egress proxy resolution is independent for each origin;
only literal loopback IP destinations connect directly, without affecting other
hosts. Host names, including `localhost`, never receive that exception. The manager
validates every grant's bounds, scopes and targets regardless of dialect.

The Gmail backend is a separately linked provider crate. Its Google OAuth dialect
declares reusable refresh material; the shared manager retains recovery budgets,
persistence and fences. Delegated invocations retain their original connection
across renewal. See [Gmail](providers-gmail.md) and [OAuth](oauth.md).

The GitLab backend crate also exports the `gitlab` dialect. Its registrations
target one instance, whose normalized base is the profile `target`, with the
audience `gitlab`, so a consumer pins its lease to its own instance. Its refresh
material is consuming, and each grant supersedes earlier access. Code exchange
reads granted scopes from the token response, or else from the new token's info
before returning the grant; refresh takes them from the response, or else keeps
the consent evidence the manager supplies, without another request.

The `atlassian` dialect lives in `agent-access-atlassian`, beside the helpers
Jira and Confluence share. Its fixed endpoints are Atlassian's authorization
server and the Atlassian gateway. A registration's one profile targets a site's
cloud ID with the audience `api.atlassian.com`, and its consumer check accepts
only services that act through the gateway on that cloud ID (Jira and
Confluence configured with it), so Jira and Confluence pin their leases to the
cloud ID their gateway route uses; route-coverage validation checks that their
allowlists reach the gateway. Its
refresh material is consuming and rotates the refresh token. Granted scopes come
only from token responses: an exchange without them fails, and a refresh without
them keeps the consent evidence. Target discovery merges the per-product entries
`accessible-resources` lists for one site into one target and adds the granted
account-level `read:me`, so the manager's whole-profile eligibility check sees
the site with both products' scopes.
