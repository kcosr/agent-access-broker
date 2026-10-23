# Agent Access Broker Agent Notes

This repository implements the Agent Access Broker service and CLI. The implemented
architecture and conceptual contract live in `docs/design.md`.

## What This Repo Is

Agent Access Broker is a Rust service and CLI for giving AI agents
scoped, audited access to service APIs without putting upstream service
credentials in the agent environment. The broker owns identity, policy,
credential selection, provider request validation, bounded transfer handling,
audit emission, and structured service observability; the CLI discovers broker
actions and exposes typed wrappers for supported services.

## Ground Rules

- Keep repository documentation focused on implemented behavior: current
  architecture, supported interfaces, operational runbooks, and contributor
  instructions. Capture implemented content in those references before moving
  historical proposals, research, review correspondence, or dated validation
  evidence to a plain folder outside the repository. Do not link shipped docs
  to that external material. Describe accepted fields, flags, headers, and current
  defaults directly; keep removed-interface lists and transition history in the
  changelog or external historical notes. Retain supported schema admission,
  upgrade, and rollback instructions as operational contracts.
- Describe proxy integration through the generic trusted-caller and client-address
  contracts. Keep product-specific deployment notes and cross-repository harnesses
  outside the public repository. Preserve the canonical wire headers, including
  `X-AW-Identity-Token-SHA256`; generic wording does not rename supported APIs.
- Use synthetic people, project names, and reserved example hosts in examples.
  Keep site-specific paths, server names, credentials, and build-service overrides
  in local configuration outside the repository. Preserve explicitly identified
  test-only cryptographic fixtures and required license notices.
- Do not add backward-compatibility aliases, bridge routes, or dual-shape config
  parsers unless a migration is explicitly requested.
- Keep generated HTML out of git; Markdown is canonical. The hand-authored
  `docs/system-overview.html` presentation is the one tracked exception: keep it
  consistent with the Markdown docs when the behavior it describes changes.
- Keep sample configs in sync with the config schema and tests.
- Stored credential rows, their AAD inputs, the `basic_api_token`/`bearer_token`
  and profile spellings, and persisted import JSON are durable data contracts.
  Core golden tests freeze rows written by an earlier release; never regenerate
  them to make a refactor pass.
- Update `README.md` for user-facing behavior, config, or workflow changes.
- Service policy grants use the canonical plural `subjects` field everywhere;
  do not reintroduce singular grant `subject` config, API, CLI JSON, or store
  shapes unless an approved interface change explicitly changes the contract.
- Grants and token resource restrictions reference typed resource entries and
  resource groups. Do not restore freeform policy scope strings, Jira issue or
  Confluence page scopes, or generic HTTP services. Group exclusions apply
  across selections within one grant/token boundary, including when their
  resource entry is disabled or context-ineligible; they are not global denies.
  Resource types may opt out with `supportsExclusions: false`: validate every
  excluded group membership at catalog validation and publication, including
  unused groups. Never silently drop an unsupported exclusion. Imported-type
  acceptance rechecks group blockers transactionally against the candidate
  registry; retained declarations keep their accepted capability.
- Runtime specs are part of the supported interface. When changing broker
  actions, typed CLI commands, `agent-access invoke`, JSON `send`, or HTTP
  routes, keep the caller-filtered catalog, OpenAPI projection, send schema,
  docs, and agent-facing skills in sync. Typed CLI commands may be ergonomic
  wrappers, but they must still map cleanly to canonical catalog actions.
- Keep action descriptions and input schemas concise for initial MCP discovery.
  Put extended grammar, limits, and examples in action `documentation`; preserve
  its detail/catalog/OpenAPI/send projections and keep it out of `tools/list`.
  MCP describe hints use stable service/action IDs, never client-renamed names.
- Caller discovery and native MCP lists expose only authority with locally usable
  selected execution and lookup credentials. Preserve grant precedence and hide
  unknown availability too. Discovery must not contact upstream services,
  refresh OAuth connections, or record credential use/verification. Identity
  admission may renew the caller's own Microsoft membership (see
  `docs/design.md`). Keep management and setup previews independent so missing
  credentials cannot prevent onboarding.
- Token-only actions (`ActionDescriptor::token_only`, native only) are checked
  with the mode each grant region's winning grant selects, beside the action's
  supported modes: refuse them only where `per_user` selects OAuth, with no
  fallback to lower grants, and before acquiring or looking up with the
  caller's OAuth access.
- Native searches declare `native_search` as `UpstreamConstrained` or
  `ResultFiltered` and receive normalized clause authority. Reuse SDK selector
  matching, union/intersection and coverage; never flatten grant exclusions.
  Query-constrained exact-only providers use strict `exact_projection()` and
  treat namespaces as contract errors. Result-filtered providers discard denied
  candidates before any release. Imports always declare no native search mode;
  command enforcement is core-owned and preserves its exact-only wire format
  and per-grant credential modes.
- Universal-reach hints are opt-in, disclosure-only metadata for ordinary
  scoped native reads. Prove complete same-mode coverage from the admitted
  snapshot after precedence, ceilings and token restrictions; never widen
  source authority or make linked-resource requests from that hint. Jira uses
  it only for embedded links in `issue.view`; absence is distinct from `[]`.
- Backend invocation context comes from the host-authorized execution context,
  never a tool input. Seal resumable provider cursors with the SDK continuation
  envelope, bound to that context and current principal/resource/query settings
  and to the execution material's method (a static kind, or the delegated
  binding, never the access version); reauthorize every continuation.
- Backend actions default to `read_only = false`; explicitly opt reviewed reads
  in via `ActionDescriptor::read_only()`. Runtime/discovery/management `readOnly`
  classifies upstream effects for grant selection; it does not gate local output.
  It is also the ceiling of read-only trusted-identity paths, checked against the
  current catalog on every request, so reclassifying a native action changes what
  those paths can do: call out every native reclassification in `CHANGELOG.md`.
  JSON and multipart-upload responses support local output, including writes.
  Do not infer read-only status from action names or presentation support, expand
  result limits, or forward local output paths to broker invoke requests. Report
  confirmed operation success separately from local output failure; never replay
  an operation to retry saving its response. Reserve response/metadata destinations
  before provider dispatch, including downloads, and preserve unverified mutation
  outcomes in compact receipts without exposing catalog-marked secrets.
  `--output` is a destination and
  `--output-format` is representation; preserve dedicated raw-download actions
  and receipt metadata.
- When making changes, audit whether `README.md`, `docs/`, `skills/`, sample
  configs, `CHANGELOG.md`, and this `AGENTS.md` need updates. Update them in
  the same change when behavior, commands, config, architecture, security
  posture, provider semantics, operational workflows, or repository layout
  changes.

## Managed access

`docs/roles.md` defines exclusive account roles and independent self-service.
Keep `PolicyReadScope` and `PolicyWriteScope` distinct. Auditors may read admin
metadata and safe previews but never mutate, reveal secrets, verify credentials,
or run import discovery. Service policy managers are assigned directly to
accounts, never groups. Use the shared store authority resolver for admission;
keep invocation authorization independent from personal self-service gates.
Personal OAuth setup uses active direct/group `per_user` grants and an approved
binding, not credential rights. Keep authoritative consent checks on current
runtime policy and transactional membership; preserve owner cleanup after grant
loss and the separate classless static credential-right path. Every end of an
OAuth family (disconnect, replacing consent, uncertain refresh, principal
disable) fences locally first and keeps the family for remote revocation in the
same transaction when the dialect revokes; a remote failure never restores
access, and `revoked` is reported only when no unknown successor can exist. A
late successor joins its family's revocation whenever its refresh reports,
even after another process presumed it lost; each token keeps its own retry
deadline.

Microsoft group auto-enrollment adds local membership only in the new JIT
principal's creation transaction after mapped-group admission; preserve the
disabled-group pause, no-backfill/no-re-add semantics, and transaction-captured
enrollment and setting-change audit details.

## Microsoft membership renewal

`membership_renewal` keeps one encrypted Microsoft refresh-token record per
Microsoft login method (`managed_store/oidc_membership_renewal.rs`, migration
`031`). The record, its AAD inputs and its payload are durable contracts: it
stays in key readiness, the used-key inventory and rewrap (which keeps its token
version), and its golden vector freezes the stored row format; never
regenerate it. While a record exists, sign-in and renewal order evidence by
Microsoft's raw `iat` against `observation_iat`: only a strictly newer complete
claim replaces evidence, and every trusted observation, complete or not, raises
the watermark. Every outcome write, success or failure, runs through
`token_store_call_from_snapshot` with the full fence (current snapshot, provider
generation, tenant, client, active method and subject, enabled user, token
version) and writes nothing when it fails. Renew only at request admission
(`membership_renewal.rs` in the host) for the caller's own identity, never under
the store mutex or inside a store transaction, at most one wait per request,
with a post-wait identity check that revalidates attested proofs rather than
replacing them. Renewal never creates a principal, so group auto-enrollment
never runs for it; a JIT sign-in records its row in the transaction that creates
and enrolls the account. Failures never extend evidence. Refresh, ID and access tokens,
response bodies and `error_description` never reach logs, audit, errors or API
responses.

## Build Service

Rust/Cargo commands work locally with the checked-in `rust-toolchain.toml` and
`Cargo.lock`. The reproducible tested toolchain is Rust/Cargo 1.98.1 with rustfmt
and Clippy. The tested portal toolchain is Node.js 24.18.0 and npm 11.16.0; these
versions do not establish a minimum supported version.

The remote build service is optional. When it is configured and available, use
it to offload Rust/Cargo work; it copies formatted sources plus debug/release
artifacts back according to `.build-service/config.toml`. Set
`BUILD_SERVICE_ENDPOINT` in the local environment; machine-specific values do
not belong in tracked files. For example:

```bash
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" build-cli build cargo -- test --locked
```

Apply the same wrapper to the local Cargo commands below when using the service.
If it cannot be used, run Cargo locally and record the build mode in validation
results. After any Cargo command creates build artifacts in a retained worktree,
run `cargo clean` through the same build mode before returning a parked clean
result.

The production provenance verifier builds locally by default. Its explicit
`--build-service` option forwards `AGENT_ACCESS_BUILD_COMMIT`,
`AGENT_ACCESS_BUILD_PROVENANCE`, and `AGENT_ACCESS_REQUIRE_BUILD_PROVENANCE`
through `build-cli --env`. A remote service must allowlist all three names.

## Fast Bootstrap

1. Format: `cargo fmt`
2. Test: `cargo test --locked`
3. Build: `cargo build --locked`
4. Lint: `cargo clippy --locked --all-targets --all-features -- -D warnings`
5. Validate broker config: `cargo run --locked -p agent-access-broker -- --config agent-access-broker.sample.toml config validate`
6. Validate CLI config: `cargo run --locked -p agent-access -- --config agent-access.sample.toml config validate`

## Development

Run these before submitting changes:

```bash
cargo fmt --check
cargo test --locked
cargo build --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
node scripts/check-crate-boundaries.mjs
node scripts/public-api.mjs check
node scripts/check-changelog.mjs
```

Every workspace crate declares `[package.metadata.agent-access] role` (`sdk`,
`core`, `host`, `assembly`, `cli`, `native`, `reference`, `adapter`, or
`helper`); declare one when adding a crate. The boundary check rejects an
undeclared role and dependency edges that cross the roles, such as any
production path from core or the host to a backend or import adapter, and any
use of the host-only items (the SDK's `host::authorize_host_request` and
`host::token_as_basic`, and core's `gateway_upstream_authorization`) in native,
adapter, reference or helper sources. See `docs/testing.md` for the rules.

`api/` holds the checked-in supported public API inventory: the SDK and host
with and without `test-support`, the assembly library, the reviewed selection
entry points of linked native and adapter crates (`SELECTION_ENTRY_POINTS` in
`scripts/public-api.mjs`), and the types their signatures expose. The public API
check fails when the candidate's API differs. For an intended change, run
`node scripts/public-api.mjs update`, review the diff against the rules in
`api/README.md`, and commit it with the change. The check needs the
`nightly-2026-07-13` toolchain and `cargo-public-api` 0.52.0; set
`AGENT_ACCESS_PUBLIC_API_RUSTUP_HOME` when the nightly is in another rustup home.

Supported SDK types follow the construction policy in `api/README.md`: build
them through constructors and builders (`const` ones for statics), keep new
data types non-exhaustive or private-field, and make extendable enums
non-exhaustive. Matches on them end with a fallback arm that fails closed,
never treating an unsupported variant as success or as another variant. Record
any intentionally exhaustive shape in its rustdoc and in that list.

Use these for offline config validation:

```bash
cargo run --locked -p agent-access-broker -- --config agent-access-broker.sample.toml config validate
cargo run --locked -p agent-access-broker -- --config agent-access-broker.production.sample.toml config validate
cargo run --locked -p agent-access -- --config agent-access.sample.toml config validate
```

On Unix, also run the isolated real-signal parent fixture explicitly:

```bash
cargo test --locked -p agent-access-broker-host --lib lifecycle::tests::unix_signal_smoke_in_isolated_child_processes -- --ignored --exact
```

It requires no live credentials and starts its own guarded child fixtures; do
not run the ignored child directly or use a broad `-- --ignored`. Record it as
not applicable on non-Unix platforms. See `docs/testing.md` for the full suite.

Tests outside the host, including the CLI smokes, start in-process brokers
only through the host's `test-support` feature: `test_support::IsolatedBroker`
runs the assembly's `composition()` and `build_identity()` on a real
configuration file through the production startup, reload and drain, and
`ProviderFixture` serves stub providers for configured native kinds. The host exports no router or
reload state and the assembly library exports only those two functions, so do
not add a raw construction path for tests. Host unit tests under
`crates/agent-access-broker-host/src/tests/` may use the crate's internals.

The fake-provider vertical smoke is included in `cargo test`; it starts an
isolated broker and invokes it through the real `agent-access` binary.

The Jira read smoke is also included in `cargo test`; it serves a stubbed Jira
backend as a provider fixture and drives typed `agent-access jira issue
view/search`, live project listing, project issue-type discovery and its create workflow, and issue
comment commands.
The ignored `real_jira_smoke` test is only for a live broker that has already
been configured with real Jira credentials.

The ignored `real_gitlab_smoke` binary is likewise only for a configured live
broker. Its read test is exact-filtered; its inline/reply and draft/review tests
also require the documented confirmation sentinels and an explicitly throwaway
MR/source branch. Never run that binary with a broad `-- --ignored`; use only
the individually named exact commands in `docs/testing.md`.

The GitLab REST smoke is included in `cargo test`; it serves a stubbed GitLab
backend as a provider fixture and drives typed `agent-access gitlab` read,
mutation, repository, and CI commands.

The CloudBees CI smoke is included in `cargo test`; it runs an isolated
broker against a stubbed controller and drives typed and JSON-send downloads,
stdio MCP output, bounded reads, build triggers, redirect rejection,
and audit checks through the real `agent-access` binary.

The command import smoke (`command_import_smoke.rs`) is included in `cargo
test`; it imports the reference command through the real `agent-access`
binary and needs `python3`, whose absence fails it.

## Layout

- `crates/agent-access-provider`: the backend contract: service descriptors,
  resource types, the `Provider` trait and its invocation/result/error types,
  reason codes and the hook contract the host checks provider failures, late
  streams and upstream traces against (`contract.rs`), the OAuth dialect and
  delegated-credential contracts, credential presentation
  (`authorization.rs`: `UpstreamAuthorization` and `CredentialPlacement`) and
  the host services backends use (upstream HTTP clients built through the
  host's client factory, egress declarations and sanitized routes, upstream
  allowlists, correlation, upstream trace events, token signing and
  continuation envelopes), and the upstream authority a descriptor declares
  for credential connections (`authority.rs`: `UpstreamAuthority`, checked
  against OAuth registrations by `OAuthDialect::check_consumer_authority`).
  Static credentials and delegated access have no plaintext accessor, and
  providers never hold a request carrying one: they
  hand an `UpstreamAuthorization` to the send method (`UpstreamCall`,
  `RedirectRules`, or a per-hop `RedirectAuthorizer`), and the client adds the
  sensitive header to the request it builds, along a redirect chain only within
  its authorized path. Only the host's raw-client paths (Git gateway, Git verification) use
  the host-only `host::authorize_host_request` and the host-only
  `host::token_as_basic` placement, which presents a token as HTTP Basic; the
  boundary check rejects both in native, adapter, reference and helper crates.
  Credential equality exists only with `test-support`, in constant time. `lib.rs`
  lists every supported export explicitly, one path per item; never add a
  wildcard re-export. Presentation items are reachable only through
  `presentation`. The supported `host` module holds the host cooperation ports:
  the client factory contract and `build_context`, the constructors of
  host-owned request values (scope requests, static credentials, admitted
  requests, spooled body parts, final invocations), the initial correlation,
  hook (`HookContext`) and deadline scopes, service-scoped signer wrapping,
  delegated-lease wrapping, the host-origin failure port and host-only request
  authorization. `deps` re-exports
  the third-party types and macros supported signatures name. The SDK resolves
  no secrets, loads no TLS files and reads no process environment.
  `docs/provider-sdk.md` documents its supported surface for provider authors.
- `crates/agent-access-core`: shared config, policy, identity, envelope, and
  runtime, host secret-reference resolution, and host network construction
  (`network.rs`: outbound TLS trust, egress proxy selection and the per-caller
  upstream client factories) and the Git gateway's upstream credential
  presentation (`gateway_token_auth.rs`: `upstream_token_auth` and the
  host-only `gateway_upstream_authorization` that forwarding and Git
  verification share; `runtime/gateway_access.rs`: each gateway request's
  static credential or OAuth lease, revalidated and pinned to the gateway's
  `upstream_base_url` before every upstream attempt, with ref discovery's one
  401 recovery, no pack POST replay, the 403 naming the portal reconnect, and
  the refusal, before sending, of a token profile a published service marks
  route-bound or none declares)
  and credential connections (`connections.rs`: the
  `[credentials.connections]` model with its `token_profiles` list and
  service-account override, its validation and authority checks, the
  implicit type every publication resolves into the effective connection,
  `PrincipalKind` and `select`, which every personal-credential consumer
  uses;
  `runtime/personal_credentials.rs` reads the selected token rows whose
  stored profile the selected list accepts, lent as that profile;
  `runtime/lookup_access.rs` plans and selects lookup access: the shared
  lookup credential, the caller's token, or the operation's one OAuth lease
  shared with execution) and OAuth login binding (`oauth/login_binding.rs`:
  a registration's optional `login_binding`, checked against the owner's
  linked Microsoft sign-in at consent start and, after the identity request,
  again inside the install transaction) and OAuth remote revocation
  (`oauth/revocation.rs`: the family a fence ends kept in the same transaction
  for a dialect that revokes, bounded revocation passes, late and uncertain
  refreshes, and the `remoteRevocation` states; `managed_store/oauth_revocation.rs`
  stores the encrypted pending revocations of migration `028`) and Microsoft
  membership renewal (`microsoft_oidc/renewal.rs`: the bounded token-endpoint
  request, response classification and backoff;
  `managed_store/oidc_membership_renewal.rs`: the encrypted records of migration
  `031`, the renewal hint, and the attempt-start and outcome writes); contains no
  backend. Its internal
  `imports` module owns the import adapter contract (`ImportedAdapter`, imported
  definitions, bounded import schemas) and the opaque
  `ImportedAdapterRegistration`. Crates that use backend-contract items import
  them from `agent_access_provider` directly, not through core.
- `crates/agent-access-content`: rich-content formats (ADF, Confluence storage,
  GitLab Markdown) rendering and conversion, plus attribution footers.
- `crates/agent-access-jira`: the Jira backend (`project_list.rs` live project collection, `backend.rs` wire seam and HTTP
  client, `jql.rs` search and JQL parser, `config.rs`, `present.rs`). Its
  `test-support` feature serves the production provider with its gateway
  route at a stub origin, for host tests of OAuth connections.
- `crates/agent-access-confluence`: the Confluence backend (`space_list.rs` live space collection, `backend.rs` wire
  seam and HTTP client, `cql.rs` search and CQL parser, `continuation.rs`
  page-token and draft-handle families, `config.rs`, `present.rs`), with the
  same `test-support` provider fixture as Jira.
- `crates/agent-access-gitlab`: the GitLab backend (`backend.rs` wire seam,
  pagination headers, and HTTP client, `access.rs` the credential each request
  presents: a static token, or delegated access pinned to the instance before
  every request with one 401 recovery per operation, `config.rs`,
  `provisioning.rs`, `present.rs`) and the `gitlab` OAuth dialect (`oauth.rs`:
  one instance's target and `gitlab` audience, token-info scope evidence at
  code exchange, the account's linked sign-ins for `login_binding`, and token
  revocation through `/oauth/revoke`).
- `crates/agent-access-atlassian`: a `native` module crate holding the
  `atlassian` OAuth dialect (`oauth.rs`: `auth.atlassian.com` consent with
  `audience=api.atlassian.com` and `prompt=consent`, JSON token requests,
  token-response scope evidence, `accessible-resources` sites merged per cloud
  ID with the granted `read:me`, a cloud-ID target and `api.atlassian.com`
  audience, and the consumer check that requires the gateway on that cloud ID)
  and the helpers shared by the Atlassian backends: the vendor-level,
  labeled and route-bound token profiles `atlassian-api-token` (site),
  `atlassian-scoped-api-token` and `atlassian-bearer-token` (gateway, declared
  with a `cloud_id`) that Jira and Confluence both declare, so one credential
  connection can serve both; the one fallible route classifier
  (`static_route`), by which each credential takes the route its token type
  selects (no profile: its kind's route; unknown profile, profile/kind
  mismatch or a gateway route without a valid `cloud_id`: refused before
  sending), shared by requests, verification, downloads and continuation
  binding; route-coverage validation of every credential source
  (`validate_atlassian_routes`, with the SDK's `base_covered_by_patterns`);
  `access.rs`, the credential each request presents: a static token on its
  route, or delegated access pinned to the gateway route's cloud ID and
  `api.atlassian.com` before every request, with one 401 recovery per
  operation, attachment downloads that present it only within the route's
  site (`AtlassianClients::site_base`), revalidated before each redirect hop,
  and the `mutation_verification_failed` receipt of a read-back the
  connection stopped; the tenant/gateway client routes, the gateway built
  whenever `cloud_id` is set, and their route fingerprint (tenant host and
  cloud ID); and the credential binding of their continuations and draft
  handles, whose classic, bearer and OAuth encodings are durable.
- `crates/agent-access-cloudbees-ci`: the CloudBees CI backend.
- `crates/agent-access-gmail`: Gmail actions, bounded mail projection and the Google OAuth dialect.
- `crates/agent-access-mcp-upstream`: generic imported MCP HTTP discovery and
  single-attempt execution over the host transport with the pinned SDK. Its
  `registration()` selects the `mcp_http` adapter together with its `mcp_oauth`
  companion dialect; the dialect has no separate export.
- `crates/agent-access-openapi-upstream`: imported OpenAPI 3.1 JSON parsing,
  bounded operation plans and single-attempt HTTP execution; `registration()`
  selects it, with no OAuth companion.
- `crates/agent-access-command-import`: the `command` import kind for
  operator-approved local executables (`[command_imports.<name>]`, endpoints
  `command:<name>`): `describe` manifest parsing and mapping (`manifest.rs`,
  `mapping.rs`), the command provider whose hook core calls instead of
  `Provider::invoke`, response, error and receipt mapping (`response.rs`), and
  Unix process supervision (`run.rs`, `process.rs`,
  `supervisor.rs` with its process-control test double): one process group per
  run, the signal lock, `WNOWAIT` exit observation and the budget slot each
  supervisor holds until it has reaped its process. Core keeps the per-command
  budgets and live supervisors in `imports/command_registry.rs`, carried across
  runtime generations and closed by the shutdown drain; its dispatch step
  (`runtime/command_dispatch.rs`) takes a slot before the final checks, then
  builds the stdin request (`imports/command_request.rs`: caller, authority,
  resources, credentials, network), which is the only place credential and
  private-attribute plaintext reaches a command.
  `registration()` selects it, with no OAuth companion. Fixture commands live
  in its `tests/fixtures/`.
- `crates/agent-access-teams`: notifications to managed Teams Workflows destinations.
- `crates/agent-access-fake`: development fixtures, each selected separately:
  the `fake` backend used by smoke tests and fixtures, the `oauth_stub`
  records backend (`[providers.oauth_stub]`) and the `stub` OAuth dialect for
  the external OAuth test server. Core defines no fixture of its own.
- `crates/agent-access-conformance`: a test-only backend using every backend
  contract extension point; the host's `tests::conformance` acceptance suite
  registers it and generates `apps/portal/unit/conformance.fixture.json`
  (regenerate with `UPDATE_PORTAL_FIXTURES=1`).
- `crates/agent-access-broker-host`: the broker host library: module
  composition (`src/composition.rs`), the assembly identity it checks against
  that composition (`src/identity.rs`) and the build status derived from both
  (`src/build_status.rs`), the broker application (`src/application.rs`:
  command parsing, `config validate`, `audit verify`, exit statuses) and its
  `serve` lifecycle (`src/lifecycle.rs`: logging, listeners, signals, reload, and
  bounded shutdown; `src/http_server.rs` serves each listener's connections and
  owns their tasks; `src/oauth_revocations.rs` the OAuth revocation worker the
  lifecycle starts and drains; `src/membership_renewal.rs` the Microsoft
  membership renewal admission, flights and drain, sharing ID-token validation
  with sign-in through `src/oidc_id_token.rs`), HTTP routers and handlers,
  management, HTTP MCP serving, portal serving, the Git smart HTTP gateway,
  reload, and runtime state, plus the broker unit-test tree (`src/tests/`). Its
  production code depends on no backend or import adapter; tests link the real
  backends through `src/test_composition.rs`. Its public API is the composition,
  the application, the assembly identity and the build status; routers, reload
  and runtime state stay crate-private. The `test-support` feature adds
  `src/test_support.rs`: isolated broker applications for acceptance tests, with
  provider fixtures and read-only store views. Release builds never enable it.
- `crates/agent-access-broker`: the `agent-access-broker` binary: a thin
  assembly whose `main.rs` runs the host's `BrokerApplication`; `composition()`
  in `src/backends.rs` selects the modules it links and `build_identity()` in
  `src/build_info.rs` stamps its identity, including the release commit for its
  workspace modules. Its library exports only those two functions.
- `crates/agent-access`: CLI binary, typed service wrappers, and smoke tests.
  `tests/fixtures/command-imports/ticketing.py` is the reference import
  command, in Python's standard library only, which `command_import_smoke.rs`
  and the portal's `imports-command.spec.ts` import; run
  `python3 crates/agent-access/tests/fixtures/command-imports/ticketing.test.py`
  when changing it, and keep it in step with `docs/command-imports.md`.
- `apps/portal`: same-origin browser management portal frontend and Playwright
  e2e harness.
  `apps/portal/src/workbench` is a pinned shared workbench-ui snapshot. Builds
  and checks require no upstream access. Never edit the snapshot in place:
  public contributors submit a Broker issue or proposed patch for maintainer
  review; maintainers commit changes to the private upstream and re-vendor.
  Follow [the contribution workflow](docs/workbench-vendoring.md).
  `npm --prefix apps/portal run check:workbench` verifies the snapshot; portal
  builds and unit tests also run this check.
- `demo/`: tracked local managed-mode browser demo config and setup script; the
  generated database, logs, token files, and copied portal assets live under
  `/tmp/agent-access-broker-demo` by default. The resume launcher preserves this
  populated state. `demo/seed-audit-showcase.py` creates marked offline audit
  fixtures with a backup and state locks; never use it on an operational store.
  Run `python3 demo/seed-audit-showcase.test.py` for its SQLite/FTS,
  idempotency, and rollback checks.
- `tests/downstream-consumer/`: templates for a separately owned provider
  repository and a downstream Broker assembly, excluded from the root workspace.
  `scripts/verify-downstream-consumer.mjs` stages them as independent Git
  repositories pinned to a clean commit, builds them `--locked --offline` from the
  shared Cargo download cache, and runs the assembled executable; release
  qualification runs it as the `downstream-consumer` gate. In the same stage it
  builds and tests the marked code of `docs/provider-sdk.md` and
  `docs/downstream-assembly.md`. Keep the templates valid TOML with package
  names distinct from upstream crates, and pin upstream only by the canonical
  URL with the all-zero sentinel `rev`. See its README.
- `skills/`: self-contained agent-facing usage skills split by access surface.
- `scripts/`: release, portal build, and local portal smoke helpers (smoke tests
  are cargo integration tests under `crates/agent-access/tests/`). Trusted-ingress
  admission and identity tests run within this repository; deployment-specific
  cross-repository harnesses are maintained outside it. See `docs/testing.md`.
  The macOS/Linux portal launchers share `scripts/local-broker-process.py` for
  path resolution, exact executable/config identity checks, port availability,
  and detached startup. Run its native checks with
  `python3 scripts/local-broker-process.test.py` when changing the launchers.
  `scripts/capture-portal.mjs` captures separate showcase (light/dark) and guide
  (light-only) image streams from the populated demo. Keep raw captures under
  ignored `.scratch/` or outside the repository; ship reviewed images under
  `docs/images/portal/` with captions identifying synthetic data. Setup forms
  remain unsubmitted; credential verification success/failure captures use
  browser-only fixtures identified in the manifest, never real upstream tests.
  Keep guide annotations as separate assets under
  `docs/images/portal/guide-annotated/`; preserve the original guide captures.
  Review generated annotations for faithful UI text and accurate callouts before
  updating guide image links.
  `demo/seed-guide-accounts.mjs` adds an actual auditor and a temporary-password
  onboarding identity to the loopback demo for role-accurate captures; keep its
  private credential handoff in the disposable demo directory.
- `docs/`: implemented architecture, reference, security, operator, and user
  docs, plus the provider-author guide (`docs/provider-sdk.md`) and the
  downstream assembly guide (`docs/downstream-assembly.md`).
- `schemas/`: published versioned JSON Schemas for runtime and contract
  surfaces.
- `api/`: generated supported public API inventories, one file per surface,
  maintained by `scripts/public-api.mjs`; `api/README.md` describes the surfaces,
  prerequisites, and review rules.

## Documentation Map

- `README.md`: project framing, quickstart, high-level architecture, and the
  top-level documentation index.
- `CONTRIBUTING.md`: focused bug reports and fixes, feature proposals,
  where provider contributions go, and contributor expectations for issues and
  pull requests.
- `assets/screenshots/`: permanent copies of selected README showcase images.
  Keep README image sources and full-size links relative, with file checksums in
  the adjacent manifest. Keep unused selection images and review galleries
  outside the product repository.
- `docs/portal-guide/index.md`: illustrated portal walkthrough index, linking
  user self-service, auditor investigation, account/group onboarding,
  resource/grant creation, and administration/offboarding. Captions distinguish
  draft forms, synthetic audit fixtures, and simulated verification results.
- `docs/images/portal/`: original and annotated walkthrough images. Keep guide
  image paths relative to their Markdown page and include every referenced
  asset. The capture inventory covers the retained guide images; public
  manifests omit private host paths, credentials, and browser session state.
- `agent-access-broker.production.sample.toml`: minimal managed production
  baseline, with required identity, protected key/state paths, SQLite audit,
  disabled steady-state bootstrap/migrations, and no provider grants.
- `docs/administrator-guide.md`: administrator bootstrap, principal onboarding,
  credential modes, resources/grants, service delegation, access review, and
  offboarding.
- `docs/release-readiness.md`: candidate validation, distribution contents,
  administrator acceptance, and publishing checklist.
- `docs/design.md`: implemented architecture and conceptual contract for crate
  layout, composition and process lifecycle, request lifecycle,
  identity, policy, credential selection, audit, observability/correlation,
  limits, egress proxy, reloads, and security posture.
- `docs/system-overview.html`: self-contained, hand-authored architecture
  presentation (connection paths, identity, policy, request evaluation, rate
  limits, audit) for readers new to the broker; Markdown remains canonical.
- `docs/http-api.md`: HTTP routes, runtime spec endpoints, request-id rules,
  response envelopes, reason codes, status mapping, management endpoints,
  upstream correlation headers, and raw download negotiation.
- `docs/cli.md`: command catalog, runtime spec commands, JSON `send`, config/env
  precedence, exit codes, transport security, and CLI recipes.
- `docs/mcp.md`: local stdio and downstream HTTP MCP setup, discovery, file inputs/transfers,
  protocol lifecycle, and client/broker authorization boundaries. The adapter
  lives in `crates/agent-access/src/mcp/`; never call CLI print/exit helpers from
  an MCP request handler, and never write diagnostics to protocol stdout.
- `docs/testing.md`: deterministic test suite, offline smoke harnesses, ignored
  live smokes, and Confluence CQL conformance smoke workflow.
- `docs/configuration.md`: canonical broker and CLI config schema, including
  identity, policy, credentials, managed store, broker tokens, encryption,
  management, audit, services, and providers.
- `docs/oauth.md`: delegated OAuth, production Google, GitLab and Atlassian
  dialects (including their administrator setup and scopes, and Atlassian's
  connection table, per-product registrations, quota and lifecycle), separate
  test provider, consent, refresh recovery, and connection boundaries.
- `docs/database.md`: managed-store database schema, token hashing, credential
  encryption, key readiness, rewrap, lifecycle, and backup/recovery model, plus
  the separate SQLite audit database.
- `docs/resources.md`: typed resources, flat include/exclude resource groups,
  execution contexts, live grant/token references, effective access, and catalog
  administration.
- `docs/providers.md`: provider overview, shared concepts, and links to the
  provider-specific docs.
- `docs/provider-sdk.md`: provider-author guide: supported SDK surface, trust
  model, registration and configuration, descriptors and scope resolution,
  provider state, admitted authority and static/delegated credential
  obligations, governed HTTP and the loopback rule, continuation tokens,
  standard and domain reasons, outcomes, test support, the compatibility policy
  and a worked example. Mark every `rust` block as described in
  `docs/testing.md#guide-code-blocks`; the `downstream-consumer` gate compiles
  and tests them against the candidate, so update the guide with SDK changes.
- `docs/downstream-assembly.md`: building another distribution from the host:
  composition, application lifecycle and exit statuses, assembly identity and
  module provenance, canonical Git pins, coordinated upgrades, source overrides,
  lockfile review, CLI/portal assets and notices, the release-feature check, and
  what qualification covers. Its example assembly is marked and checked like the
  provider guide's code; keep the files it states it shares with the fixture's
  assembly template in step with `ASSEMBLY_GUIDE_SHARED_FILES`.
- `docs/imported-services.md`: generic MCP import setup, administrator review,
  credential ownership, refresh, limits, and invocation outcomes.
- `docs/imported-openapi.md`: OpenAPI document/API destination setup, discovery
  authentication, scheme selection, supported operation profile and write receipts.
- `docs/imported-oauth.md`: approved MCP OAuth registrations, metadata validation,
  discovery onboarding, unknown upstream identity, and optional refresh.
- `docs/command-imports.md`: operator-approved local command imports:
  `[command_imports]` approval, import and refresh with resource-type changes,
  Broker- versus command-enforced resources, credentials, the describe/invoke/
  verify stdin and stdout contract, error codes and receipts, network settings,
  process lifecycle and limits, audit, and the trust model.
- `docs/providers-jira.md`: Jira issue, search, comment, attachment,
  verification, URL locator, and attribution behavior, and OAuth connections
  with each action's Atlassian scopes.
- `docs/providers-gmail.md`: Google connection setup, Gmail actions, MIME bounds,
  refresh recovery, and live smoke instructions.
- `docs/providers-teams.md`: signed Workflow destinations, managed setup, payloads,
  client commands, and acceptance/delivery limits.
- `docs/providers-confluence.md`: Confluence live spaces, page, blog, draft, comment,
  attachment, CQL, URL locator, and attribution behavior, and OAuth
  connections with each action's Atlassian scopes.
- `docs/providers-cloudbees-ci.md`: CloudBees CI job resources and
  job/build/Pipeline/test reads, log/report/artifact downloads, queue inspection,
  and trigger actions.
- `docs/providers-gitlab-rest.md`: GitLab REST project, issue, merge-request,
  note, discussion, branch, file, commit, pipeline, and job behavior.
- `docs/git-http-gateway.md`: Git smart HTTP gateway behavior for
  `[gateways] kind = "git_http"`.
- `docs/security-model.md`: rationale for the broker, agent containment model,
  egress boundary, direct-token comparison, credential boundary, authorization
  ownership, linked-module trust, and residual risks.
- `docs/end-user-guide.md`: user sign-in, personal credential/OAuth setup,
  separate setup/invocation client configuration, agent token issuance,
  CLI/MCP connections, and troubleshooting.
- `docs/operator-guide.md`: managed deployment operations, store setup, key
  handling, reloads, health checks, service logs/correlation, audit,
  backup/restore, and common failures.
- `docs/manual-live-smoke.md`: sanitized operator runbook for manual live smoke
  setup, grants, tokens, attribution, and targeted provider commands.
- `skills/agent-access-cli-typed/SKILL.md`: typed provider-wrapper CLI usage.
- `skills/agent-access-cli-invoke/SKILL.md`: canonical `agent-access invoke`
  usage against runtime catalog actions.
- `skills/agent-access-cli-send/SKILL.md`: JSON request-file usage with
  `agent-access send` and runtime send schema.
- `skills/agent-access-http/SKILL.md`: direct broker HTTP API usage with
  runtime OpenAPI/catalog discovery.
- `skills/agent-access-mcp/SKILL.md`: discovery and invocation through existing
  MCP connections, including argument shapes, pagination, and error handling.

## Changelog

Location: `CHANGELOG.md` (root)

### Format

Use these sections under `## [Unreleased]`:
- `### Breaking Changes` - API/config changes requiring migration
- `### Added` - New features
- `### Changed` - Changes to existing behavior
- `### Fixed` - Bug fixes
- `### Removed` - Removed features

### Rules

- New entries always go under `## [Unreleased]`.
- Use the existing subsections; do not create duplicate subsection headers.
- Record user- and operator-visible changes: configuration, HTTP API, CLI,
  portal, audit and log contracts, managed-store migrations, security-relevant
  behavior, and the supported SDK surface for provider authors. Usually one to
  three short bullets per PR is enough. Describe the resulting behavior and
  required upgrade action relative to the last release, not the implementation
  diary; leave internal, test-only and refactor-only changes, implementation
  detail and test logs to the PR.
- Consolidate related Unreleased entries as a feature evolves: edit the entry
  a later PR changes instead of appending another, and replace or remove one
  whose behavior changed again before release. Retain the consolidated entries'
  PR references and only the current compatibility requirements.
- Link the operator guide or other documentation for detailed contracts.
- End each entry with an indented line of its PR links in ascending order, such
  as `([#12](https://github.com/kcosr/agent-access-broker/pull/12))`. Add the
  PR number or link after opening the PR and before merging.
- Leave dated release sections unchanged; record corrections under Unreleased.
- `node scripts/check-changelog.mjs` enforces these sections, with bullets and
  indented continuation lines; empty headings are fine in `Unreleased`. Released
  sections must match the merge-base with `origin/main` byte for byte.

## Release Procedure

Prepare release metadata, qualify the reviewed source revision, and publish that
same revision as separate steps. Follow `docs/release-readiness.md` for required
checks and distribution acceptance. All four release entrypoints, including
standalone provenance verification, reject inherited Git location/configuration
overrides and verify that Git's repository root matches the source checkout.

### Prepare

Start from a clean checkout on the preparation branch. Select `major`, `minor`,
`patch`, or an explicit semantic version; on the 0.x line, use `minor` when
`[Unreleased]` has breaking changes. Use `current` only when `Cargo.toml` has
the intended version but its release notes still need preparation; do not rerun
it on an already prepared version:

```bash
node scripts/prepare-release.mjs current
node scripts/prepare-release.mjs patch
node scripts/prepare-release.mjs X.Y.Z
```

The preparation script edits only `Cargo.toml`, `Cargo.lock`, and `CHANGELOG.md`.
It stamps the versioned release notes and opens a new empty `Unreleased` section
in the same change, then validates locked Cargo metadata. A failure restores the
three files. Review the diff, commit it, and merge it through the normal PR
process. Preparation does not commit, tag, push, or publish.

### Qualify

Run the qualification driver on the final clean merged commit, with a new or
empty evidence directory outside the checkout:

```bash
node scripts/verify-release.mjs --output-dir /absolute/external/path
```

The driver runs the required standalone Rust, crate-boundary, public API,
downstream consumer, portal, script, documentation, changelog, sample-config,
Unix signal, native release-provenance, and notice checks. It
writes `qualification.json`, per-gate logs, and generated Rust notices. Missing
required prerequisites or failed gates prevent passing qualification; optional
OAuth/live-provider exclusions and platform applicability are recorded. Preflight
requires Python 3.11+ and its SQLite 3.43+ library with working FTS5
`contentless_delete`, the `nightly-2026-07-13` toolchain and `cargo-public-api`
0.52.0 for the public API gate, and rejects Cargo target runners, including
through configuration includes. The public API gate checks the candidate
against its own `api/` inventory; for a release on an existing compatible line,
also review `git diff <previous-release-tag> -- api/`, where a patch release
may not remove or change any line. See the
[full prerequisites](docs/release-readiness.md#qualify-the-candidate) and
[public API compatibility](docs/release-readiness.md#public-api-compatibility).

Qualification accepts any clean branch or detached commit for PR validation and
rechecks that `HEAD` stays clean and unchanged. A merge that changes the SHA
requires qualification of that merged commit before publishing. Qualification is
native and local; the optional remote provenance check below cannot substitute
for it. The driver does not publish, create archives, or perform administrator
acceptance against a deployment.

### Publish

Only when publication is intended, use the passing qualification for the exact
prepared release commit:

```bash
node scripts/release.mjs --qualification /absolute/external/path/qualification.json
```

The publisher verifies the receipt's full SHA, version, and required gates, and
requires clean `main` to match freshly fetched `origin/main` and the qualified
SHA. It creates an annotated tag at that SHA, pushes only the tag, creates a
GitHub draft from the prepared release notes, then publishes the draft. It does
not edit source, create commits, push `main`, or make a post-tag changelog commit.

A failed publication preserves a matching tag or draft. Retry with the same
qualification only when the existing tag and draft metadata match the same
SHA, version, and notes. Existing published releases are never overwritten.

### Standalone provenance check

The full qualifier includes native production provenance. To run that check
alone from a clean checkout at a full commit or exact tag:

```bash
node scripts/verify-release-provenance.mjs <full-commit-or-exact-tag>
```

The verifier checks the exact pinned local compiler/Cargo versions and physical
paths, rejects ambient compiler/flag/profile overrides, rejects a release
dependency graph whose resolved features include `test-support` or that links a
`reference` crate, and uses locked dependencies with required source provenance;
the stamped host, SDK and module packages must resolve to tracked path packages
in the checkout. It builds native executables under
`target/<host-triple>/release`, checks CLI startup and authenticated Broker
status, and records discovered Cargo configuration digests. It is not a hermetic
build; see the [provenance boundaries](docs/operator-guide.md#build-provenance-and-deployed-status).

To run the separate optional remote check:

```bash
BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
node scripts/verify-release-provenance.mjs <full-commit-or-exact-tag> --build-service
```

Remote compiler/Cargo and service configuration are unverified. Both modes
require a clean, unchanged source revision and neither publishes a release.

## GitLab credential issuance

GitLab bot provisioning is implemented in `crates/agent-access-gitlab/src/provisioning.rs`;
its canonical contract is `docs/gitlab-bot-provisioning.md`. Preserve the explicit
distinction between Broker-held execution credentials and deliberately exported
new tokens. Only issuance/rotation responses contain `result.issuedToken`; keep
metadata reads/audit secret-free and maintain sensitive output markers across
catalog, OpenAPI, and send schema. Project service-account ownership must be
proved before membership changes or token management.

## Trusted managed human identity

Keep username assertions HTTP-MCP-only, with exact `X-Agent-Access-User` values and
explicit managed namespace/name bindings. A direct `authorization_user` caller
requires fixed context; a relayed `caller_authorization` caller uses its configured
context contract. Match credentials by transport on every route. Select typed
username mode before ordinary principal auth; competing sources or failure never
fall back to an ordinary token or fingerprint. Without a user assertion, preserve
ordinary-token precedence over fingerprint identity. The caller credential alone
never authenticates the human. Keep caller audit identity separate from token
provenance and keep assertion secrets/names out of failure traces.

Every human has one durable identity-access gate and exactly one identity-token
row, both created transactionally with the principal, even without token
inventory; a row without a secret is not configured. Preserve gate pause across
inventory set/remove/generate. Username bindings and inventory revisions are
independent; never recreate removed inventory on login, and never recreate or
repair a missing identity-token row. Each binding and the identity token carry
their own Enabled and Read-only settings; secret set/generate/remove keep them.
Every actual settings change advances the binding version or inventory revision
once (a no-op writes nothing), and the attested proof includes the read-only
value. Gate incarnation/version, binding ID/version and inventory revision
prevent old sessions from regaining authority when values are restored. A
disabled binding or token resolves exactly like an unknown name or fingerprint.
Reject kind changes to/from human. Missing gate or identity-token rows fail
closed. Identity inventory remains encrypted; ordinary reads and audit must not
expose plaintext or fingerprints. Only explicit administrator reveal returns
plaintext. Shared pause belongs to identity-access administration, independently
of issued Broker token pause and browser login.

Read-only is a per-path class ceiling, not a person setting and not a grant
filter: apply it in the one agent-invoke ceiling rule (execution context,
read-only, service/action caveats) that invocation, Git admission, discovery and
resource clauses share, before grant selection and without removing grants, so
precedence is unchanged. A missing or unserved descriptor counts as a write.
Refuse writes before credential, OAuth, scope or provider work; Git push is
refused at receive-pack discovery and POST before the body is read. Carry the
setting as serialized `identitySource.readOnlyAccess`, never in `token_scopes`
or stored token caveats. Browser sessions and issued Broker tokens are
unaffected.

Carry one private proof through MCP intake/session/final governed admission.
Revalidate it before credential or provider work; never resolve a queued request
as a newly mapped human. Caller security epochs survive reload snapshots and
advance for actual security-contract changes, including loaded secrets. Prune
confirmed stale sessions without cancelling independently admitted operations;
unavailable state is not proof of staleness. Reject protected Connection/trailer
nominations globally and all actual MCP request trailers before dispatch. Keep
proofs and credential-derived bindings out of serialization, Debug and telemetry.

Validate every supplied caller and protected assertion on HTTP, MCP and Git,
independently of token-free fingerprint Git opt-in. Fixed callers reject context
headers; asserted callers cannot inherit the direct-client default. Reserve
`broker` as the control-plane service namespace: designated admission failure
tuples must never be produced after provider dispatch. Keep schema, portal,
CLI/catalog/OpenAPI/send projections and current docs aligned. See
`docs/trusted-callers.md` and `docs/managed-identity.md`.

## Private resource configuration

Resource and resource-group mutations keep mandatory preflight and supplemental
success audit distinct. Capture allowlisted before/after names and membership
deltas inside the managed transaction, never from a later catalog lookup or raw
request body. Keep completion emission in the mutation owner so disconnects do
not cancel it; completion failure must preserve the committed response. Managed
and audit stores are separate, so do not claim crash-atomic completion. Audit
names are historical; portal links explicitly open current state at the ID and
must be gated by catalog read capability. Never infer service visibility from a
global resource/group change.

Keep private resource attributes out of `ResourceDefinition`, catalog/export
serialization, agent tool inputs/results, Debug output, and audit. Command
imports are the exception: the Broker passes them to the approved command on
stdin only and never adds them to results or audit itself, but it checks the
command's messages, stages and locators for credentials and proxy secrets
only, so a command's own reply may carry an attribute value. Only explicit
admin reveal returns plaintext, after authorization/CSRF and audit preflight, with
`Cache-Control: no-store`. Store changes are atomic with resource versions and
policy publication. At dispatch, revalidate the admitted resource identity, alias,
versions, enabled state, and context before decrypting; never refresh a stale
binding onto a replacement endpoint. Retained secrets, including disabled
resources, participate in key readiness, used-key inventory, and credential rewrap.
Rewrap preserves semantic versions.

Teams uses current Workflows signed URLs on configured Microsoft environment
origins and service-mode grants without dummy credentials. Keep endpoint path and
query out of logs, errors, traces, and client bases; reject redirects and automatic
POST retries. A 2xx receipt means endpoint acceptance, not completed Teams delivery.
Use only synthetic endpoints in deterministic tests; live sends require an
explicitly authorized dedicated Workflow.

## Imported services

Imported integrations use DB-managed stable service/action identities and compiled
adapter factories. Core must not depend on a protocol adapter. Preserve offline
startup, retained grant references, current operator gates, and cancellation-safe
DB commit/runtime publication. Selected imported user credentials never fall back
to shared service or discovery tokens. Retained service-owned secret slots must
remain in key inventory, readiness and rewrap. Imported upstream payloads are
conservatively sensitive output, including ordinary telemetry or document data.

Import management remains outside the agent tool catalog. Preview acceptance must
reconstruct schemas from the persisted manifest, never trust caller-supplied tool
definitions. Complete refresh quarantines changed/missing accepted tools; failed
partial discovery must not publish. MCP imports support exactly `2026-07-28` and
`2025-11-25` through the host transport and pinned SDK. Keep automatic negotiation
bounded to startup: at most one discovery probe and one legacy initialization,
with a shared deadline and single tool-dispatch fence. Legacy sessions remain
private to an operation; initialized-session and eligible probe-session cleanup
share one two-second budget and cannot change known outcomes or invalidate OAuth
tokens. Preserve the finite JSON/SSE profile and uncertain-write receipts after
disconnect; upstream stdio hosting, server requests and replay remain unsupported.
Opaque image/audio content stays bounded JSON.

Propagate the host operation deadline into imported MCP finalization, and mark
cleanup only after capturing an outcome. The ordinary HTTP MCP deadline permits
one immediate final poll of that same provider future during cleanup; Pending
remains a timeout. Preserve the known result without a grace period, detached
cleanup or second dispatch. Forced shutdown retains its unknown-outcome contract.

Imported OAuth must use operator-approved authentication adapters and exact resource
bindings. Preserve per-flow issuer checks, PKCE, connection revision fences and
per-request delegated lease revalidation. Never infer an upstream account identity
when the authorization server provides none, or replay MCP calls after a 401.

Imported OpenAPI document URLs are operator-controlled destinations independently
of API base URLs. Keep schema/operation plans bounded and offline at execution;
never fetch external references, follow redirects, or infer resource grants.
Empty drafts may choose settings before accepting actions; accepted connection
settings and delivery cannot change underneath existing action identities.

Imported resource types come only from accepted import metadata and keep their
Broker type IDs once accepted. They change in place only under the safe-change
rules in `docs/imported-services.md`; acceptance rechecks every decision that
depends on stored resources inside its transaction under the policy mutation
lock, and publishes the registry, catalog and any advanced policy together.
Never decrypt attribute values to judge a type change.

Empty imported drafts may change adapter settings/delivery only before actions
are accepted. Such changes clear execution/discovery slots transactionally and
require removal of existing personal credentials first; never carry stored
authority to a new draft destination.
