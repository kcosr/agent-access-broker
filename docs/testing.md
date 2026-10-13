# Testing Guide

This document is the canonical testing guide for Agent Access Broker. CLI command
syntax is documented in `docs/cli.md`; provider behavior is documented in
`docs/providers.md` and the linked provider-specific references.

## Test Taxonomy

The repository uses five test categories:

- Deterministic local tests run during ordinary `cargo test` and require no live
  upstream credentials.
- The Unix process-signal smoke is deterministic and local but explicitly
  `#[ignore]`-gated because it sends real signals to isolated child processes.
  It is required separately on Unix and not applicable on non-Unix platforms.
- The portal Playwright e2e harness is deterministic and local, but it runs
  separately from Cargo. It combines real-service integration fixtures with
  mocked API contracts for UI behavior. Real-service fixtures start a Broker
  with a temporary managed store and drive desktop Chromium through the
  same-origin portal; there is no phone project. The harness builds the React
  app and both Rust binaries locally by default. `BUILD_SERVICE_ENABLED=true`
  selects the optional build service for those binaries. Setting both
  `AAB_BROKER_BIN` and `AAB_CLI_BIN` to freshly built executables from the
  selected revision skips Cargo; one override builds the remaining executable.
  The independent OAuth fixture is skipped without `OAUTH_STUB_REPO`.
  The main journeys fail on
  any Content Security Policy violation or uncaught page error, one test checks
  that every page and top-bar control fits a 1024px window, and the specs
  select by role and accessible name rather than CSS classes.
- Live smoke tests are `#[ignore]`-gated integration tests that drive the real
  `agent-access` binary against a live broker and real upstream services.
- Conformance smoke tests are `#[ignore]`-gated, manifest-driven live tests that
  collect focused evidence about provider compatibility.

Live tests can be read-only or mutating. Mutating tests create comments, pages,
attachments, updates, webhook deliveries, reviews or commits in the configured
Jira, Confluence or GitLab tenant. Always run live tests with an exact test-name
filter.

Do not run a live-smoke binary broadly with `-- --ignored`. For example,
`cargo test -p agent-access --test real_confluence_smoke -- --ignored` runs both
the read smoke and the mutating write/download/verify smoke in that binary.

## Local Deterministic Suite

Security regressions cover pre-body concurrency/source admission, independent
control-plane/metadata caps, anonymous and verified-principal body isolation,
probe availability, idle
and total receive deadlines, supported large GitLab inline HTTP/CLI inputs, and a Linux subprocess
with a 512 MiB address-space limit measuring bounded body-buffer memory. Password
fixtures pause real/dummy verification while resolving an existing token, race
resets/disables, preserve administrative hashing under login load, and verify
hash admission survives reload. CLI redirect tests
use two origins for JSON, upload, and download requests. Gateway caching tests
combine a real TLS upstream and two Broker tokens with an RFC-aware cache-storage
fixture. Management tests assert no-store on each token issuance route and
exercise a real SQLite failure without exposing its diagnostic in HTTP output.
Snapshot tests confirm prepared operations may finish after revocation while
fresh requests fail; delegated OAuth/private-resource fences retain separate
coverage.

The `git_http_gateway` integration test requires Git, including `git http-backend`.
It drives real protocol-v2 clone, fetch, and push commands through an in-process
Broker gateway to a disposable Git repository behind a local TLS origin. Both
repository URL forms, with and without `.git`, must reach canonical `.git`
upstream paths. It also checks upstream credential selection, repository denial
before forwarding, and disabled redirect following. Git configuration, tokens,
repositories, and certificate trust are isolated from the user's environment.
Run it with `cargo test --locked -p agent-access-broker-host --test git_http_gateway`;
the ordinary locked Rust suite includes it. Its ignored `git_http_gateway_child`
test is invoked by the parent with isolated proxy settings, as with the outbound
TLS child fixture below. This fixture uses real Git smart HTTP, not a live GitLab
deployment or an external ingress proxy.

Local action-output coverage checks JSON/multipart send-schema eligibility and
destination dependencies, CLI format versus destination flags, saved JSON/Markdown,
private atomic replacement, compact receipts, and local stdio MCP output. Reads,
writes, and uploads can save supported responses; HTTP MCP rejects local paths
and raw downloads retain their transfer contract. A forced local save failure
after a successful mutation must report separate operation/output outcomes with
exactly one invocation and no response-payload retention. Denied or malformed
responses preserve the destination, while failures after replacement report that
it already changed. Invalid destinations must cause zero invocations, abandoned
reservations must be removed, and `applied_unverified` outcomes must retain their
status through successful and failed response/metadata saves. Tests use local
stubbed brokers/providers.

Grant UI tests cover conservative read-only classification, searchable two-column
selection, independent All/None controls, preservation of hidden selections,
explicit saved actions, and derived Write-capable indicators. Browser coverage
exercises distinct accessible bulk-action names, keyboard access, and the
desktop layout.

Command-palette unit tests cover word matching, relevance order, explicit safe
metadata fields, and role-specific destinations. Mocked browser contracts cover
resource/user groups, nested navigation, service actions, imports, personal
credentials, audit-search links, keyboard expansion, loading, and retry. A
real-broker browser regression creates a resource group, searches its name and
member selector, and opens its persisted details.

Audit filter tests cover raw service filtering, canonical broker suggestions on
empty history, visibility tiers, editable prefixes, and dropdown alignment in
both themes and viewport sizes. Cookie tests distinguish absent or invalid
broker sessions while allowing unrelated malformed cookies.

`apps/portal/tests/resource-audit.spec.ts` uses a real temporary Broker and
SQLite audit store, with no mocked API responses or seeded audit rows. Its
resource/group journey creates a named repository, includes it in a group, and
renames it. Assertions cover correlated preflight/success records, recorded
names and exact membership changes, search by the historical name, links to
current details, and back navigation preserving audit filters. Duplicate
creation must identify the existing resource, offer its detail link, create no
second entry, and emit no success record.

The core `outbound_tls` integration test uses private test CAs and loopback TLS
servers to check system, custom, and combined trust, hostname verification,
CloudBees downloads, and trust changes across reloads. Its parent test re-executes
the test binary with isolated `SSL_CERT_FILE`/`SSL_CERT_DIR` settings and proxy
variables removed, so it does not depend on the host trust store or change the
environment of concurrent tests. The ignored `outbound_tls_child` test is only
intended to run through that parent; do not invoke it with `--include-ignored`.
Run the harness with `cargo test -p agent-access-core --test outbound_tls`.

Provider and Broker unit tests share the `test-support` feature of
`agent-access-provider`. Its `TestHost` lends a provider build context with a
deterministic, offline upstream client factory: clients trust only a disposable
test CA embedded in that package, never read proxy environment variables, use a
configured service proxy only when it has no credential references, and record
each requested label, base URL, profile and route in `built_clients()`. Core's
own network tests cover proxy precedence, credential resolution and the
literal-loopback caller categories against the real host factory.

Broker acceptance tests use the `test-support` feature of
`agent-access-broker-host`. Its `test_support::IsolatedBroker` starts an
assembly's composition and identity on one real configuration file, either a
TOML document written privately (`0600` in a `0700` fixture directory) or a
test-owned path, through the same startup as `serve`: configuration validation,
state locks, readiness, reload publication, and operation and audit drain. Its
loopback listeners are bound to ephemeral ports when the fixture is created, so
a configuration can name their addresses, such as `[mcp] public_url`. It
installs no process signal handler or global log subscriber. The lifecycle's
tasks, reloads and connections report to the dispatcher of the task that
starts the broker; tasks that request handlers spawn themselves report to the
default dispatcher. `RunningBroker::reload` and `shutdown` stand in for SIGUSR2
and SIGTERM. As in the process, connections still open at the shutdown deadline
are cut off. `join` ends HTTP MCP sessions a client left open, as process exit
does, and returns a drain report once every state lock is released, so a test
can restart on the same state. `ProviderFixture` is a fixture control, not an
embedding API: it supplies the provider of a selected native kind that the
configuration configures, built for each generation, while configuration
validation, admission and generation ownership still apply.
`RunningBroker::audit` and `managed_store` give read-only views of the
fixture's stores; the views keep the fixture directory and stay readable after
`join`. `portal_service_catalog` exports the grant catalog that the portal
conformance fixture records. The feature adds construction and control APIs
only. Release builds must not enable it, and test binaries into which Cargo
unifies it keep production semantics.

Tests that assert `tracing` events call
`install_trace_capture()`, which installs one capturing dispatcher as the test
binary's global default, then start a capture and run the observed work through
`TraceCapture::run` or `in_scope`. A capture records only the events inside its
span, including owned work carried by `InvocationScope` or another instrumented
future, so concurrent tests need no lock. Events on uninstrumented tasks,
blocking closures, or plain threads are not captured. A test binary that uses it
must not install another global subscriber.

Reload behavior fixtures use the production admission and shutdown budgets.
Runtime construction loads the host CA store and performs local filesystem work,
which can exceed a one-second deadline under parallel test load. Tests that
exercise timeout validation keep explicit timeout values.

Run these checks before submitting code changes with the pinned Rust/Cargo 1.98.1
toolchain in `rust-toolchain.toml`. The tested portal toolchain is Node.js 24.18.0
and npm 11.16.0; these pins record reproducible validation, not minimum supported
versions. Commands below run locally. An available configured
[build service](../AGENTS.md#build-service) can wrap the Cargo commands instead.

```bash
cargo fmt --check
cargo test --locked
cargo build --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo run --locked -p agent-access-broker -- --config agent-access-broker.sample.toml config validate
cargo run --locked -p agent-access-broker -- --config agent-access-broker.production.sample.toml config validate
cargo run --locked -p agent-access -- --config agent-access.sample.toml config validate
npm --prefix apps/portal ci
npm --prefix apps/portal run check:workbench
npm --prefix apps/portal run build
npm --prefix apps/portal run test:unit
npm --prefix apps/portal run test:e2e
node --test scripts/*.test.mjs
node scripts/check-crate-boundaries.mjs
node scripts/public-api.mjs check
python3 scripts/generate-rust-notices.test.py
python3 scripts/local-broker-process.test.py
python3 demo/seed-audit-showcase.test.py
node scripts/check-doc-links.mjs
```

Every workspace crate declares one role in its manifest:

```toml
[package.metadata.agent-access]
role = "native"
```

The roles are `sdk` (`agent-access-provider`), `core`, `host`
(`agent-access-broker-host`), `assembly` (`agent-access-broker`), `cli`
(`agent-access`), `native` (backend crates), `reference`
(`agent-access-conformance`), `adapter` (the MCP and OpenAPI import adapters),
and `helper` (`agent-access-atlassian`, `agent-access-content`).
`node scripts/check-crate-boundaries.mjs` reads
`cargo metadata --locked --format-version 1 --all-features` and fails when a
workspace member has no known role or when a resolved dependency edge crosses
these boundaries:

- The SDK has no dependency of any kind on another workspace crate.
- Native, reference, and helper crates have no normal, build, or development
  dependency on core, host, assembly, CLI, or adapter crates.
- Adapter normal and build dependencies reach only SDK, helper, and core crates.
- The transitive normal and build dependency closures of core and the host
  contain no native, adapter, or reference crate. Development dependencies may
  link real backends for tests.
- The CLI's normal and build closure contains no host, assembly, native,
  adapter, or reference crate. Its core dependency is reported as allowed.

Its unit tests use synthetic metadata and run with the other script tests.

`node scripts/public-api.mjs check` regenerates the supported public API
inventory and fails when it differs from the checked-in `api/` files. It covers
the SDK and host with and without `test-support`, the assembly library, the
reviewed selection entry points of the native and import adapter crates the
assembly links, and the workspace and third-party types those signatures expose.
After an intended and reviewed API change, run `node scripts/public-api.mjs
update` and commit the `api/` diff. The check requires the `nightly-2026-07-13`
Rust toolchain, installed with rustup, and `cargo-public-api` 0.52.0 on `PATH`.
Set `AGENT_ACCESS_PUBLIC_API_RUSTUP_HOME` when the nightly is in a different
rustup home from the active one:

```bash
rustup toolchain install nightly-2026-07-13 --profile minimal
cargo install cargo-public-api --version 0.52.0 --locked
AGENT_ACCESS_PUBLIC_API_RUSTUP_HOME="$HOME/.rustup" node scripts/public-api.mjs check
```

It runs the nightly's rustdoc by absolute path, so `rust-toolchain.toml` does
not select the toolchain, and builds only in `target/public-api`. A missing or
mismatched tool fails with exit status 2; the check never skips. Its unit tests
use synthetic rustdoc JSON and Cargo metadata, check the reviewed entry points
against the repository's own metadata, and run with the other script tests. See the [inventory guide](../api/README.md) for the file format and review
rules.

On Unix, run the real-signal parent fixture separately:

```bash
cargo test --locked -p agent-access-broker-host --lib lifecycle::tests::unix_signal_smoke_in_isolated_child_processes -- --ignored --exact
```

The parent starts guarded child fixtures for SIGTERM/SIGINT shutdown and SIGUSR2
reload. Never invoke `lifecycle::tests::unix_signal_smoke_child_harness` directly; it is an
entrypoint for the parent. Do not broaden this command to all ignored tests,
which include separately authorized live-provider smokes. Record the signal
fixture as not applicable on non-Unix platforms.

Playwright additionally needs its matching Chromium installation
(`npx --prefix apps/portal playwright install chromium`). Use an already provisioned browser/runtime on hosts where
downloading it or installing OS dependencies is unavailable; record that a skipped
browser suite was not validated.

Record the exact source revision, toolchain, local or remote build mode, commands,
exit codes, and check results. A release build must use the checked-in lockfile;
do not silently update dependencies to make validation pass. Keep live-provider
smoke results separate from deterministic checks. After candidate edits, run the
complete release gate against the final clean commit and its freshly built
Broker, CLI, and portal; earlier passing results do not validate a newer revision.
Follow [release readiness](release-readiness.md) for distribution notice checks.

Portal builds generate and check `dist/licenses/THIRD-PARTY-NOTICES.txt` and its
manifest from emitted JavaScript dependencies, alongside the Broker and font
licenses. Check the actual copied portal directory before distributing it:

```bash
npm --prefix apps/portal run check:notices -- /absolute/path/to/packaged/portal
```

The check validates notice and emitted-chunk digests. Preserve the entire
`dist/licenses` directory with the portal assets. Generate and check the separate
Rust executable notices as described in the release distribution checklist.

Confirmed core-dump hard-limit or nested-sandbox mount/hostname restrictions in
the container are environment-limited failures. Identify the affected test and
restriction, continue independent checks, and retain the exception in release
evidence. Other failures need investigation; a passing build does not validate a
skipped test or live upstream compatibility.

On a shared host running other agents' tests, use
`cargo test -- --test-threads=4` to limit concurrent fixtures. The invocation
ownership and webhook-policy fixtures allow ten seconds for provider startup
or reload setup involving real audit, filesystem, and worker activity. Tests
of shutdown and timeout behavior retain their explicit budgets.

To offload the portal harness's Rust binary builds to the configured build
service while still running the TypeScript build and browser tests locally:

```bash
BUILD_SERVICE_ENABLED=true \
BUILD_SERVICE_ENDPOINT=http://build-host.example:6680 \
npm --prefix apps/portal run test:e2e
```

To run the portal harness against prebuilt binaries instead (for example an
unpacked release archive whose source matches the checkout), point the harness
at them; no Cargo build runs:

```bash
AAB_BROKER_BIN=/path/to/release/bin/agent-access-broker \
AAB_CLI_BIN=/path/to/release/bin/agent-access \
npm --prefix apps/portal run test:e2e
```

The prebuilt broker must include every server change the portal under test
relies on; use a fresh build when a change touches both.

The offline smoke harnesses live in `crates/agent-access/tests/`:

- `fake_smoke.rs`
- `jira_smoke.rs` includes project issue-type discovery through typed CLI,
  invoke, send, and direct HTTP, catalog/OpenAPI/send/MCP projections, explicit
  pagination, project denial before backend dispatch, and passing a discovered
  issue-type ID into issue creation.
- `confluence_smoke.rs`
- `gitlab_smoke.rs`
- `cloudbees_smoke.rs`
- `rate_limit_errors.rs` answers the real CLI with synthetic broker 429
  responses (`rate_limited`, `upstream_rate_limited`, `concurrency_limited`) and
  checks exit 7, the single stderr `rate limited: ` line, the unchanged stdout
  envelope and `--output` destinations, and that nothing is retried across
  generic invoke, typed commands, JSON `send`, and downloads.
- `audit_commands.rs` answers the real CLI with wiremock audit query
  responses: each filter flag as its query parameter, `--since` resolved to an
  absolute UTC `from`, cursor continuation with only `--cursor` and `--limit`,
  rejection of filters beside `--cursor` and of `--principal` on the
  self-service listing, timeline routes, and error exit codes.
- `teams_smoke.rs` uses managed encrypted destinations and an offline transport
  to exercise the real typed/generic CLI, JSON send, admin attribute files/reveal,
  and stdio MCP `requestFile`, including grant narrowing and secret redaction.
- `mcp_stdio.rs` drives the real local MCP process against the real broker,
  covering action discovery, edited request files, resource denials, token
  rotation, stale tools, error recovery, and EOF shutdown. MCP unit tests also
  cover bounded framing, pagination, uploads, verified downloads, and secret
  sources. Discovery coverage includes the five fixed helpers, resource pages,
  targeted action names, exact native schemas, malformed helper arguments,
  broker denials, and recovery. Shared client tests cover inconsistent/failing
  detail fetches and token-class catalog visibility. Core and HTTP tests cover
  exclusions, token/context boundaries, broad grants, stale/foreign cursors,
  managed label revisions, and visibility before query validation.
  See [local MCP](mcp.md).

They use in-process or stubbed components and require no upstream credentials.

Teams unit tests cover simple/native payloads, size/depth limits, supported URLs,
exact-origin allowlists, redirects, response/status handling, and safe errors.
Core resource-attribute tests cover migration, encryption/AAD, atomic rollback,
version races, disabled-secret readiness, and rewrap. Broker management tests cover
admin-only reveal, CSRF, no-store, and audit failure before decryption. These tests
make no live Workflow calls; rendering and final delivery need a separately
authorized dedicated Workflow test.

Core stored-format golden tests use rows written by an earlier release. Per-user
credential rows and imported execution slots must still resolve to the same
material with fixed AAD bytes. Imported service definitions, including credential
bindings, accepted action definitions and hashes, and discovery previews keep their
exact JSON. A failure means stored credentials or imports would need reentry or
change identity; fix the change rather than regenerating the vectors.

The backend-contract acceptance suite (`cargo test -p agent-access-broker-host
conformance`) registers the test-only `agent-access-conformance` backend beside
the linked backends and exercises it through TOML configuration and
validation, discovery, the catalog/OpenAPI/send-schema projections, JSON,
Markdown, raw-download, and multipart-upload invocation against a stubbed
upstream, and MCP. A managed-policy fixture enables its endpoints and checks
private resource attributes end to end: the admin API's attribute rules,
encrypted storage, reveal, replacement, and that a key reaches the upstream
only for an authorized invocation of its endpoint. It also checks
`apps/portal/unit/conformance.fixture.json`, which the portal's unit tests
(`npm --prefix apps/portal run test:unit`) use to exercise resource labels,
namespace coverage, grant choices, and private attribute fields for a backend
the portal was not written for; its grant catalog comes from
`test_support::portal_service_catalog`. After changing the conformance backend
or the policy catalog shape, regenerate the fixture with
`UPDATE_PORTAL_FIXTURES=1 cargo test -p agent-access-broker-host conformance_portal_fixture`.
CloudBees CI coverage includes deterministic provider, policy/config,
managed-store migration, typed CLI parser/lowering, and an in-process Broker
smoke with a stubbed controller and the real CLI. The smoke drives artifact,
console-log, and test-report downloads through typed CLI, JSON send, direct
HTTP, and stdio MCP, including raw metadata and local output files. It verifies
that downloads for an ungranted job make no upstream requests and leave an
existing destination unchanged. HTTP MCP lists the new JSON reads and excludes
raw downloads. Console reads exercise head, tail, and literal search on the
reported 4,590,015-byte log through actual HTTP and stdio MCP handlers, including
escaped JSON wire limits. Provider tests cover cursor replay, changed prefixes,
caller/context/configuration binding, Unicode and malformed bytes, bounded
search context, scan ceilings, timeouts, and cancellation. Revoked-grant
continuation makes no upstream request. Coverage also includes trigger receipts,
redirect rejection, and audit redaction of log text, queries, and cursors. A throttled controller checks
`upstream_rate_limited` end to end: exit 7 and the stderr line from typed CLI
and JSON send, and the Broker's message as the stdio MCP tool error text. There
is no live CloudBees CI smoke without a configured tenant.
GitLab project-upload coverage includes real CLI typed/JSON-send HTML transfers,
HTTP multipart to a stub upstream, canonical repository/action/token denials,
caller-filtered catalog/OpenAPI/send metadata, file count/integrity and configured
byte/MIME bounds, and audit/error redaction of contents, credentials and upload
link secrets. No live upload is performed by the deterministic suite.
The hermetic GitLab core, Broker, and CLI suites cover the webhook vertical
surface: all ten action routes and typed wrappers, caller-filtered catalog/
OpenAPI/send parity, default-deny and allowed destination policy, existing
out-of-policy behavior, HTTP/TLS gates, secret-source handling and leak checks,
event mapping/redaction/truncation, and ambiguous mutation recovery.

Build-provenance parser, exact status-shape, authentication, request-ID,
execution-context independence, cache-control, runtime-spec parity, CLI parsing,
and status-command tests run in the ordinary deterministic suite. The verifier's
status comparison also has a Node unit test:

```bash
node --test scripts/verify-release-provenance.test.mjs
```

To smoke-test a production release binary end to end, use a clean checkout at
the expected immutable commit or exact tag:

```bash
node scripts/verify-release-provenance.mjs <full-commit-or-exact-tag>
```

The verifier first rejects a release dependency graph (normal and build units of
`agent-access-broker` and `agent-access`) whose resolved features include
`test-support` on any package, or that links a `reference` crate. It then builds
Broker and CLI release executables locally with locked dependencies and required
provenance. It starts the Broker on loopback with a temporary minimal identity and
asserts that `/v1/broker/status` names the `agent-access-broker` assembly at the
expected package version, with the expected commit as evidence-backed provenance
for the assembly, host, SDK and every module, and that each of those packages
resolves to exactly one tracked path package in the checkout. It checks CLI
startup with `--help` and fails if the checkout is dirty or `HEAD` changes. It
does not publish artifacts or perform the source release. Its script tests run
`cargo tree` on small generated workspaces to show that test support enabled
through a release package's default features is rejected while a dev-only
activation is allowed, and that a second module origin from a local Git
repository is ignored when only a development feature selects it but rejected
when production selects it.

To opt into a configured remote build service explicitly:

```bash
BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
node scripts/verify-release-provenance.mjs <full-commit-or-exact-tag> --build-service
```

The service must allowlist `AGENT_ACCESS_BUILD_COMMIT`,
`AGENT_ACCESS_BUILD_PROVENANCE`, and `AGENT_ACCESS_REQUIRE_BUILD_PROVENANCE`.
The verifier forwards all three and checks the copied-back Broker using the
same status assertions. Inherited `BUILD_SERVICE_ENABLED` does not select this
mode. Both modes use the repository's `target` directory.

Credential-helper tests exercise `auth git-credential get`, `store`, `erase`,
and `capability` through the real CLI binary. They cover every supported token
source and precedence, disabled identity, blank-line and EOF input termination,
malformed and forward-compatible fields, fail-closed `quit=true` output, and
token redaction from diagnostics. A temporary URL-scoped Git configuration also
proves that the matching gateway host receives the fixed `agent-access` username
and fake token while a different host receives no credentials from the helper.
That integration test requires a local `git` executable on `PATH`.

### Execution-context matrix

Context changes must cover config-neutral `default`, configured default, and
strict required-header modes. Exercise missing, duplicate, comma-joined,
malformed, unknown, allowed, and token-denied headers; prove the stable
`execution_context_required`, `execution_context_invalid`, and
`execution_context_denied` codes. For invoke, Git gateway,
capabilities, services, catalog, OpenAPI, and send schema,
verify context-specific visibility and that a mismatch performs no metadata
lookup, credential load/decrypt, or upstream connection. Also verify `/v1/me`,
health, browser/OIDC, and management routes remain context-independent, while
admin `visibility=all` omits context metadata.

Contract tests must cover TOML and managed grants, supported schema admission
and forward migrations, grant CRUD/filter/export, one-or-more self and admin token context caveats,
options endpoints, unknown/duplicate caveat rejection, stored tokens without
context caveats, CLI flags, portal choices, audit fields, spec `Vary`, and non-forwarding of the
trusted header by provider and Git gateway transports.

### Broker-token pause matrix

Store tests cover the fresh schema and incompatible-schema rejection, paired pause metadata,
idempotent pause/resume, status precedence, wrong-owner and wrong-class
concealment, terminal-state conflicts, and independently opened-store races in
which revocation wins. Invocation tests prove a token succeeds, fails exactly
with `broker_token_paused` after pause, and succeeds with the same secret after
resume; denial must not update `last_used_at`, load credentials, evaluate
provider policy, or contact upstream. Current grants and groups are re-resolved
after resume, including grants added while paused.

HTTP and runtime-contract tests cover owner, principal-admin, and general-admin
routes, CSRF, audit redaction, catalog/OpenAPI/send-schema parity, and rejection
of non-agent and browser-session tokens. CLI tests cover all four pause/resume
commands. Portal unit and Playwright tests cover state precedence and badge
tones, derived active counts, Pause/Resume controls, revoke-while-paused, pause
metadata, and parity in the managed-user admin view. An invocation admitted
before pause commits may complete; all later admissions must fail.

### Agent-token action/resource boundary matrix

Core caveat tests cover canonical reference sorting and round-trip, strict
unknown-field handling, duplicate IDs, absent versus present-empty restrictions,
and rejection of noncanonical scope shapes. Management token classes reject
agent-only caveats.

Resource-policy tests cover exact/all/nested namespace matching, selector
uniqueness, unregistered wildcard targets, mixed groups, live membership,
grant-local exclusion precedence, separate-grant authority, and token
intersection. Disabled or context-ineligible excluded entries must keep excluding.
Search tests exercise finite/all-except query composition before pagination and
returned-object containment checks.

Management tests cover global-admin catalog mutation, filtered options/Used by,
manual referenced-delete conflicts, token issuance/deletion races, and atomic
policy generations across updates. Paused token references remain live;
revoked/expired tokens do not block deletion. Effective access retains symbolic
exceptions and accepts a selection with no current access. Portal and CLI checks
exercise resource/group selection for the existing Jira, Confluence, GitLab REST,
and Git HTTP surfaces. CloudBees CI's new resource type has policy, typed CLI,
and broker-and-CLI smoke tests.

Service-account lifecycle tests cover portal/API creation, principal-kind
projection, absence of generated passwords and login controls,
administrator-managed agent tokens, and managed-store rejection of local
password, Microsoft login, admin role, browser-session, `user_manage`, and
`admin` issuance. Retained login and management-token rows are also exercised
after a user is changed to `service_account` to prove request-time fail-closed
behavior.

Runtime tests prove action denial precedes provider lookup, credential access,
upload consumption, and upstream work; canonical finite resources are enforced
after resolution across Jira, Confluence, GitLab REST, and Git gateway
paths. Jira/Confluence search tests verify policy/token intersection is injected
before the upstream query and an empty intersection performs no search. Catalog,
OpenAPI, and send projections hide token-disallowed actions. Grant removal
denies without mutating the boundary, restoration re-enables only stored values,
later grants cannot expand a finite ceiling, and an omitted scope deliberately
follows later grants.

Portal unit and Playwright coverage exercises self/admin issuance, action and
resource selection, wildcard free-form exact values, typed repository selectors,
immutable review/reveal, existing coarse-token display, unavailable-value
warnings and restoration, and lifecycle orthogonality. Audit
assertions require canonical safe boundary metadata and forbid raw secrets.
Deployment smoke covers one fine-grained token and one existing coarse token;
no database migration or configuration change is expected.

### Service policy management matrix

Store and API tests cover explicit manager roles with direct assignments to
multiple services, idempotent assignment/revocation, dormant services, disabling
and re-enabling accounts, and assignment removal on role change. Roles are not
derived from groups. Auditor reads, safe POST previews, denied mutations and
secret reveals, credential classes, and self-service on/off are covered across
API, runtime specs, and portal. Role changes revoke admin tokens while no-op and
flag-only updates retain them. Upgrade tests preserve identity data and reject
unexpected pre-upgrade manager assignments transactionally.

Cross-service inspect and mutation must be indistinguishable from an unknown
grant and must never reveal `version_conflict`. Create and create-shaped
validation reject unauthorized services; patch-shaped validation follows the
same not-found collapse, and scoped managers cannot move grants between
services. Assignment management and administrative identity, credential, token,
and configuration mutations remain global-admin-only. Auditors can read permitted
metadata, exports and status, and use safe previews, but cannot reveal secrets or
mutate. Independent self-service rights remain separate from these admin gates.

CLI tests cover manager list/grant/revoke, subject add/remove, and exact
grant-list filters. Portal unit and Playwright tests cover global-admin
assignment controls, direct principal holders, the scoped Policies-only admin
navigation, locked service edits, retained normal self-service areas, CSRF on
writes, and assignment/membership revocation. Token tests confirm an assignment
alone does not satisfy the effective-grant prerequisite for self-issued
`agent_invoke` tokens.

Trusted username acceptance is Broker standalone coverage using controlled callers:
exercise direct and relayed aggregate/service MCP, strict field parsing and route
rejection, binding and shared-gate administration, migration preservation, and
session/final-admission races. Include username operation without inventory,
fingerprint and ordinary-token regressions, all MCP trailer rejection, stale
session pruning at the cap, and completion of already admitted work. These
fixtures establish Broker's contract; they do not validate an external attester or
cross-product ingress implementation. For a deployment test, select freshly built
components explicitly and record that integration separately.

For rollout smoke, register the test proxy as a [named trusted caller](trusted-callers.md)
for both governed listeners. An asserted proxy injects its private
`X-Agent-Access-Caller-Authorization` credential and replaces incoming context
headers with the approved test value. A fixed caller sends only its credential
and omits the context header. Run discovery and an action through each selected
context, and confirm the catalog `executionContext`. Test missing-credential denial
and missing-context denial independently on an isolated listener. Keep test caller
credentials out of CLI configurations and agent workloads.

Microsoft OIDC coverage is also fully deterministic and does not contact
Microsoft. Core tests exercise strict single-tenant configuration and secret
loading, OIDC store schema admission, provider reconciliation, durable flow
capacity/claim/replay behavior, subject watermarks, atomic JIT completion,
binding and link conflicts, authoritative empty membership, expiry and
source-aware effective-membership projection, and unlink session revocation.

Broker tests use a local fake Microsoft provider with real discovery, token,
JWKS, RSA signature, nonce, and PKCE processing. They cover the browser start
and callback happy path; state, binding-cookie, replay, signature, duplicate
claim, and malformed claim failures; group overage versus complete empty groups;
unknown-key refresh; and provider-scoped discovery, token, and JWKS outages.
Management tests cover the mapping and direct-link routes, authorization, CSRF,
auditing, runtime catalog/OpenAPI/send parity, and membership provenance.

`fake_smoke.rs` verifies the typed Microsoft mapping/link CLI commands use the
canonical routes and JSON bodies and reject malformed UUIDs before making a
request. Portal Vitest tests cover the Microsoft login/link-control helper, and
the Playwright suite covers Microsoft login availability, provider-outage
presentation, sanitized return paths, and start redirects.

### Audit store and viewer matrix

Audit storage and query coverage is deterministic and uses temporary audit
databases and files:

- Core config tests (`lib_tests.rs`) cover `[audit]` `type`/`path`, unknown-field
  rejection, `rotate_bytes` only for JSONL, an audit path equal to the
  managed-store database, and offline `deployment.node_id` validation;
  `node_identity.rs` covers the host-name default.
- Backend-neutral writer tests in `runtime/tests.rs` run against both backends:
  queue saturation, terminal capacity, shutdown drain, readiness, per-class
  failure tracking, and a fresh UUIDv7 `auditId` plus `nodeId` on every record.
  JSONL retention tests keep the state lock file and other non-rotated files.
- `runtime/audit_sqlite/tests.rs` covers file and sidecar permissions, symlink
  refusal, migration from empty, unknown migrations, catalog-only open checks,
  `database_id` persistence, batching limits (257 records, the 16 MiB split, an
  oversized record), acknowledgement after commit, and `audit verify`. A lock
  probe (`sqlite_support/lock_probe.rs`) re-runs the test binary to read SQLite's
  `-shm` dead-man-switch and database shared locks with `fcntl(F_GETLK)` from
  another process, proving that startup, reload admission beside a live
  generation, and recovery's permission repair keep them; the same probe covers
  managed-store startup and reload opens and `restrict_sqlite_files`. An online
  backup from another process while the writer appends leaves the live database
  intact and every acknowledged record in a later backup. Fault
  injection (a test-only commit-failure hook and `max_page_count` for a full
  database) proves fail-closed appends, blocked supervised dispatch, independent
  failure classes, the one-per-second recovery rate, and recovery without a
  restart. Maintenance tests cover chunked deletes with their full-text rows,
  appends acknowledged between slices, a checkpoint deferred by a reader, and
  persistent optional-slice failures that never affect readiness.
- `runtime/audit_sqlite/query_tests.rs` covers each filter, action prefixes,
  time bounds, literal full-text terms, phrases, and prefixes, ordering and
  cursor paging, query plans that use each filter's index, and the reader
  pool: deadlines while waiting and executing, admission overflow, disconnect
  interrupts that cannot reach the next query, generation drain, and no read
  transaction left open.
- The broker suite `crates/agent-access-broker-host/src/tests/audit_query.rs`
  (`cargo test -p agent-access-broker-host audit_query`) covers route availability
  with SQLite, JSONL, and disabled audit or management across the catalog,
  OpenAPI, and send schema; `auditQueryable`; CSRF-free browser reads; the
  admin, service-manager, and self visibility tiers; timelines; cursor
  continuation and binding, including a path-changing reload; successes that
  are neither audited nor logged; audited denials; busy and slow queries; and
  queries while audit writes fail.
  `crates/agent-access-broker-host/src/tests/management_read_audit.rs`
  (`cargo test -p agent-access-broker-host management_read_audit`) calls every
  read route in the runtime catalog and checks that it answers with its
  classified operation and leaves an audit record exactly when it is an
  audited read, denied, or failed; that the portal page-load reads and
  representative admin reads and policy dry runs write no records; and that
  they keep working while audit writes fail. The unit test
  `every_management_read_route_has_an_audit_classification` requires every
  catalog read route to be classified as an unaudited or audited read. Broker
  reload tests cover
  restart-only type and node ID changes and path changes, `login_lockout.rs`
  covers the failed-login principal, and `tests/state_locks.rs` covers the
  `audit verify` lock and usage errors.
- Portal unit tests cover navigation gating and URL filter state; Playwright
  covers the admin Audit page, the service-manager view, user Activity, and
  hidden navigation with a JSONL backend.

Ignored scale tests measure the performance targets on developer hardware; they
are not CI gates. Run them only in a release build, where the bundled SQLite is
optimized, and record the results in the pull request:

```bash
cargo test --release -p agent-access-core --lib scale_ -- --ignored --nocapture
cargo test --release -p agent-access-core --lib audit_query_scale -- --ignored --nocapture
```

The targets are at least 2,000 acknowledged records per second with
`durability = "write"`, a 100,000-row retention prune that delays no
acknowledgement by more than 250 ms, and, over 1,000,000 records spread across
30 days, a first page filtered by any single indexed column in under 250 ms and
a single-term search in under 500 ms.

## Live Smoke Setup

Live smoke tests require a live broker that is already configured with suitable
provider credentials and policy grants. Keep live credentials, token files, env
files, customer hostnames, page IDs, issue keys, and site-specific manifests
outside the repository.

For the manual operator workflow around starting a live smoke broker, preparing
managed grants and tokens, enabling attribution, and running targeted mutating
CLI commands, see `docs/manual-live-smoke.md`.

Use the CLI's normal token resolution for live tests:

```bash
export AGENT_ACCESS_TOKEN_FILE=/secure/path/agent-access-token
# or:
export AGENT_ACCESS_TOKEN=broker-identity-token
# or:
export AGENT_ACCESS_CONFIG=/secure/path/agent-access.toml
```

`AGENT_ACCESS_TOKEN_FILE` may use a leading `~/` for the current user's home
directory. Keep smoke-test token files outside the repository and avoid
world-readable locations.

Do not use `--token-value` in live smoke documentation or conformance commands.
Do not send identity tokens to a remote plaintext HTTP broker. Plain HTTP is only
appropriate for local loopback development unless `agent-access` is explicitly
run with the insecure-HTTP override for a controlled development case.

The examples below use placeholder paths and resource identifiers. Replace them
with values from your external test setup.

## Jira Live Smokes

### Read Smoke

```bash
AGENT_ACCESS_REAL_BROKER_URL=https://broker.example \
AGENT_ACCESS_REAL_JIRA_ISSUE=PROJ-123 \
AGENT_ACCESS_REAL_JIRA_PROJECT=PROJ \
AGENT_ACCESS_REAL_JIRA_COMMENT_ID=10042 \
cargo test -p agent-access --test real_jira_smoke \
  real_broker_jira_read_smoke -- --ignored --exact
```

The read smoke exercises one representative Jira ADF body in embedded
Markdown/text mode and one body-free search or list in whole-result Markdown
mode. It asserts that omitted presentation options preserve native JSON,
`readContentFormat` preserves the native body while adding the correctly placed
`renderedBody`, and `responseFormat=markdown` returns the bounded Markdown result
wrapper. The typed CLI prints only the Markdown value, while direct HTTP and
JSON `send` retain the normal JSON envelope. The smoke also confirms search
stays body-free and that native and rendered sentinels are absent from audit.

### Write, Download, And Verify Smoke

This mutates the configured issue.

```bash
AGENT_ACCESS_REAL_BROKER_URL=https://broker.example \
AGENT_ACCESS_REAL_JIRA_ISSUE=PROJ-123 \
AGENT_ACCESS_REAL_JIRA_COMMENT_CONTENT_FILE=/secure/path/comment.md \
AGENT_ACCESS_REAL_JIRA_COMMENT_CONTENT_FORMAT=markdown \
AGENT_ACCESS_REAL_JIRA_ATTACHMENT_FILE=/secure/path/attachment.txt \
AGENT_ACCESS_REAL_JIRA_ATTACHMENT_CONTENT_TYPE=text/markdown \
cargo test -p agent-access --test real_jira_smoke \
  real_broker_jira_write_stream_verify_smoke -- --ignored --exact
```

The mutating Jira smoke creates a top-level Markdown or plain-text comment with
`jira issue comment add`, creates a threaded reply with `jira issue comment
reply`, updates comments
with `notifyUsers=false`, sets/gets/deletes an
`agent-access.real-smoke` comment property, uploads/downloads an attachment,
verifies the created objects, and deletes the created reply and parent comment.

Issue summary/description update has a separate ignored live smoke because it
mutates issue fields. Use a throwaway issue and an explicitly formatted content
file:

```bash
AGENT_ACCESS_REAL_BROKER_URL=https://broker.example \
AGENT_ACCESS_REAL_JIRA_UPDATE_ISSUE=PROJ-123 \
AGENT_ACCESS_REAL_JIRA_UPDATE_CONTENT_FILE=/secure/path/description.md \
AGENT_ACCESS_REAL_JIRA_UPDATE_CONTENT_FORMAT=markdown \
cargo test -p agent-access --test real_jira_smoke \
  real_broker_jira_issue_update_smoke -- --ignored --exact
```

The smoke reads the original summary and current description, updates the
summary, restores the original summary, updates the description from normalized
content,
and asserts sanitized issue metadata, changed field names, browser URLs, and
description-bearing readback.

Issue create has a separate ignored live smoke because it creates new issues in
the approved project. Use a throwaway approved project and an issue type that
does not require custom fields beyond project, issue type, summary, and optional
rich-content description. Grant `issue_type.list` as well as `issue.create` and
obtain the selected type ID from discovery using the same Jira credential:

```bash
agent-access --url https://broker.example jira issue-type list --project PROJ
```

Follow `nextStartAt` by passing `--start-at` until `isLast` is true. Copy a
returned non-subtask `id` into `AGENT_ACCESS_REAL_JIRA_CREATE_ISSUE_TYPE_ID`;
the value below is only an example:

```bash
AGENT_ACCESS_REAL_BROKER_URL=https://broker.example \
AGENT_ACCESS_REAL_JIRA_CREATE_PROJECT=PROJ \
AGENT_ACCESS_REAL_JIRA_CREATE_ISSUE_TYPE_ID=10001 \
AGENT_ACCESS_REAL_JIRA_CREATE_CONTENT_FILE=/secure/path/description.md \
AGENT_ACCESS_REAL_JIRA_CREATE_CONTENT_FORMAT=markdown \
cargo test -p agent-access --test real_jira_smoke \
  real_broker_jira_issue_create_smoke -- --ignored --exact
```

The smoke first walks the project's issue-type metadata pages (at most 100),
checks names, decimal-string IDs, descriptions and subtask flags, and requires
the selected ID to be present before any creation. It then creates one
summary-only issue and one issue with normalized content,
then asserts key/project, browser URL, summary, status, issue type, description
readback, and that the broker returns readback metadata rather than the raw Jira
create response. If Jira rejects the create because the project or issue type
requires additional fields, choose a throwaway project/type that matches the
broker-owned create contract before rerunning.

Issue child create has a separate ignored live smoke because it creates new
parented issues. Configure a standard-child-under-Epic case, a
subtask-under-parent case, or both. When only one case is configured, the smoke
prints which case it exercised:

```bash
AGENT_ACCESS_REAL_BROKER_URL=https://broker.example \
AGENT_ACCESS_REAL_JIRA_CHILD_STANDARD_PROJECT=PROJ \
AGENT_ACCESS_REAL_JIRA_CHILD_STANDARD_ISSUE_TYPE_ID=10001 \
AGENT_ACCESS_REAL_JIRA_CHILD_EPIC_ISSUE=PROJ-100 \
AGENT_ACCESS_REAL_JIRA_CHILD_SUBTASK_PROJECT=PROJ \
AGENT_ACCESS_REAL_JIRA_CHILD_SUBTASK_ISSUE_TYPE_ID=10003 \
AGENT_ACCESS_REAL_JIRA_CHILD_SUBTASK_PARENT_ISSUE=PROJ-124 \
cargo test -p agent-access --test real_jira_smoke \
  real_broker_jira_issue_child_create_smoke -- --ignored --exact
```

The smoke calls `jira issue child create`, then asserts
`verification.status=matched`, matching parent issue keys, and that the broker
returns readback metadata rather than the raw Jira create response.

Issue parent assignment has a separate ignored live smoke because it mutates
existing child issues. Configure a standard-issue-to-Epic case, a
subtask-to-parent case, or both. When only one case is configured, the smoke
prints which case it exercised:

```bash
AGENT_ACCESS_REAL_BROKER_URL=https://broker.example \
AGENT_ACCESS_REAL_JIRA_PARENT_STANDARD_ISSUE=PROJ-124 \
AGENT_ACCESS_REAL_JIRA_PARENT_EPIC_ISSUE=PROJ-100 \
AGENT_ACCESS_REAL_JIRA_PARENT_SUBTASK_ISSUE=PROJ-125 \
AGENT_ACCESS_REAL_JIRA_PARENT_SUBTASK_PARENT_ISSUE=PROJ-126 \
cargo test -p agent-access --test real_jira_smoke \
  real_broker_jira_issue_parent_smoke -- --ignored --exact
```

The smoke calls `jira issue parent set`, then asserts
`verification.status=matched` and matching child/parent issue keys in each
broker response.

Issue dependency linking has a separate ignored live smoke because it mutates
relationships between two issues. Use disposable issues that the broker policy
authorizes, preferably before they have any dependency link between them:

```bash
AGENT_ACCESS_REAL_BROKER_URL=https://broker.example \
AGENT_ACCESS_REAL_JIRA_DEPENDENCY_BLOCKING_ISSUE=PROJ-123 \
AGENT_ACCESS_REAL_JIRA_DEPENDENCY_BLOCKED_ISSUE=PROJ-124 \
cargo test -p agent-access --test real_jira_smoke \
  real_broker_jira_issue_dependency_smoke -- --ignored --exact
```

The smoke calls `jira issue dependency add`, then asserts `status=present`,
`verification.status=matched`, and matching blocking/blocked issue keys in the
broker response.

Deterministic Jira normalized-read coverage asserts the common top-level
`readContentFormat` (`native`, `markdown`, `text`) and `responseFormat` (`json`,
`markdown`) contract across catalog, OpenAPI, action-specific send schema,
typed CLI, generic `invoke`, JSON `send`, multipart/direct HTTP, and provider
execution. Omission and explicit defaults preserve the exact native JSON shape;
unknown top-level fields and mutually exclusive non-native embedded plus
whole-Markdown requests return `input_invalid`/400. A representation not
advertised by the resolved action returns
`response_format_unsupported`/415 after identity/token admission but before
policy authorization, credential selection, or provider access. Projection
tests also require every action-specific OpenAPI/send invoke schema to accept
explicit `native`/`json` protocol defaults when capability arrays are absent.

Jira descriptor completeness tests enumerate every declared issue-description
and comment-body result path, including mutation readbacks. They assert that
Markdown/text rendering preserves native ADF and adds one correctly placed
`renderedBody` for present content, distinguishes missing/null from
present-empty bodies, never guesses similarly named or arbitrary property
fields, and keeps body-free search/list results body-free. Golden and
adversarial ADF tests cover every supported node and mark, safe and unsafe
links, unknown-container and unknown-leaf fallbacks, malformed roots, Unicode,
depth/node/work/output boundaries, deterministic LF output, no truncation, no
panic, and no network access.

Capability projection tests require `readContentFormats` on exactly
`issue.view`, `issue.create`, `issue.update`, `comment.view`, `comment.add`,
`comment.reply`, and `comment.update`. They require `responseFormats` on exactly
`issue_type.list`, `issue.view`, `search`, `comment.list`, `comment.view`,
`comment.property.list`, `comment.property.get`, `attachment.list`, and
`verify`. Representative child-create, property mutation, attachment mutation,
and raw-download actions assert absence rather than accepting a compatibility
fallback.

Whole-result contract snapshots cover every eligible Jira retrieval family:
project issue-type metadata, singleton issue/comment, body-free search, metadata-only comment and attachment
lists, comment-property list/get with arbitrary JSON, verification success, and
the `allow_with_result` verification mismatch. Assertions require stable field
and collection ordering, exact identifiers/timestamps/URLs/booleans/counts and
pagination tokens, omission of absent/null fields, one terminal newline, no raw
ADF, and the same provider request count, endpoint, query, selected fields, and
pagination inputs as JSON mode. Mutations and raw attachment downloads must not
advertise whole-result Markdown. Renderer snapshots also require identifiers and
timestamps as code spans, safe URLs as autolinks, neutralized metadata controls
and newlines, and fenced preservation of valid JSON-null property values.

CLI tests derive each Jira command's presentation flags from compiled catalog
capabilities. They verify `--read-content-format` appears on declared embedded
read and mutation-readback actions, `--output-format` appears only on eligible
retrievals, unsupported presentation flags are rejected, and JSON is the default.
They also cover command/config/environment/built-in precedence, invalid ambient
values, omission of unsupported ambient defaults (including a caller-filtered
catalog that omits the action), local rejection of explicit unsupported flags,
whole-Markdown suppression of ambient embedded formatting, generic-invoke
catalog-fetch behavior, shared core contract validation, no ambient
injection by `send`, Markdown-only successful stdout, JSON errors, existing
`allow_with_result` exit policy, and exit 5 for malformed promised response
shapes.

Bounds and observability tests apply Jira `max_body_bytes` to every declared
native body even in omitted or explicit-native mode, plus traversal, rendered,
aggregate, whole-document, and final-result limits. Malformed or oversized Jira
read content returns sanitized `upstream_protocol_failed`/502 without partial
stdout or a second provider request, including for oversized returned descriptions. Unique
native/rendered/property/pagination/link sentinels must remain absent from audit
JSONL, tracing/log captures, errors, object identifiers, and metric labels.

Deterministic Confluence normalized-read coverage uses the same top-level
protocol and capability checks. Descriptor tests enumerate exactly 26 embedded
actions across page/blog/draft views, body-bearing comment/reply collections,
comment views, and mutation readbacks. They cover root, wrapped, and collection
placement; bare `blog.view.body.storage`; empty/missing representation maps;
present-empty bodies; and deterministic ADF-before-storage selection. Serialized
ADF source bytes are bounded before one parse, and malformed selected ADF fails
without falling back to storage.

Confluence storage golden/adversarial tests cover standard HTML, namespaced
`ac:`/`ri:` references, macros, active-content suppression, entities, unknown
nodes, safe/unsafe links, malformed fragments, depth/event/work/output limits,
determinism, and secrecy of macro parameters and internal identifiers.
Whole-result snapshots cover exactly 26 retrievals: current page/blog
view/search/verify, page/blog draft view/verify, current/draft attachment lists,
and all page/blog footer/inline comment list/view/reply-list reads. They verify
that body-free actions stay body-free, collection bodies are converted in
place, `allow_with_result` verification semantics survive formatting, and JSON
and Markdown modes make identical upstream requests.

Confluence CLI tests derive presentation flags from capabilities, reject
unsupported flags, and require JSON default output.
Bounds apply `providers.confluence.content.max_body_bytes` to every declared
native body in every mode, plus aggregate, whole-document, and final-result
limits. Malformed or oversized content returns sanitized
`upstream_protocol_failed`/502 without partial output or body-derived audit,
tracing, log, error, object-ID, or metric data.

Deterministic GitLab normalized-read coverage enumerates the declared embedded
action families: issue view/search/create/update and note list/add/update;
merge-request view/search/create/update and note list/add/update; discussion
list/view/general-add/inline-add/note-add/note-update/resolve/reopen; and draft
note list/view/add/update. Contract tests cover singleton and
collection descriptions, note bodies, every nested discussion note, mutation
readbacks, missing/null/present-empty values, byte-exact embedded Markdown,
bounded text extraction, raw-HTML suppression, and non-guessing of file,
commit, job, or similarly named fields.

Whole-result fixtures cover the eligible GitLab retrieval families: project
view; issue view/search/note list; merge-request view/search/note
list/discussion list/view; reviewer, MR commit, MR pipeline, current structured
diff, diff-version, draft-note list/view, approval summary/state, and
approval-rule list/view reads;
branch and protected-branch list/view; protected-branch verify; file view;
commit list/view; pipeline list/view; and job list/view. They assert semantic
field completeness and stable ordering, body-bearing search/list behavior,
nested-note structure, collision-safe literal commit messages and file base64,
ordinary protected-branch verification results, exact pagination metadata on
issue/MR searches, note/discussion lists, and every merge-request review-context
collection plus draft-note lists, one terminal LF, and safe closure of
untrusted Markdown before following metadata. Mutations and raw file, MR-diff,
and job-trace streams advertise no whole-result Markdown.

Review-context parser coverage uses one positioned multiline text discussion
to assert note type, exact path/line-range association, normalized suggestion
fields, and fail-closed handling of a malformed present position. HTTP-backend
tests assert the exact reviewer-list, discussion-list, structured-diff,
diff-version-view, and raw-diff routes and their implemented query parameters;
reviewer and discussion fixtures exercise
upstream next-page headers. The real-broker/stub-backend smoke invokes all
eight merge-request review-context read actions, checks commit ID,
SHA/path/line association and resolution
time on a discussion, follows a reviewer continuation token through page two,
checks caller-visible policy narrowing, streams raw diff through the typed CLI,
and asserts that note/suggestion/patch/raw bytes and page tokens stay out of
audit output. Presentation snapshots cover review positions, suggestions,
review readiness, structured diffs, and diff-version literals.

Provider-contract and smoke tests compare native and formatted calls for the
same endpoint, query, filters, page inputs, and upstream call count. CLI tests
derive GitLab flags from the shared capability registry and exercise typed,
generic invoke, send, and HTTP behavior plus config/environment precedence.
Bounds cover every native body in all modes, parsing work, per-body/aggregate
rendered output, whole-result output, and GitLab's common final serialized
result cap. Unique description/note/rendered/base64/pagination sentinels remain
absent from audit, tracing, logs, errors, object IDs, and metric labels; all
limit or parse failures are fixed sanitized
`upstream_protocol_failed`/502 without partial output or an extra provider
request.

Deterministic Jira write coverage spans all six normalized actions:
`issue.create`, `issue.child.create`, `issue.update`, `comment.add`,
`comment.reply`, and `comment.update`. Contract tests assert catalog,
OpenAPI/send-schema, typed CLI, and provider parity for `adf`, `markdown`, and
`plain_text`; exact-one-of inline/file source handling; required/optional
pairing; config-aware comment action omission; conversion and attribution
ordering; source/conversion/final byte bounds; `body_size_denied`/413 and
`body_format_unsupported`/415; no upstream call on validation failure; and
absence of unique source/native sentinels from audit and tracing.

Deterministic Confluence normalized-write coverage spans all twenty current
page/blog, draft, footer-comment, inline-comment-update, and reply mutations.
Contract tests assert exact catalog/OpenAPI/send-schema parity; canonical
`content`/`contentFormat` typing; typed inline/file handling; native storage and
ADF plus normalized Markdown/plain-text conversion; config-aware format enums
and action omission; conversion/attribution/final-validation ordering; source,
conversion, and final byte bounds; 413/415 failures without upstream calls; and
content exclusion from audit, tracing, errors, and object identifiers. The
512 MiB CLI file ceiling is tested separately from lower provider limits.

Deterministic GitLab normalized-write coverage spans all sixteen issue/MR
description, note, discussion, and draft mutations that accept body content or
an optional summary. Contract tests assert exact
catalog/OpenAPI/send-schema and typed CLI parity; required/optional pairing;
Markdown identity; literal plain-text escaping for CommonMark punctuation, raw
HTML, mentions, issue/MR references, autolinks, and GitLab extensions;
conversion/attribution/final-limit ordering; the twelve-action attribution
boundary (with all note updates and draft-note update excluded); source and
final 413 failures without upstream calls; and
source/native sentinel exclusion from audit, tracing, errors, and object IDs.
Repository-file actions remain outside the rich-content matrix.
Quick-action tests reject the fixed command-line grammar outside fences before
upstream work while preserving commands in fenced code and suggestion blocks,
inline prose, URLs, Unix paths, and slash-containing Markdown. The review
attribution subset is exactly direct inline add, reply add, draft add,
publish-all summary, and review-submit summary.

Merge-request review mutation coverage exercises current text, multiline,
file, and image positions; complete non-null base/start/head SHA triplets;
expected-head conflicts and stale coordinates; multiline patch proof and the
safe `coordinates_unresolved`/`patch_unavailable` categories; replies to
outdated discussions; current-owner draft list/view/add/update/delete and
single/all publication; and per-user versus shared service-account ownership.
Draft-list fixtures model GitLab's one non-paginated array and prove Broker-
local slicing without sending pagination query parameters upstream. Generic
signed-pagination tests prove token scope and cap binding; there are no
draft-specific response-cap or concurrent-mutation tests.
Image fixtures accept nonnegative integer x/y and reject fractional, negative,
or otherwise invalid values before mutation. Diff-version
`overflow`/`without_files` states assert
`patch_unavailable` without upstream mutation.
It proves that `review.submit` checks GitLab 19.2 or newer before mutation,
maps an unassigned reviewer to `version_conflict`, rejects formal approval or
reviewer state `approved`, permits a zero-draft
summary, distinguishes `requested_changes` from approval, and verifies the
acting user's final reviewer state.
Tests and examples must not treat `requested_changes` as proof that merging is
blocked; that outcome is Premium/Ultimate and project-configuration dependent.

Formal-approval coverage checks free-tier summary fields and edition-dependent
aggregate semantics, Premium/Ultimate state/rule fields and tier failures,
actor lookup, exact-head and collected-diff readiness, hard null-`patchIdSha`
blocking, and the unchanged empty/legacy-diff limitation. Approve/unapprove
readback proves the acting user through `approvedBy` and
`userHasApproved` when present; aggregate `approved` alone is never accepted as
proof.

Suggestion coverage proves scoped discussion/note/suggestion association,
applicability and expected position head, unique batch size `1..=100`, bounded
commit-message template input and GitLab placeholder/default-trailer behavior,
and no implicit discussion resolution or commit metadata. It exercises stale
`applied = false` mutation responses followed by successful scoped reread, plus
missing/contradictory/still-unapplied readback as
`mutation_verification_failed`. Same-project scope deduplication and fork
target+source authorization require one all-covering grant; tests prove grants
cannot be combined and that hidden/changed source identity fails before the
global endpoint.

Every review mutation is checked with a post-write readback and is never retried
automatically. Tests force accepted-but-unverifiable writes to return HTTP 409,
`decision = error`, `reasonCode = mutation_verification_failed`, CLI exit 2,
`retrySafe = false`, and only closed safe locators in `result`. Body, summary,
patch, line-code, token, and attribution sentinels must remain absent from audit,
tracing, logs, errors, object IDs, and metric labels.
For direct and single-item mutations, an upstream 5xx after the request is
asserted as the same applied-unverified 409 outcome. Publish-all and
review-submit tests also cover their readback branch: an ordinary sanitized
upstream failure is permitted only when the draft snapshot and reviewer state
prove unchanged; any possible effect remains applied-unverified.

### Per-User Smoke

This requires a per-user grant and credential, and mutates the configured issue.
Supply the per-user agent token through a smoke-specific token source. The test
passes that source to the CLI as `--token-env` or `--token-file`, never as a
literal token value. `--token-file` may use a leading `~/` if the smoke runner's
home directory is the intended secret location.

```bash
PER_USER_AGENT_TOKEN=broker-identity-token \
AGENT_ACCESS_REAL_JIRA_PER_USER_TOKEN_ENV=PER_USER_AGENT_TOKEN \
AGENT_ACCESS_REAL_BROKER_URL=https://broker.example \
AGENT_ACCESS_REAL_JIRA_PER_USER_ISSUE=PROJ-123 \
AGENT_ACCESS_REAL_JIRA_PER_USER_PROJECT=PROJ \
AGENT_ACCESS_REAL_JIRA_PER_USER_COMMENT_CONTENT_FILE=/secure/path/comment.md \
AGENT_ACCESS_REAL_JIRA_PER_USER_COMMENT_CONTENT_FORMAT=markdown \
AGENT_ACCESS_REAL_JIRA_PER_USER_ATTACHMENT_FILE=/secure/path/attachment.txt \
AGENT_ACCESS_REAL_JIRA_PER_USER_ATTACHMENT_CONTENT_TYPE=text/markdown \
cargo test -p agent-access --test real_jira_smoke \
  real_broker_jira_per_user_smoke -- --ignored --exact
```

Alternatively, set `AGENT_ACCESS_REAL_JIRA_PER_USER_TOKEN_FILE` to a token file
path instead of `AGENT_ACCESS_REAL_JIRA_PER_USER_TOKEN_ENV`.

## GitLab Live Smokes

`real_gitlab_smoke` contains exactly ten ignored, exact-filtered live tests.
Use a broker already configured with the necessary GitLab credential, repository
scope, per-action grants, and normal CLI identity-token resolution described in
[Live Smoke Setup](#live-smoke-setup). The complementary operator walkthrough is
the [GitLab Smoke Matrix](manual-live-smoke.md#gitlab-smoke-matrix).

Never run this binary with a broad `-- --ignored`. Supply the variables listed
for the one exact test being run; the test does not infer alternate
`AGENT_ACCESS_REAL_GITLAB_*` variables.

| Variable | Used by | Meaning |
| --- | --- | --- |
| `AGENT_ACCESS_REAL_GITLAB_PROJECT` | context/approval reads | Canonical repository path containing the configured review MR. |
| `AGENT_ACCESS_REAL_GITLAB_MERGE_REQUEST_IID` | context/approval reads | Positive IID of that MR. |
| `AGENT_ACCESS_REAL_GITLAB_POSITIONED_DISCUSSION_ID` | context read | Discussion ID whose returned notes contain a valid positioned text note. |
| `AGENT_ACCESS_REAL_GITLAB_APPROVAL_RULE_ID` | approval-rule read | Positive ID of a configured rule on the Premium/Ultimate MR. |
| `AGENT_ACCESS_REAL_GITLAB_MUTATION_PROJECT` | mutation target and suggestion read | Canonical target-project repository path for the explicitly disposable MR. |
| `AGENT_ACCESS_REAL_GITLAB_MUTATION_MERGE_REQUEST_IID` | mutation target and suggestion read | Positive IID of the explicitly disposable MR. |
| `AGENT_ACCESS_REAL_GITLAB_MUTATION_SOURCE_BRANCH` | mutation target and suggestion read | Exact throwaway source branch; broker preflight must match it. |
| `AGENT_ACCESS_REAL_GITLAB_MUTATION_EXPECTED_HEAD_SHA` | mutation target and suggestion read | Current full 40-character head SHA; preflight requires both MR `sha` and `diffRefs.headSha` to match. |
| `AGENT_ACCESS_REAL_GITLAB_MUTATION_SOURCE_PROJECT` | suggestion apply | Canonical repository path that owns the throwaway MR source branch. |
| `AGENT_ACCESS_REAL_GITLAB_SUGGESTION_DISCUSSION_ID` | suggestion read/apply | Exact discussion containing the configured unapplied suggestion. |
| `AGENT_ACCESS_REAL_GITLAB_SUGGESTION_NOTE_ID` | suggestion read/apply | Positive note ID containing that suggestion. |
| `AGENT_ACCESS_REAL_GITLAB_SUGGESTION_ID` | suggestion read/apply | Positive applicable, unapplied suggestion ID. |
| `AGENT_ACCESS_REAL_GITLAB_MUTATION_OLD_PATH` | positioned mutations | Current diff position's old path. |
| `AGENT_ACCESS_REAL_GITLAB_MUTATION_NEW_PATH` | positioned mutations | Current diff position's new path. |
| `AGENT_ACCESS_REAL_GITLAB_MUTATION_NEW_LINE` | positioned mutations | Positive current new-side line that accepts a positioned note. |
| `AGENT_ACCESS_REAL_GITLAB_MUTATION_CONTENT_FILE` | positioned mutations | Readable, nonempty UTF-8 Markdown file of at most 4096 bytes. |
| `AGENT_ACCESS_REAL_GITLAB_INLINE_REPLY_CONFIRM` | inline/reply | Must equal the exact sentinel `throwaway-inline-reply`. |
| `AGENT_ACCESS_REAL_GITLAB_DRAFT_REVIEW_CONFIRM` | draft/review | Must equal the exact sentinel `throwaway-draft-review`. |
| `AGENT_ACCESS_REAL_GITLAB_REVIEWER_STATE` | draft/review | Exactly `reviewed` or protocol value `requestedChanges`. |
| `AGENT_ACCESS_REAL_GITLAB_APPROVE_UNAPPROVE_CONFIRM` | approve/unapprove | Must equal the exact sentinel `throwaway-approve-unapprove`. |
| `AGENT_ACCESS_REAL_GITLAB_SUGGESTION_APPLY_CONFIRM` | suggestion apply | Must equal the exact sentinel `throwaway-single-suggestion`. |
| `AGENT_ACCESS_REAL_GITLAB_WEBHOOK_PROJECT` | webhook read | Canonical repository path containing the configured existing webhook. |
| `AGENT_ACCESS_REAL_GITLAB_WEBHOOK_ID` | webhook read | Positive ID of the configured existing webhook. |
| `AGENT_ACCESS_REAL_GITLAB_WEBHOOK_MUTATION_PROJECT` | webhook lifecycle | Canonical repository path of the explicitly disposable webhook project. |
| `AGENT_ACCESS_REAL_GITLAB_WEBHOOK_RECEIVER_URL` | webhook lifecycle | Explicit HTTP(S) receiver URL allowed by Broker TOML and safe for test plus duplicate resend delivery. |
| `AGENT_ACCESS_REAL_GITLAB_WEBHOOK_LIFECYCLE_CONFIRM` | webhook lifecycle | Must equal the exact sentinel `throwaway-webhook-lifecycle`. |

`AGENT_ACCESS_REAL_BROKER_URL` is also required by all ten tests, but is the
common live-broker variable rather than a GitLab-specific one.

### Review-Context Read Smoke

The configured MR must have complete current `diffRefs`, at least one stored
diff and diff version, and a discussion containing a valid positioned note.
The smoke reads the MR, current diffs, exact latest diff version, and discussion
and checks full SHA/path/line association.

```bash
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_merge_request_review_context_read_smoke -- --ignored --exact
```

### Approval Read Smokes

The safe summary smoke works with approval API access and performs no mutation.
The rule smoke additionally requires a Premium/Ultimate MR and a configured
rule whose positive ID is supplied exactly:

```bash
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_merge_request_approval_read_smoke -- --ignored --exact

export AGENT_ACCESS_REAL_GITLAB_APPROVAL_RULE_ID=<approval-rule-id>
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_merge_request_approval_rule_read_smoke -- --ignored --exact
```

### Configured Suggestion Read Smoke

Configure the disposable mutation MR/head plus exact suggestion discussion,
note, and suggestion IDs from the table. The suggestion must be applicable,
unapplied, and associated with the configured expected source-branch head. This
test only reads:

```bash
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_merge_request_suggestion_read_smoke -- --ignored --exact
```

### Throwaway Inline And Reply Smoke

This test permanently creates one current positioned discussion and one reply.
The project, MR, source branch, expected head, path tuple, and line must all name
an explicitly disposable target. The preflight requires a prepared MR
(`preparedAt` present and `detailedMergeStatus` not `preparing`) and refuses a
stale head, wrong MR, or wrong source branch. Set the confirmation exactly:

```bash
export AGENT_ACCESS_REAL_GITLAB_INLINE_REPLY_CONFIRM=throwaway-inline-reply
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_throwaway_inline_reply_smoke -- --ignored --exact
```

### Throwaway Draft And Review-Submit Smoke

This test creates and publishes one positioned draft, creates a second, then
submits it while changing reviewer state. Use a truly throwaway project, MR,
and source branch on GitLab 19.2 or newer. The selected credential owner must be
an assigned reviewer without a formal approval or reviewer state `approved`.
Set both guards exactly; choose one supported state:

```bash
export AGENT_ACCESS_REAL_GITLAB_DRAFT_REVIEW_CONFIRM=throwaway-draft-review
export AGENT_ACCESS_REAL_GITLAB_REVIEWER_STATE=requestedChanges
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_throwaway_draft_review_submit_smoke -- --ignored --exact
```

### Throwaway Formal Approve And Unapprove Smoke

This test approves and then unapproves only an explicitly disposable MR. The
configured execution user must not already have approved and GitLab must not
report `userCanApprove = false`. Set the destructive confirmation exactly:

```bash
export AGENT_ACCESS_REAL_GITLAB_APPROVE_UNAPPROVE_CONFIRM=throwaway-approve-unapprove
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_throwaway_formal_approve_unapprove_smoke -- --ignored --exact
```

### Throwaway Single-Suggestion Apply Smoke

This test permanently commits one configured suggestion to the disposable
source branch. Configure the mutation target, canonical source project, and
exact suggestion locators, then set the confirmation exactly:

```bash
export AGENT_ACCESS_REAL_GITLAB_SUGGESTION_APPLY_CONFIRM=throwaway-single-suggestion
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_throwaway_single_suggestion_apply_smoke -- --ignored --exact
```

All five mutation tests independently enforce their exact test name plus the
test harness `--exact` flag before they invoke the broker. Request bodies are
written to mode-0600 temporary JSON files, and failure diagnostics intentionally
suppress response content.

### Project Webhook Live Verification

The read smoke lists and views one configured existing hook without mutation:

```bash
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_webhook_read_smoke -- --ignored --exact
```

The lifecycle smoke creates one push hook, sets a generated disposable custom
header, triggers and inspects a delivery, resends that exact event, and deletes
the header and hook. Its cleanup guard makes a best-effort hook deletion after
an intermediate assertion failure. Use only a disposable project and receiver
that can safely accept the initial and duplicate deliveries. Configure the
Broker destination allowlist before startup; do not widen a shared deployment
solely for a smoke. Grant the required `webhook.*` actions explicitly and set
the destructive confirmation exactly:

```bash
export AGENT_ACCESS_REAL_GITLAB_WEBHOOK_LIFECYCLE_CONFIRM=throwaway-webhook-lifecycle
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_throwaway_webhook_lifecycle_smoke -- --ignored --exact
```

Verify create/view/update with an HTTPS receiver, then set a masked custom
header from an env/file/stdin source. Confirm the value never appears in CLI
output, audit, or service logs. Test one supported event, list recent delivery
events, and resend only a delivery whose receiver can safely accept a duplicate.
Event rows must omit the upstream URL, redact sensitive/custom-header values,
and mark any bounded truncation. Exercise HTTP or disabled TLS only in an
isolated deployment whose TOML explicitly permits it.

For existing-hook behavior, temporarily remove that destination from an
isolated Broker's allowlist and reload. Confirm list/view, URL-preserving
update, test, event list/resend, and delete remain governed only by their
grants, while create and URL change fail with
`webhook_destination_denied`. Restore configuration after the smoke. Delete
the disposable hook last and retain request IDs plus sanitized results; never
record receiver secrets or delivery bodies in evidence.

## Confluence Live Smokes

### Read Smoke

```bash
AGENT_ACCESS_REAL_BROKER_URL=https://broker.example \
AGENT_ACCESS_REAL_CONFLUENCE_PAGE_ID=123456 \
AGENT_ACCESS_REAL_CONFLUENCE_SPACE=ENG \
cargo test -p agent-access --test real_confluence_smoke \
  real_broker_confluence_read_smoke -- --ignored --exact
```

Optional inputs:

- `AGENT_ACCESS_REAL_CONFLUENCE_CQL`
- `AGENT_ACCESS_REAL_CONFLUENCE_PAGE_URL`
- `AGENT_ACCESS_REAL_CONFLUENCE_TENANT_HOST` to assert the returned
  `webUrl`/`spaceUrl` host exactly.

The read smoke asserts page view and page search return browser-shaped
`webUrl` and `spaceUrl` values. It also exercises one storage/ADF body in
embedded Markdown/text mode and body-free search in whole-result Markdown,
asserting that the native body is unchanged, `renderedBody` is beside `body`,
and the Markdown search performs no additional fetch. Configure the CQL so it
returns at least one page in the target space.

### Write, Download, And Verify Smoke

This mutates the configured space and update page.

```bash
AGENT_ACCESS_REAL_BROKER_URL=https://broker.example \
AGENT_ACCESS_REAL_CONFLUENCE_SPACE=ENG \
AGENT_ACCESS_REAL_CONFLUENCE_CREATE_TITLE='Agent Access Smoke Page' \
AGENT_ACCESS_REAL_CONFLUENCE_CREATE_CONTENT_FILE=/secure/path/page.md \
AGENT_ACCESS_REAL_CONFLUENCE_CREATE_CONTENT_FORMAT=markdown \
AGENT_ACCESS_REAL_CONFLUENCE_UPDATE_PAGE_ID=123456 \
AGENT_ACCESS_REAL_CONFLUENCE_UPDATE_BASE_VERSION=7 \
AGENT_ACCESS_REAL_CONFLUENCE_UPDATE_CONTENT_FILE=/secure/path/update.md \
AGENT_ACCESS_REAL_CONFLUENCE_UPDATE_CONTENT_FORMAT=markdown \
AGENT_ACCESS_REAL_CONFLUENCE_ATTACHMENT_FILE=/secure/path/attachment.txt \
AGENT_ACCESS_REAL_CONFLUENCE_ATTACHMENT_CONTENT_TYPE=text/markdown \
cargo test -p agent-access --test real_confluence_smoke \
  real_broker_confluence_write_stream_verify_smoke -- --ignored --exact
```

Optional input:

- `AGENT_ACCESS_REAL_CONFLUENCE_TENANT_HOST` to assert the returned
  `webUrl`/`spaceUrl` host exactly.

The write smoke asserts page create and update return browser-shaped `webUrl`
and `spaceUrl` values. The deterministic `confluence_smoke` and provider tests
cover space-homepage and same-space parent placement, ID and URL locators,
`page.move` before/after/append mutations, hierarchy and `childPosition`
readback, and rejection of mixed/missing locators, self-targeting, cross-space
placement, cycles, and unsupported hierarchy operations.
The manual live-smoke runbook describes optional throwaway-page checks for those
parent-placement flows; the ignored automated live write smoke does not yet run
them.

Confluence comment list/view/add/reply/update/delete coverage is included in
the deterministic `confluence_smoke` test that runs with ordinary `cargo test`.
Before relying on live-tenant behavior for comment mutation endpoints, run a
throwaway-comment broker smoke that updates and deletes page/blog footer and
inline replies without recording comment body text.

Confluence draft unit coverage is deterministic and runs with ordinary
`cargo test`. It covers stable draft-handle signing and binding, draft attachment
pagination token binding, and fail-closed staged-draft attachment/discard gates.
Before enabling draft grants broadly in a live tenant, exercise a throwaway page
and blog through draft create, staged draft creation, view, update, publish,
verify, discard for new drafts, and new-draft attachment upload/list/download.
Exercise page-draft creation both under the default space homepage and under a
same-space parent.
Do not use staged draft attachments, staged discard, attachment delete,
cross-credential draft visibility assumptions, or draft comments as supported
behavior until separate live proof and tests are added.

Content-attribution unit coverage is deterministic and runs with ordinary
`cargo test -p agent-access-core attribution`. It covers provider action glob
resolution, configured-provider validation failures, unconfigured-provider
ignore behavior, ADF footer append/dedupe, Confluence storage marker and visible
footer dedupe, and GitLab Markdown append/dedupe. Provider smoke fixtures that
enable attribution should assert the upstream body includes the broker footer
while CLI request payloads remain unchanged.

### Blog Smoke

This mutates the configured space and update blog post.

```bash
AGENT_ACCESS_REAL_BROKER_URL=https://broker.example \
AGENT_ACCESS_REAL_CONFLUENCE_SPACE=ENG \
AGENT_ACCESS_REAL_CONFLUENCE_BLOG_ID=222222 \
AGENT_ACCESS_REAL_CONFLUENCE_BLOG_CREATE_TITLE='Agent Access Smoke Blog' \
AGENT_ACCESS_REAL_CONFLUENCE_BLOG_CREATE_CONTENT_FILE=/secure/path/blog.md \
AGENT_ACCESS_REAL_CONFLUENCE_BLOG_CREATE_CONTENT_FORMAT=markdown \
AGENT_ACCESS_REAL_CONFLUENCE_BLOG_UPDATE_BASE_VERSION=4 \
AGENT_ACCESS_REAL_CONFLUENCE_BLOG_UPDATE_CONTENT_FILE=/secure/path/blog-update.md \
AGENT_ACCESS_REAL_CONFLUENCE_BLOG_UPDATE_CONTENT_FORMAT=markdown \
AGENT_ACCESS_REAL_CONFLUENCE_BLOG_ATTACHMENT_FILE=/secure/path/blog-attachment.txt \
AGENT_ACCESS_REAL_CONFLUENCE_BLOG_ATTACHMENT_CONTENT_TYPE=text/plain \
cargo test -p agent-access --test real_confluence_smoke \
  real_broker_confluence_blog_smoke -- --ignored --exact
```

Optional inputs:

- `AGENT_ACCESS_REAL_CONFLUENCE_BLOG_CQL`
- `AGENT_ACCESS_REAL_CONFLUENCE_TENANT_HOST` to assert the returned
  `webUrl`/`spaceUrl` host exactly.
- `AGENT_ACCESS_REAL_CONFLUENCE_PROBE_BROWSER_URLS=1` to make the smoke perform
  an unauthenticated browser request to the constructed blog
  `viewpage.action?pageId=...` URL. Use this only with a tenant/page visibility
  setup where browser requests can resolve without an interactive login.

The blog smoke asserts blog search, view, create, and update return
browser-shaped `webUrl` and `spaceUrl` values. It also constructs
`https://{tenant_host}/wiki/pages/viewpage.action?pageId={blogId}` from the
returned blog URL and verifies that `confluence blog view --blog-url` and
`confluence blog attachment list --blog-url` resolve the configured blog post.
The deterministic CLI smoke also covers modern
`/wiki/spaces/{space}/blog/{YYYY}/{MM}/{DD}/{blogId}/...` blog URL locators.
When `AGENT_ACCESS_REAL_CONFLUENCE_PROBE_BROWSER_URLS=1` is set, the smoke also
confirms the constructed browser URL resolves successfully on the configured
tenant. If a tenant does not resolve blog IDs through that `viewpage.action` URL
family, the smoke should fail and blog URL locator/fallback behavior must be
revisited before release.

## Confluence CQL Conformance Smoke

The Confluence CQL conformance smoke is read-only and manifest-driven. It proves
that real Confluence Cloud accepts the broker-emitted CQL field/operator subset
through the public CLI and broker surface.

The checked-in example manifest is shape documentation only:

```text
crates/agent-access/tests/fixtures/confluence-cql-conformance.example.json
```

Copy that file outside the repository, replace fake values with stable tenant
fixtures, and keep the live manifest outside git.

```bash
AGENT_ACCESS_RUN_CONFORMANCE_SMOKE=1 \
AGENT_ACCESS_REAL_BROKER_URL=https://broker.example \
AGENT_ACCESS_CONFLUENCE_CQL_CONFORMANCE_CASES=/secure/path/confluence-cql-cases.json \
AGENT_ACCESS_CONFLUENCE_CQL_CONFORMANCE_REPORT=/secure/path/confluence-cql-report.json \
cargo test -p agent-access --test confluence_cql_conformance_smoke \
  confluence_cql_conformance_smoke -- --ignored --exact
```

Required variables:

| Variable | Meaning |
| --- | --- |
| `AGENT_ACCESS_RUN_CONFORMANCE_SMOKE` | Must be exactly `1`; otherwise the ignored test exits early without failure. |
| `AGENT_ACCESS_REAL_BROKER_URL` | Live broker URL. |
| `AGENT_ACCESS_CONFLUENCE_CQL_CONFORMANCE_CASES` | External JSON manifest path. |

Optional:

| Variable | Meaning |
| --- | --- |
| `AGENT_ACCESS_CONFLUENCE_CQL_CONFORMANCE_REPORT` | JSON report path. Defaults under Cargo's test target temp directory. |

The report is credential-sanitized but not automatically public. It records raw
tenant values only through SHA-256 digests, but case descriptions can still reveal
site-specific intent if the external manifest uses private wording.

A run without `AGENT_ACCESS_RUN_CONFORMANCE_SMOKE=1` only verifies that the
ignored test is safely gated. It does not produce conformance evidence.

The conformance test passes `AGENT_ACCESS_REAL_BROKER_URL` to the child CLI with
`--url` so it overrides any configured `service.url`. This intentionally places
the broker URL in child process arguments; the broker URL is not credential
material, and the durable report still stores only `brokerUrlSha256`.

## Manifest Cases

Manifest shape:

| Field | Required | Meaning |
| --- | --- | --- |
| `version` | yes | Must be `1`. |
| `description` | yes | Non-sensitive suite description. |
| `defaults.spaces` | yes | Default Confluence spaces for cases that omit `spaces`; non-empty. |
| `defaults.maxResults` | yes | Default max result count; greater than `0`. |
| `cases` | yes | Non-empty case array. |
| `cases[].id` | yes | Stable lowercase kebab-case identifier. |
| `cases[].description` | yes | Non-sensitive explanation of what the case proves. |
| `cases[].cql` | yes | Raw caller CQL passed to `confluence page search --cql`. |
| `cases[].spaces` | no | Case-specific spaces; defaults to `defaults.spaces`. |
| `cases[].maxResults` | no | Case-specific max results; defaults to `defaults.maxResults`. |
| `cases[].covers` | yes | Canonical coverage tags declared by this case. |
| `cases[].expect.minPages` | no | Minimum returned page count; default `0`. |
| `cases[].expect.containsPageIds` | no | Page IDs expected in the first result page; default empty. |
| `cases[].expect.expectedUpstreamFailure` | no | Non-sensitive reason for a documented upstream syntax case that is accepted by the broker but currently returns `upstream_failed` from live Confluence Cloud. |

Every conformance case requires:

- `id`: stable lowercase kebab-case identifier
- `description`: non-sensitive explanation of what the case proves
- `cql`: raw caller CQL passed to `confluence page search --cql`
- `covers`: canonical coverage tags satisfied by the case

Optional expectations:

- `minPages`: minimum returned page count
- `containsPageIds`: page IDs expected in the first result page
- `expectedUpstreamFailure`: marks a documented upstream syntax case as an
  accepted live incompatibility when Confluence Cloud currently rejects it

`containsPageIds` cases must use a narrow CQL predicate and a large enough
`maxResults` value for the expected page IDs to appear in the first response
page. The broker clamps the effective search size to
`providers.confluence.search.max_results`, so `minPages` and `containsPageIds`
expectations must stay within that configured cap. The conformance harness does
not paginate.

`expectedUpstreamFailure` is only for Atlassian-published CQL syntax that the
broker accepts and passes through without rewriting, but that the current live
Confluence Cloud endpoint rejects. The case passes only when the child CLI
returns a broker `error` decision with `reasonCode = "upstream_failed"`. If
Atlassian fixes the endpoint and the case starts returning an `allow` decision,
the case becomes a normal pass. Do not use this field for undocumented syntax.

## Artifacts And Evidence

The live manifest plus the sanitized report form the local evidence set. Reports
include:

- manifest and broker URL hashes
- required, declared, and passing-case declared coverage tags
- accepted upstream incompatibility coverage tags
- per-case status, decision, reason code, page count, and page ID hashes
- sanitized setup or case failure summaries

Coverage tags are declared by the manifest author and reviewed as part of the
external fixture. The harness validates that tags are known and that all required
tags are declared, but it does not parse CQL to prove each tag's field/operator
mapping. The report field `passedDeclaredCoverage` therefore means "declared
coverage tags on cases that passed."

When a case uses `expectedUpstreamFailure`, its declared tags appear in
`acceptedUpstreamIncompatibilityCoverage` instead of `passedDeclaredCoverage`.
A suite with only passed cases and expected upstream incompatibilities reports
`status = "passed-with-upstream-incompatibilities"` and exits successfully.

Reports must not include raw tokens, authorization headers, credential usernames,
raw broker URLs, manifest paths, raw spaces, raw CQL, page titles, page bodies,
attachment data, raw stdout, raw stderr, or full command arguments.

## GitLab provisioning smoke

`cargo test -p agent-access --test gitlab_smoke provisioning_` exercises the real
CLI, Broker authorization/catalog, and HTTP GitLab backend against a local
stub server. Coverage includes both provisioning paths, private file delivery,
metadata filtering, issuance caps, ownership denials, pagination, and uncertain
mutation results. It creates no live GitLab accounts or credentials.

## Optional live Codex discovery smoke

After building, run an isolated `codex exec` client against `agent-access mcp
serve` and a temporary local development broker with fake-provider grants. Use
per-process MCP configuration overrides, preserving permanent client settings.
Exercise all five helpers, resource pagination, an unregistered broadly allowed
locator, an excluded locator, exact action schema discovery, and native fake
invocation. Check recovery after a helper argument error and a broker denial.
Inspect the recorded tool-call results rather than relying only on the model's
summary. This validates a real agent client and broker without upstream calls;
it does not establish connectivity to a deployed broker or provider. Remove
temporary tokens/configuration and stop the local broker after the run.

## Downstream HTTP MCP

`cargo test -p agent-access-broker-host --lib tests::mcp::` exercises the real public
router and SDK transport: initialization, helpers, native JSON calls, resource
denials, current bearer authentication, session ownership, reload/expiry,
protocol errors, and request/response bounds. Core ownership tests and Broker
operation-supervisor tests cover explicit cancellation, dropped waiters, retained
execution permits, unknown outcomes, and terminal audit finalization.
Wire regressions also cover policy reloads preserving sessions, security reloads
draining admitted work, cancellation and DELETE after minute quotas are exhausted,
authentication-failure budgets, and short session-idle keepalives. Request-span
tests distinguish the MCP HTTP status from the Broker tool outcome; shutdown
tests allow already accepted JSON request bodies to finish before dispatch.

For native-client validation, run a disposable broker with the development
`fake` backend (`deployment.enable_fake_service = true` plus `[providers.fake]`),
a static bearer token file, one exact TEST resource grant, a private
audit directory, and `/mcp` enabled. Place a streaming loopback TLS reverse proxy
in front, issue a leaf certificate for localhost from a disposable CA, and trust
that CA in the clients (never disable certificate verification). Use isolated
client configuration and temporary credentials, with the documented HTTP MCP
settings. Have each client discover `services_list`, invoke the discovered
`fake.echo` tool for TEST, and invoke it for an ungranted project. Verify one
allow and one deny audit for each client. The synthetic action can be
preauthorized in the client's tool approval policy. No real provider mutation
is needed. Clean up the clients, broker, proxy, tokens, and CA after the run.

## Trusted ingress and managed identity

Broker's deterministic tests exercise the trusted-caller contract without an
external proxy executable or another repository. These commands run a focused
subset of HTTP/MCP/Git admission and shared-runtime caller tests:

```sh
cargo test --locked -p agent-access-broker-host --lib tests::managed_identity
cargo test --locked -p agent-access-core --lib trusted_caller
```

The full `cargo test --locked` suite is the complete Broker-side check; it also
includes MCP caller/session binding, pre-dispatch admission envelopes, ordinary
principal authentication alongside caller attestation, and forwarded-identity
fallback rejection tests outside the filters above.

Coverage includes ordinary browser sessions, direct Broker tokens, and HTTP MCP
on the public listener, plus Git on the separate gateway listener; mandatory
caller attestation for protected
headers; malformed/duplicate credentials; explicit-token precedence; conservative
direct defaults versus required asserted context; fingerprint inventory lifecycle;
and forwarding capabilities. Git checks also cover gateways with token-free
identity disabled. Configure ingress forwarding for each public and gateway
destination separately. Broker's configured caller admission applies on both;
each Git gateway additionally controls its token-free identity opt-in.

These tests establish Broker behavior, not a proxy's identity verification or
header stripping. Deployment acceptance must verify the selected ingress's
identity source, trusted context assignment, caller-credential injection,
untrusted-header/trailer handling, authenticated transport, and identity rotation.
Client-address forwarding separately requires configured `network.trusted_proxies`
and verified `Forwarded`/`X-Forwarded-For` values. Optional product-specific
end-to-end harnesses are separate from this repository's build and test suite.

## Development OAuth test provider

The shared-core `oauth::tests` select the `stub` dialect and `oauth_stub`
records backend from `agent-access-fake` explicitly; `cargo test -p
agent-access-fake` covers the dialect's protocol units and the records
backend's configuration. Those and the managed-store OAuth tests cover encrypted
storage, consent/session/grant and binding fences, refresh concurrency/cancellation,
restart, rotation and disconnect races. Personal setup tests cover direct/group
`per_user` grants without credential rights, rights-only denial, current
membership expiry, owner cleanup after grant loss and denied-flow retry behavior.
Resource/context availability remains independent of setup authorization.
The separate `oauth-provider-stub` repository contains provider protocol tests and `scripts/broker_e2e.py`, which drives the
real Broker and CLI. Its generated configuration points both
`[providers.oauth_stub] base_url` and the `stub` registration at the same test
server. With built binaries and portal assets, run the harness and
the optional `OAUTH_STUB_REPO` Playwright test as described in [oauth.md](oauth.md).

## Gmail

`cargo test -p agent-access-gmail` covers Gmail routes, MIME limits, pagination and
errors. Core OAuth tests cover reusable refresh recovery and account pinning; Broker
Gmail tests cover managed browser linking and invocation. Test doubles never reach
Google. The [Gmail live smoke](providers-gmail.md#validation-and-live-smoke) requires
an operator-owned Google client, browser consent and disposable test messages.


## Imported MCP services

The import suites use synthetic servers and credentials; no Grafana, Prometheus,
or production write target is required. `agent-access-provider` tests the bounded
import contract, `agent-access-core` tests store/key lifecycle and stable naming,
and broker `imports_foundation`, `imports_mcp`, and `imports_management` suites
exercise restart, publication cancellation, normal authorization/limits/audit,
credential isolation, and the administrator lifecycle. The foundation suites load
a development-only synthetic import adapter from the broker host's test tree;
only test registries select it, and the broker binary never links it.
`agent-access-mcp-upstream` uses the pinned SDK's real HTTP server plus raw
protocol fixtures. Two-version
regression coverage must include:

- `2026-07-28`, `2025-11-25` and dual-version servers, current-version preference,
  JSON and finite SSE lists/calls, pagination, safe server identity projection
  and the actual selected version in discovery and audit metadata.
- Legacy initialize/initialized ordering, version validation before notification,
  202/204/empty-200 acknowledgements, sessionless and stateful servers, correct
  headers, invalid/duplicate session IDs, and ignored later session headers.
- Startup rejection classification for each allowed and forbidden HTTP status,
  legacy-only or contradictory version lists, malformed evidence, middleware
  rejection IDs, strict success correlation, and a failed legacy initialization
  retaining its own authentication or rate-limit outcome. Startup is bounded to
  one discovery probe and at most one initialize attempt.
- Private sessions across concurrent users and discovery/execution operations,
  cleanup-only probe IDs, distinct-ID deduplication and at most two DELETEs under
  one two-second budget. Cancellation, expired deadlines and invalid leases stop
  cleanup; cleanup failure or a deadline during cleanup preserves a known result.
  Exercise the real HTTP MCP supervisor deadline during cleanup, a final poll that
  stays pending, and the existing forced-shutdown unknown-outcome contract.
- Exactly one tool dispatch when its response is an authentication/session error,
  timeout, malformed result or server error; cancellation races before dispatch;
  unsupported legacy `ping` and SSE closure after priming; no stream resumption;
  preserved uncertain-write receipts after dispatch.
- Static and delegated credentials, lease revocation/replacement between phases,
  protocol rejection preserving an OAuth connection, normal-operation 401
  rejecting only the sent token version, and cleanup 401 leaving it intact.
  Logs/traces must exclude credentials, session IDs, raw upstream errors,
  instructions, notifications, tool arguments and results.

The real Broker/CLI imported-service fixtures must exercise discovery and
downstream HTTP/stdio invocation against a legacy upstream through an existing
personal OAuth connection. The same fixtures retain header-encoding, schema,
content-preservation and single-dispatch assertions for the current version.
The imported OAuth suites add synthetic protected-resource and issuer metadata,
PKCE/issuer fencing, explicit client registration, refresh omission/rotation,
per-destination egress, unknown-identity replacement, canceled consent recovery,
semantic discovery revisions, and delegated no-replay tests. The portal
`tests/imports-oauth.spec.ts` drives an administrator's draft discovery Connect and
personal agent read/write invocation against local fixtures. Separate-tab
coverage checks opener isolation, unchanged original document and unsaved edits,
blocked pop-ups, failed Connect requests, consent denial, status refresh,
automatic tab closure, the Authorized fallback when closure is blocked, manual
closure of canceled consent, manual-closure instructions, neutral reloads,
callback errors, and explicit replacement confirmation. Backend tests distinguish
provider errors from denied consent and verify neutral reloads do not create
consent audit records or bypass authentication. Unit tests cover preserving an in-flight
authorization after view cleanup, actual tab closure, late API failures,
exact callback-path detection and focus/visibility refresh.
`tests/imports-oauth-server-default.spec.ts` covers server-default authorization
through administrator discovery and a separate ordinary user's personal
connection, including scope omission on consent, code exchange and refresh,
known/unknown scope display, credential isolation and action-grant enforcement.
The Gmail regression suite retains its stricter initial refresh-token requirement.

## Imported OpenAPI services

The adapter suite uses synthetic OpenAPI 3.1 documents and HTTP servers to test
bounded references, scheme selection, security/server overrides, serialization,
response validation and single-attempt write outcomes. The shared imported-service
CLI smoke exercises both adapter kinds through management, direct invoke, JSON
send with file output, downstream HTTP MCP and local stdio MCP. The OpenAPI case
checks shared/personal credential isolation, missing-personal-token denial and
operator removal of the document destination on offline restart.

The portal OpenAPI fixture covers public/private definition discovery, the
security-scheme picker, reviewed actions, refresh and invocation. The ordinary
MCP and OAuth fixtures remain regression checks.

### Local password method transitions

Password reset must reject absent or disabled local methods; explicit enable
requires acknowledgment and rejects an already active method. Verify these
boundaries through the store, HTTP handlers, CLI, and portal, including stale
reset/change operations racing with disable or another password write. Check
that local and Microsoft methods coexist, principal disablement remains
independent, source lockout does not change method status, and changing a local
password from a Microsoft session preserves that session while revoking local
sessions. CLI smoke tests cover distinct reset/enable payloads, required
acknowledgment, and rejection of unsupported password commands. Runtime
projection tests cover both routes and their schemas in catalog, OpenAPI, and
JSON send.
