# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Breaking Changes

- **Upgrade as a set and back up first.** Upgrade the Broker, CLI and portal
  together. Follow [upgrade and rollback](docs/operator-guide.md#upgrade-and-rollback).
  Managed-store migrations `027_command_imports` through
  `031_oidc_membership_renewal` run forward only. Rolling back across any of
  them requires the backup taken before the upgrade.
- **`[limits].upload_spool_dir` is required.** A configuration without it fails
  `config validate` and startup. Point it at a dedicated broker-owned
  directory. The old implicit default was
  `<working directory>/target/agent-access-upload-spool`.
- **Personal credentials are configured as credential connections.**
  `[credentials.connections.<id>]` defines one personal credential that
  services can share. Its keys are `display_name`, `token_profile` and an
  optional `oauth = { registration, profile }`. Each service's
  `[credentials.per_user.<service>]` selects one with `type = "connection"`
  and `connection = "<id>"`. The per-user types `managed_store` and `oauth`
  are removed, as are the `credential_name` and `profile` keys. The caller's
  principal kind selects the method, with no fallback between token and OAuth:
  people use OAuth when the connection configures it and a stored token
  otherwise; service accounts and `system` principals use tokens; callers
  without an active managed principal, including static principals whose ID
  names none, have no method. Translating the configuration alone can
  therefore leave existing static callers unable to use their stored
  credentials. Only tokens stored under the name `default`, with the
  connection's ID and profile, are kept. Tokens under other names become
  retained rows and must be stored again. Credential rights now apply to the
  connection and `default`, so grant the affected rights there. Rewrite the
  configuration before upgrading, using the
  [credential connections](docs/operator-guide.md#credential-connections)
  table.
- **Jira and Confluence use Atlassian token profiles.** Configure
  `atlassian-api-token` (an account email and API token). Through the
  Atlassian gateway, configure `atlassian-bearer-token`. One `atlassian`
  connection can serve both products. The `jira-cloud-api-token`,
  `jira-bearer-token`, `confluence-cloud-api-token` and
  `confluence-bearer-token` profiles are removed. Tokens stored under them stay
  listed but are no longer read. People store their Atlassian token again, and
  administrators re-provision service accounts' tokens.
- **Reserved names.** A gateway may not use the name of a native provider kind
  that the binary includes: `jira`, `confluence`, `gitlab`, `cloudbees_ci`,
  `gmail`, `teams`, `oauth_stub` or `fake`. A credential connection may not be
  named `broker`. It also may not use the name of a configured service, gateway
  or imported service, unless that service uses the connection.
- **OAuth loopback exceptions need a literal loopback address.** Use
  `http://127.0.0.1` or `http://[::1]` with `allow_insecure_loopback = true`.
  `http://localhost` is rejected. `https://localhost` and other host names now
  follow the egress proxy settings.
- **Confluence `all` resources include personal spaces.** Grants, groups and
  token restrictions that use `all` space resources now also cover personal
  (`~`) spaces visible to the selected credential. Review them before
  upgrading, especially service-mode grants on shared credentials. To exclude
  personal spaces, select exact team spaces.
- **Issued continuations are rejected after the upgrade.** These are now bound
  to the credential method: GitLab page tokens, Jira and Confluence search
  continuations and list tokens, and Confluence draft handles. Any issued
  before the upgrade are rejected. Repeat the search or listing, or create the
  draft again. OAuth consent flows pending at the upgrade are discarded.
- **The personal credential API and CLI are keyed by connection.**
  `GET /v1/credentials` returns `{connections, retained}`.
  `/v1/credentials/connections/{connection}`, with `/verify` and
  `/input-schema`, replaces `/v1/credentials/{service}/{name}`. Administrator
  routes move under
  `/v1/admin/principals/{principal}/credentials/connections/{connection}`.
  `PUT /v1/admin/credentials/{id}` and `POST /v1/admin/credentials/{id}/verify`
  are removed. OAuth connect, disconnect and listing are keyed by
  `registration`. The CLI commands `credentials inspect|put|delete|verify`
  take a connection instead of a service and a name. `admin credentials list`
  takes a principal, and `admin credentials list-stored` lists stored rows.
  Management audit targets are `{principal, connection}` for connections,
  `{principal, credentialId}` for retained-row deletes and `{registration}`
  for OAuth. Connection records list the consuming services in
  `providerAudit.management.targetServices`; `targetService` is set only when
  a single service uses the connection. See the [HTTP API](docs/http-api.md)
  and [CLI](docs/cli.md) references.
- **Import administration responses** replace `oauthRegistrations` with
  `importAuthentication`. It has one entry per import kind with an OAuth
  companion, each with `importKind`, `dialectId` and `registrations`.
- **Broker status reports the assembly identity.** `GET /v1/broker/status` and
  `agent-access broker status` no longer return `brokerVersion`, `buildCommit`
  or `buildProvenance`. They return `assembly`, `host`, `sdk`, `modules`,
  `inventoryFingerprint`, `catalogVersion` and `sendSchemaVersion`, and each
  source is `{revision, provenance}`. The `broker_starting` event's fields
  change the same way: `assemblyName`, `assemblyVersion`,
  `assemblyProvenance`, `qualification`, `inventoryFingerprint` and
  `assemblyRevision`.
- **Log targets.** Broker host events log under `agent_access_broker_host::…`
  instead of `agent_access_broker::…`. Lifecycle events log under
  `agent_access_broker_host::lifecycle`. Update module-level `RUST_LOG`
  directives. The OIDC diagnostic target `agent_access_broker::handlers::oidc`
  is unchanged.
- **CLI identity bindings.** `admin principals identity-bindings enable` and
  `disable` are removed. Use `identity-bindings update PRINCIPAL BINDING_ID
  --enabled BOOL --expected-version N` instead.
- **Native search audit shape.** New native-search audit records store
  `searchAuthorization.scope` as `{clauses: [{included, excluded}]}`. Earlier
  records keep their stored shape.
- **Provider SDK and Broker host (Rust).** `agent-access-provider` and
  `agent-access-broker-host` are now a supported API, inventoried under `api/`.
  Version 0.2.0 is the first baseline. Port providers and assemblies built
  against the 0.1.0 crates; see the [provider SDK](docs/provider-sdk.md) and
  [downstream assembly](docs/downstream-assembly.md) guides. The main changes:
  - Scope resolution is one `Provider::resolve_scopes(ScopeRequest)` call that
    returns a `ScopeResolution`. Typed `ProviderState` replaces JSON
    `provider_preflight`. Body admission returns an explicit `BodyAdmission`.
  - Execution credentials are opaque. Providers present them through an
    `UpstreamAuthorization` on the upstream call and receive the admitted
    `CredentialMode` and `InvocationAuthority`. Live invocation and credential
    values can no longer be serialized.
  - `DelegatedLease` implementations add the required
    `binding_identity() -> DelegatedBindingId`, which stays stable across
    routine refresh. Struct literals of the exhaustive
    `OAuthRegistrationConfig` supply `login_binding` (`None` for existing
    registrations).
  - Native searches declare `native_search` and receive normalized
    `SearchAuthorizationScope` clauses. This replaces `search_contained`.
  - Host networking left the SDK. Build clients with
    `UpstreamClient::build(spec, host.clients())`. Clients send credentials
    only to their base origin, and redirects carry credentials only within
    the authorized path.
  - `ProviderBuildError` replaces `HostError`. Read `ProviderError` through
    `decision()` and `reason_code()`. Envelopes and audit records carry a
    `ReasonCodeId`. CloudBees CI's log-limit reasons are now its own domain
    reasons, with unchanged wire spellings.
  - `ContinuationFamily` and `ContinuationSigner` replace `OpaqueTokenSigner`.
  - Build supported types with constructors and builders. Extendable types are
    non-exhaustive, and each item has one export path through the
    `presentation`, `host` or `deps` module. Registrations use
    `BackendRegistration::new(module_metadata!(), …)`, and import adapters
    register through `ImportedAdapterRegistration`.
  - The `agent-access-broker` library exports only `composition()` and
    `build_identity()`. Run it with `BrokerApplication::new(composition,
    identity)`, which returns a `Result`. `AssemblyIdentity` takes explicit
    `SourceRevision`s.

  Stored credential rows, credential kind spellings and persisted import JSON
  are unchanged.

### Added

- **Identity access path controls.** Each username binding and each identity
  token has its own **Enabled** and **Read-only** setting. A read-only path
  lists and runs only actions the catalog classifies as reads, on every
  surface: Git can fetch but not push. Manage the settings in the principal's
  **Access paths** table or through the identity-token and identity-binding
  `PATCH` routes. The CLI equivalents are `admin principals identity-token
  update` and `identity-bindings update`. Migration `029` keeps existing
  access. See [access path controls](docs/managed-identity.md#access-path-controls).
- **Automatic group enrollment for new Microsoft users.** A managed group's
  **Automatically add new Microsoft users** setting adds a persistent
  membership when a new Microsoft account is created. The API field is
  `autoEnrollNewMicrosoftUsers`, and the CLI option is
  `--auto-enroll-new-microsoft-users`. Existing accounts are not backfilled.
  Migration `030` leaves the setting off for existing groups.
- **Microsoft membership renewal**
  (`browser_auth.oidc.microsoft.membership_renewal`, off by default). With it
  on, Microsoft sign-in also requests `offline_access` and the Broker keeps the
  refresh token encrypted; requests from that person then renew expired or
  expiring Entra group evidence on demand, so their agents keep group-derived
  access without returning to the portal until Microsoft revokes or expires
  the token. Outcomes are audited as `oidc.membership.renewed` and
  `oidc.membership.renewal_failed` (new reason codes `oidc_sign_in_required`
  and `oidc_client_rejected`), and `GET /v1/me`, the admin login-method
  listing and the portal show each person's renewal status. Managed-store
  migration `031_oidc_membership_renewal`; rolling back across it needs a
  pre-migration backup. See the
  [operator guide](docs/operator-guide.md#microsoft-membership-renewal).
- **Credential connections.** One personal credential can serve several
  services, such as GitLab REST and its Git gateway, or Jira and Confluence.
  The portal's **Credentials** page lists one row per connection and OAuth
  registration, plus retained rows that can be deleted. Administrators see a
  person's OAuth connections read-only. Invocation and gateway audit records
  name the `credentialConnection`.
- **GitLab OAuth.** The `gitlab` OAuth dialect connects a person's GitLab
  account for GitLab REST and Git gateways. An optional `login_binding`
  requires that GitLab account to be linked to the person's Broker Microsoft
  sign-in. When the Broker ends a connection, it revokes the GitLab tokens and
  retries in the background. Connection rows report `remoteRevocation`.
  Migration `028`. See [GitLab OAuth](docs/oauth.md#gitlab).
- **Atlassian OAuth.** The `atlassian` OAuth dialect connects a person's
  Atlassian account for Jira and Confluence through the Atlassian gateway. See
  [Atlassian OAuth](docs/oauth.md#atlassian).
- **Git gateway credentials.** Git gateways accept OAuth connections. They can
  present OAuth access and bearer tokens as HTTP Basic, which GitLab requires:
  `upstream_token_auth = { scheme = "basic", username = "oauth2" }`. See
  [Git gateway OAuth connections](docs/git-http-gateway.md#oauth-connections).
- **OAuth for metadata lookups.** Lookups for `per_user` grants use the
  caller's OAuth connection. Token-only actions stay hidden from and denied to
  callers using OAuth. Examples are creating and rotating GitLab project and
  service-account tokens.
- **Command imports.** `[command_imports.<name>]` approves a local executable,
  and the `command` import kind imports it from its `agent-access-command/1`
  manifest. Imports can declare resource types and use shared, personal or no
  credentials. Each call runs in a supervised process with resource caps and
  audit. The portal's **Import service** offers **Local command**. Migration
  `027`. See [command imports](docs/command-imports.md).
- **GitLab search.** `project.search` discovers repositories. Separately
  grantable `search.issues`, `search.merge_requests`, `search.code`,
  `search.commits`, `search.wiki` and `search.comments` search content. The
  typed commands are `gitlab project search` and `gitlab search`. Configure
  engines and categories under `[providers.gitlab.search]`; see
  [configured engines](docs/providers-gitlab-rest.md#configured-engines-and-coverage).
- **Jira issue links.** `issue.view` returns `issueLinks` when the caller's
  access to that action covers every project.
- **Confluence personal spaces** can be granted as exact `confluence_space`
  resources by their `~` keys.
- **MCP client setup for agent tokens.** Token options report the HTTP MCP
  endpoint as `mcp.url`. The portal's **Token created** dialog shows setup
  commands and configuration for Pi, OpenCode, Claude Code, Codex and Cursor.
  The snippets reference `AGENT_ACCESS_TOKEN`, never the token itself.
- **Provider SDK additions.** The SDK adds the following:
  - provider domain reasons;
  - signed and confidential continuation envelopes, including relayed
    upstream page tokens;
  - bounded download and body helpers;
  - URL pattern validation;
  - `MutationReceipt`, `UpstreamAuthority` and `RedirectAuthorizer`;
  - opt-in universal-reach and token-only markers for actions.

  The host's `test-support` feature adds `IsolatedBroker` and
  `ProviderFixture` for acceptance tests.

### Changed

- **Write outcomes are reported consistently.** Write failures in GitLab,
  Jira, Confluence, Gmail, CloudBees CI `build.trigger`, Teams notifications
  and imported MCP and OpenAPI services carry a `mutationStatus`, with the
  exceptions below:
  - `not_applied`, with `retrySafe: true`, when the request was provably not
    sent;
  - `unknown`, with `retrySafe: false`, when the write may have applied, such
    as after no response, a redirect or a 5xx;
  - `applied_unverified`, with `retrySafe: false`, when the write may have
    applied and was not confirmed. Usually the upstream answered with success
    and its response or read-back then failed. A CloudBees CI trigger that
    times out, fails in transport without a response or gets a 5xx, and an
    uncertain GitLab write with a verification contract, also report it, so it
    does not prove acceptance. CloudBees CI's existing `applied_unverified`
    outcomes are unchanged.

  Upstream rejections or throttling of the write itself, and some failures
  before dispatch, carry no receipt. Reason code changes: a provably unsent
  GitLab write with a verification contract fails with
  `upstream_connection_failed` or `upstream_timeout` instead of
  `mutation_verification_failed`, and a Jira issue create that Jira places
  under a renamed project's current key reports `scope_unresolved` instead of
  `upstream_protocol_failed`, keeping its `applied_unverified` receipt. See
  also the GitLab write receipts fix.
- **Agent token issuance** moved to its own portal page. It selects actions
  and resources per service and shows a live access preview. The shared
  action selector uses a wider grid.
- **Provider contract enforcement.** A provider outcome that its contract does
  not allow reports `broker_provider_contract_failed` (HTTP 500).
- **Raw downloads.** Late download failures record uniform messages. A body
  that overruns its `Content-Length` fails before the excess is delivered. A
  GitLab file download that hits its deadline mid-body reports
  `upstream_timeout`.
- **Process behavior.** `serve` exits `3` when its configuration cannot be
  read or validated. At `--shutdown-timeout-ms`, open connections are cut off
  before the final audit drain.
- **Identity reporting.** MCP `serverInfo` and state lock metadata report the
  assembly name and version. Imported MCP connections identify as
  `agent-access-broker-host`.
- **Git gateway error responses** use `text/plain`, so Git shows the reason as
  `remote:` output.
- **Release qualification** adds the required `crate-boundaries`,
  `public-api` and `downstream-consumer` gates. It needs the pinned nightly
  toolchain and `cargo-public-api` 0.52.0. It rejects `test-support` features
  and `reference` crates in the release dependency graph. See
  [release readiness](docs/release-readiness.md).

### Fixed

- **Security: Atlassian gateway downloads.** An attachment download through
  `api.atlassian.com` could present the credential on a redirect to another
  site's cloud ID. Credentials now stay within the configured site.
- **Security: re-authorization at execution.** Jira comment,
  comment-property, attachment and `verify` actions deny an issue that moved
  to an ungranted project after authorization. GitLab actions refuse a
  project that moved to a path that is not authorized.
- **Search containment.** Confluence and Jira searches check results against
  the granted boundary, not the space or project names the caller wrote. A
  name the caller writes still narrows the query. It no longer rejects
  results that Confluence or Jira resolve to the current key.
- **Renamed and moved content.** GitLab resolves old paths and URLs of
  renamed, moved or transferred projects. Jira accepts previous project keys
  in issue URLs and searches. Confluence accepts space URL aliases. A link that
  fails validation is replaced with a constructed link instead of failing the
  operation.
- **Download limit.** The Broker enforces `limits.max_download_bytes` on every
  raw download.
- **GitLab write receipts.** A webhook write whose read-back fails, including
  with a 4xx or beyond the content bounds, reports
  `mutation_verification_failed` with an `applied_unverified` receipt and the
  webhook ID instead of a plain error. A write with a verification contract
  that the Broker could not prepare keeps its cause's reason, such as
  `upstream_protocol_failed`, without a receipt, instead of
  `mutation_verification_failed`.
- **GitLab webhook destinations** that differ only by a nondefault port are no
  longer rejected as duplicates.
- **Management decisions.** Credential verification and import discovery
  report the provider failure's own decision, such as `error`. They used to
  report `deny` for every failure.
- **HTTP MCP.** Unread responses and open sessions no longer keep a runtime
  generation and its state locks alive. Graceful shutdown closes the remaining
  sessions.
- **State locks at shutdown.** A managed-store write from sign-in or a
  management request keeps the state locks until it returns, even when
  shutdown abandons it after the drain deadline. Another Broker process can no
  longer take the store while the write still runs.
- **`broker_listening`** reports the bound address, including the port
  assigned for `--listen …:0`.
- **Portal.** A restricted token draft waits for complete selections before it
  previews, so an incomplete restriction cannot become an unrestricted token.
  In the grant editor, **Discard changes** after browser Back or Forward now
  leaves the page.

### Removed

- No features were removed. The removed configuration keys, token profiles,
  routes, response fields, CLI commands and Rust exports are listed under
  Breaking Changes, with their replacements.

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
