# Configuration reference

This document describes every section of the broker configuration file, the
separate CLI client config, and how `agent-access config validate` checks the
client config. It reflects the configuration structures and validation rules in
`crates/agent-access-core/src/lib.rs`.

Two distinct config files exist:

- The **broker config** (`BrokerConfig`), loaded by the `agent-access-broker`
  service. A sample lives at `agent-access-broker.sample.toml`.
- The **CLI client config** (`CliConfig`), loaded by the `agent-access` CLI. A
  sample lives at `agent-access.sample.toml`.

They are unrelated structs. The broker config has no listen-address or
`[service]` block; the CLI config's `[service].url` is purely a client setting.

## Canonical broker config shape

`BrokerConfig` and every nested struct use `#[serde(deny_unknown_fields)]`, so
any unrecognized key anywhere in the file is a hard parse error. Each
`[providers.<kind>]` table is parsed by the backend of that kind that the
broker binary registers, with the same strictness; a table for a kind the
binary does not register is a parse error that lists the supported kinds.

Sections fall into three categories:

| Category | Sections | Behavior when absent |
| --- | --- | --- |
| Mandatory | `identity`, `policy` | parse error |
| Optional | `execution_context`, `managed_store`, `credential_encryption`, `broker_tokens`, `audit` | feature-specific behavior described below; audit is disabled without `[audit]` |
| Defaulted | `deployment`, `network`, `credentials`, `imports`, `oauth`, `management`, `browser_auth`, `portal`, `mcp`, `providers`, `gateways`, `attribution`, `limits` | filled with built-in defaults |

### Conditional requirements

These cross-section rules are enforced by validation (not by the parser):

- A `broker_tokens` identity source requires both `[managed_store]` and
  `[broker_tokens]`.
- Any `per_user` credential of type `managed_store` requires both
  `[managed_store]` and `[credential_encryption]`.
- `management.enabled = true` requires `[managed_store]` unless management is
  configured only for explicit classless static TOML admin config operations:
  `allow_classless_admin_identities = true`, at least one configured admin
  principal or group, and `initial_admin.mode = "disabled"`.
- `browser_auth.enabled = true` requires `[managed_store]`, `[broker_tokens]`,
  `management.enabled = true`, `browser_auth.csrf_key_ref`, and
  `browser_auth.local_password.enabled = true`.
- `browser_auth.local_password.enabled = true` requires
  `browser_auth.local_password.pepper_ref`.
- `browser_auth.oidc.microsoft.enabled = true` additionally requires managed
  identity authority, `[managed_store]`, `[broker_tokens]`, enabled management,
  enabled browser auth, and enabled local-password login. It also requires the
  Microsoft tenant, client, and two OIDC secret references described under
  [`[browser_auth]`](#browser_auth).
- `portal.enabled = true` requires `browser_auth.enabled = true` and an
  absolute `portal.static_dir`.

Validation runs `deployment`, `identity`, `execution_context`, `network`, managed sections,
`credentials`, `providers`, `gateways`, `policy`,
`attribution`, `limits`, and `audit` checks and returns the full list of
errors at once.

## `[deployment]`

```toml
[deployment]
environment = "development"          # default
allow_production_anonymous = false   # default
enable_fake_service = false          # default
# node_id = "broker-prod-1"          # optional; defaults to the host name
```

- `environment` must be one of `production`, `staging`, `development`, `test`.
- When `environment = "production"` and `identity.mode = "anonymous"`,
  `allow_production_anonymous` must be `true`, otherwise validation fails.
- `enable_fake_service = true` permits the development fixtures: the `fake`
  backend (configured with an empty `[providers.fake]` table) and OAuth stub
  registrations. It is rejected when `environment = "production"`, and
  `[providers.fake]` without it fails validation.
- `node_id` names this broker in every audit record (`nodeId`) and in
  state-lock holder metadata. It must be 1 to 128 characters matching
  `^[A-Za-z0-9][A-Za-z0-9._-]*$`. When it is unset, `serve` uses the operating
  system host name (read the same way as for state-lock metadata, once per
  process); if the host name cannot be read or does not match the rule, `serve`
  fails at startup and asks for an explicit `node_id`. `config validate` stays
  offline: it validates an explicit `node_id` and does not resolve the host
  name. Uniqueness across brokers is the operator's responsibility: set
  `node_id` explicitly wherever host names are not stable (containers) or not
  unique. Reload rejects a change to the effective node ID with
  `config_admission_failed`; it requires a restart.

## `[network]`

```toml
[network]
trusted_proxies = []   # default empty

# Optional:
# [network.egress_proxy]
# url = "https://proxy.example:8443"
# username_ref = "env:EGRESS_PROXY_USERNAME"
# password_ref = "env:EGRESS_PROXY_PASSWORD"
```

- Each `trusted_proxies` entry must be a bare IP address or a CIDR (prefix
  `<= 32` for IPv4 / `<= 128` for IPv6). `"*"` and `/0` CIDRs are rejected in
  every environment; list the exact reverse-proxy addresses or subnets that are
  allowed to supply `Forwarded` or `X-Forwarded-For`.
- `egress_proxy` is the global outbound-proxy default. Its `Debug`
  representation redacts the URL down to scheme/host/port and shows the refs as
  `<redacted>`. See [Egress proxy](#egress-proxy-configuration) for the URL
  rules, which are shared across all proxy scopes.

### `[network.outbound_tls]`

One TLS trust policy applies to all Broker-owned outbound HTTPS clients: provider
API calls, uploads and downloads, Git gateways and credential verification, and
Microsoft OIDC discovery and token requests. HTTPS egress proxies use the same
trust policy. The separate `agent-access` CLI retains its `service.tls` settings.

```toml
[network.outbound_tls]
trust = "system" # default: system | custom | system_plus_custom
# ca_certificate = "/etc/agent-access-broker/ca/organization.pem"
```

| `trust` | Trusted certificates | `ca_certificate` |
| --- | --- | --- |
| `system` | Native system roots visible to the Broker process | Must be absent |
| `custom` | Only the configured PEM bundle | Required |
| `system_plus_custom` | Native system roots and the configured PEM bundle | Required |

The default uses the process-visible native trust store rather than bundled
WebPKI public roots. `SSL_CERT_FILE` and `SSL_CERT_DIR` can replace native-store
discovery; check the Broker service's environment when its trust differs from a
shell command. `custom` does not read the native store. `system_plus_custom` adds
trust and does not pin a server certificate. All modes verify certificate chains
and hostnames; there is no option to disable verification or override trust per
provider or controller.

`ca_certificate` must be an absolute path to a readable regular file of at most
4 MiB containing one or more valid `CERTIFICATE` PEM blocks. Empty bundles, other PEM blocks,
trailing non-whitespace text, and malformed certificates are rejected. Missing
files are errors. `config validate`, startup, and reload check the selected trust
sources; an unavailable or empty selected native store is an error.
Native certificates that Rustls cannot parse are skipped, as in Reqwest's
native-root handling; at least one usable native root is required. Startup and
reload log the skipped count as a warning. `config validate` checks usability
and reports errors but does not install service logging or print that count.
Native-store read errors include their underlying context and reject admission.
Custom bundles remain strict: every certificate must be usable.

Roots are captured once for each runtime candidate. A successful reload rebuilds
outbound clients with the new roots, including when the bundle contents change
at the same path. In-flight requests retain their admitted runtime's trust.
A failed reload leaves the active runtime and its trust unchanged. Replacing a
bundle or installing a system CA takes effect after reload or restart.

To add an internal CA while retaining system trust:

```toml
[network.outbound_tls]
trust = "system_plus_custom"
ca_certificate = "/etc/agent-access-broker/ca/organization.pem"
```

## `[execution_context]`

Execution context is a single attested authorization attribute. A configured
[trusted caller](trusted-callers.md) either asserts it through the fixed
`X-Agent-Access-Context` header or receives its configured fixed value. A context
or identity-fingerprint header always requires valid caller authentication on
HTTP, MCP and Git. Header-free direct clients use ordinary authentication and
the configured direct default. A caller credential alone never supplies a principal.

```toml
[execution_context]
allowed_values = ["default", "workstation", "internal", "external"]
default_context = "default" # optional conservative fallback for contextless callers
```

- `allowed_values` must contain one to 64 unique values. Every value must match
  `^[a-z][a-z0-9_-]{0,63}$` exactly; there is no wildcard and values are not
  trimmed or case-normalized.
- `default_context`, when present, must be one of `allowed_values`. A missing
  request without a trusted caller resolves to that one concrete value. Use a
  conservative value for direct callers, with grants and token caveats limited
  accordingly. Asserted callers must provide their assertion; fixed callers use
  their configured context. Remove it when all governed traffic must have an
  attested context, so missing headers fail with `execution_context_required`.
- A present header must contain exactly one ASCII safe slug and be a configured
  value. Duplicate fields, comma lists, whitespace, alternate case, malformed
  values, and unknown values fail closed with `execution_context_invalid`.
- When the whole section is absent, a missing header resolves to built-in
  `default`, omitted TOML grant contexts normalize to `["default"]`, and any
  present context header is rejected. The `default` value is one execution
  context, not a wildcard.
- `X-Agent-Access-Context` is reserved case-insensitively. It cannot be an
  identity-source header, browser CSRF header, or caller-controlled provider
  header, and it is never forwarded upstream.

The broker resolves this attribute for governed invocation, discovery, and Git-gateway traffic before token lookup, grant planning, provider
lookup, or credential selection. Management, browser login, health, readiness,
and reload routes do not acquire service-policy authority from this header.

## `[mcp]`

Optional downstream Streamable HTTP MCP uses `/mcp` and `/mcp/{service}` on the public listener.
Terminate TLS at trusted ingress and preserve its public Host. The broker does
not create a second listener. This setting controls downstream client connections;
upstream imports are configured separately. Keep `public_url` at `/mcp`; a
service-specific connection appends its canonical service ID. No per-service
listener, URL record or enable flag is needed. Proxy rules must permit both path
forms with identical identity, context, Host and Origin protections.

```toml
[mcp]
enabled = false
public_url = "https://broker.example.com/mcp"
allowed_origins = []
max_request_bytes = 16777216
max_response_bytes = 16777216
max_catalog_bytes = 67108864
operation_timeout_ms = 120000
protocol_timeout_ms = 30000
max_sessions = 256
max_sessions_per_principal = 8
session_idle_timeout_ms = 900000
session_max_lifetime_ms = 3600000
max_control_requests = 64
max_control_requests_per_principal = 8
```

These are defaults, except `public_url`, which must be supplied when enabled.
The URL must use HTTPS and exact path `/mcp`, without credentials, query or
fragment. Loopback HTTP is permitted only in development/test deployments.
Enable an `Authorization` identity source with canonical `scheme = "Bearer"` and
type `static_principals` or `broker_tokens`, or a named trusted caller with
`username_namespace` or `allow_forwarded_identity = true`. The caller options
admit managed username or fingerprint identities respectively; direct username
callers additionally require `credential_transport = "authorization_user"` and
fixed context. Every request requires an invocation identity;
ordinary anonymous service discovery and browser cookies do not apply here.

`allowed_origins` contains exact canonical HTTP(S) origins, without paths or
wildcards. An empty list permits clients that omit Origin and rejects all
requests that supply it. This is Origin validation, not a browser CORS or OAuth
onboarding implementation. Host and session checks also apply to native clients.

The request cap cannot exceed `limits.max_http_body_bytes`. Response size counts
the serialized MCP result, including escaped text and structured copies, with
space reserved for protocol framing. It must be at least 64 KiB. Catalog work
must allow at least one response cap. Tool pages contain at most 100 definitions
and may be shorter to stay within the response cap.

Aggregate and service connections share session and control pools. Two clients
with four HTTP service connections each consume the default eight sessions per
principal; allow restart overlap until abandoned sessions expire (15 minutes
idle by default). Size control limits for simultaneous initialization/listing
requests. Local stdio connections do not allocate downstream HTTP MCP sessions.

Session and control limits must be positive and per-principal limits cannot
exceed their global values. Session idle time cannot exceed maximum lifetime.
All deadlines must be positive. Control requests and responses have bounded
admission; provider work also uses the existing shared execution limits and
invocation limits: each action `tools/call` is counted once against the
caller's [service invocation limit](#service-invocation-limits). Protocol
messages, discovery helper tools, cancellation notifications, and session DELETE
are never counted, so an exhausted invocation budget does not prevent
cancellation. Authentication-failure budgets apply to failed identity resolution. Streaming body reads retain the existing idle
timeout; SSE keepalives are scheduled within that idle window.

`operation_timeout_ms` is the total HTTP MCP execution deadline, including
preparation and verification. It does not change existing REST/stdio timeout
semantics. `protocol_timeout_ms` bounds protocol/discovery and completed-response
delivery; keepalives do not extend these deadlines. Session storage is ephemeral.
Restart or changes to `[mcp]`, `[identity]`,
`[execution_context]`, `[broker_tokens]`, `[managed_store]`, or trusted-proxy
configuration invalidate sessions. Other reloads preserve sessions while each
request uses current authentication and policy. No result retention/replay is
provided.
Memory planning must account for concurrent work, not only a single wire cap.
At most `max_control_requests` incoming bodies and control operations can be
admitted globally, with separate native response leases capped by
`limits.max_concurrent_requests`. Each admitted discovery may project up to
`max_catalog_bytes`; each response has structured JSON, escaped text, capped
serialization buffers, and bounded SDK queues. Provider work retains its own
upstream/result allocation limits. These byte budgets bound serialized work;
Rust JSON object overhead and provider allocations mean they are not a resident
memory limit. Size concurrency and byte budgets together. Expired sessions and
completed SDK response caches are discarded; there is no result retention.
See [MCP client setup](mcp.md#http-endpoint).

## `[identity]`

```toml
[identity]
mode = "required"          # required | optional | anonymous
authority = "toml"         # toml | managed
sources = []               # default empty
groups = []                # non-empty only in TOML authority; default empty
```

- `mode` must be `required`, `optional`, or `anonymous`.
- `authority` must be `toml` or `managed`.
- `required` and `optional` each need at least one source. `anonymous` needs
  none.
- `authority = "toml"` allows `static_principals` sources and
  `[[identity.groups]]`; it rejects `broker_tokens` sources.
- `authority = "managed"` allows `broker_tokens` sources and rejects static TOML
  principals and `[[identity.groups]]`.
- `groups` is a list of first-class TOML group objects. Group IDs must be valid
  identifiers, `anonymous` is reserved, `status` must be `active` or `disabled`,
  and every member must reference a configured static TOML principal.

```toml
[[identity.groups]]
id = "agent-users"
status = "active"
members = ["alice"]
```

Disabled TOML groups remain visible in management catalogs but do not authorize
policy grants.

### Identity sources

Each entry in `[[identity.sources]]` carries these common fields:

| Field | Required | Notes |
| --- | --- | --- |
| `name` | yes | Unique, matches `^[A-Za-z0-9._-]{1,128}$` |
| `type` | yes | `static_principals` \| `broker_tokens` |
| `header` | yes | Valid HTTP header name |
| `scheme` | default `raw` | `raw` or `Bearer` |

A single header cannot be configured with two different schemes across sources.
`static_principals` and `broker_tokens` may repeat a header/scheme pair within
their respective authority modes. Any other `type` value is rejected.
`X-Agent-Access-Context` is also rejected because it is reserved for trusted
ingress attestation.

#### `static_principals`

Maps raw tokens to principals.

```toml
[[identity.sources]]
name = "local"
type = "static_principals"
header = "Authorization"
scheme = "Bearer"

[[identity.sources.principals]]
principal = "alice"
token_refs = ["file:/run/agent-access/alice.token"]

[[identity.groups]]
id = "agent-users"
status = "active"
members = ["alice"]
```

- `principals` must be non-empty; every principal must be globally unique across
  all static sources and have at least one `env:`/`file:` token ref.
- Valid only when `identity.authority = "toml"`.

#### `broker_tokens`

Resolves opaque `aab_`-prefixed broker tokens from the managed store.

```toml
[[identity.sources]]
name = "managed"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"
```

- Rejects `principals`.
- Valid only when `identity.authority = "managed"`.
- Requires `[managed_store]` and `[broker_tokens]` elsewhere in the file.

## `[credentials]`

```toml
[credentials.service]
[credentials.per_user]
[credentials.lookup]
```

Each of the three maps is keyed by service name (`^[a-z][a-z0-9_-]{0,62}$`) and
defaults to empty. A `CredentialConfig` uses `deny_unknown_fields`.

A backend that explicitly declares no execution credential may use `service`
grants without an entry in this map. Teams obtains its signed endpoint from the
authorized managed resource; do not configure Teams service/per-user/lookup
credentials or dummy tokens.

There are five credential kinds:

| Kind | Required fields | Allowed in |
| --- | --- | --- |
| `basic_api_token` | `username_ref`, `token_ref` (both `env:`/`file:` refs) | service, per_user*, lookup |
| `bearer_token` | `token_ref` (`env:`/`file:` ref) | service, per_user*, lookup |
| `secret_store` | `provider = "local_file"`, absolute `path` | per_user only |
| `managed_store` | `profile` (and optional `credential_name`) | per_user only |
| `oauth` | `provider` (an `oauth.registrations` name), `profile` (one of its permission profiles) | per_user only, for services that accept delegated credentials |

\* A `per_user` credential's `type` must be `secret_store`, `managed_store`, or
`oauth`.
The static `basic_api_token` / `bearer_token` kinds are used under
`credentials.service` and `credentials.lookup`.

Additional rules:

- `credentials.lookup.<service>` must set `read_only = true`.
- Jira, Confluence, and GitLab lookup-backed grants require
  `credentials.lookup.<service>` only when at least one lookup-backed grant for
  that service uses `credential_mode = "service"`. Per-user-only lookup-backed
  grants validate without a shared lookup credential.
- Static kinds must not set `provider`, `path`, `credential_name`, or `profile`.
- `secret_store` must not set `username_ref`, `token_ref`, `credential_name`,
  `profile`, or `read_only`. Its `provider` must be `local_file` and `path`
  must be absolute.
- `oauth` sets only `provider` and `profile`. The service's descriptor must
  accept delegated credentials (`gmail` and the development `oauth_stub`
  service), and none of the service's per-user actions may need a lookup
  credential, which a delegated credential cannot provide. See
  [oauth.md](oauth.md).
- `managed_store` must not set `username_ref`, `token_ref`, `provider`, `path`,
  or `read_only`. Its `credential_name` (optional) must be routable as
  `/v1/credentials/{service}/{name}` and match
  `^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$`; `profile` is required and must be
  supported for the service.

### Managed-store profiles

The supported `managed_store` `profile` values, and the credential kind each
resolves to, depend on the surrounding config:

| Service | Profile | Resolves to | Requires |
| --- | --- | --- | --- |
| `jira` | `jira-cloud-api-token` | `basic_api_token` | `[providers.jira]` present |
| `jira` | `jira-bearer-token` | `bearer_token` | Jira gateway enabled (`cloud_id` set AND `api.atlassian.com` allowlisted) |
| `confluence` | `confluence-cloud-api-token` | `basic_api_token` | `[providers.confluence]` present |
| `confluence` | `confluence-bearer-token` | `bearer_token` | Confluence gateway enabled (`cloud_id` set AND `api.atlassian.com` allowlisted) |
| `gitlab` | `gitlab-access-token` | `bearer_token` | `[providers.gitlab]` present |
| `cloudbees_ci` | `cloudbees-ci-api-token` | `basic_api_token` | `[providers.cloudbees_ci]` present |
| any Git HTTP gateway | `git-basic-api-token` | `basic_api_token` | the `gateways.<service>` entry has `kind = "git_http"` and allows `per_user` |
| any Git HTTP gateway | `git-bearer-token` | `bearer_token` | the `gateways.<service>` entry has `kind = "git_http"` and allows `per_user` |

Any other profile fails validation.

### Secret-ref syntax

A secret reference is either:

- `env:NAME` where `NAME` matches `^[A-Z_][A-Z0-9_]*$`, or
- `file:/absolute/path` (the path must begin with `/`).

## `[managed_store]`, `[broker_tokens]`, `[credential_encryption]`

### `[managed_store]`

```toml
[managed_store]
type = "sqlite"                                       # must be sqlite
path = "/var/lib/agent-access-broker/managed.sqlite3" # absolute
require_registered_principal_for_invocation = false   # default
auto_migrate = false                                  # default
```

- `type` must be `sqlite`; `path` must be absolute.
- `auto_migrate = false` is fail-closed: the database and current schema must
  already exist and reloads never migrate. Set `auto_migrate = true` only for
  an intentional startup that initializes an empty store or applies pending
  forward migrations to a recognized, supported migration-ledger prefix. Back up
  existing state first, then return it to `false` after migration. Databases
  predating the supported baseline, unknown migrations, checksum mismatches, and
  schema drift are rejected without modification. See the
  [schema model](database.md#schema-model) and
  [upgrade runbook](operator-guide.md#upgrade-and-rollback).
- During `serve` and reload admission, `path` participates in the broker's
  single-node state-lock set. The broker locks a sibling
  `<database-file>.agent-access.lock` file before opening or migrating the
  SQLite database.

### `[broker_tokens]`

```toml
[broker_tokens]
hash_key_ref = "env:AGENT_ACCESS_BROKER_TOKEN_HASH_KEY"
# Optional TTLs (string durations):
# default_agent_invoke_ttl = "8h"
# default_user_manage_ttl = "8h"
# default_admin_ttl = "2h"
# max_self_issued_agent_invoke_ttl = "30d"
# self_agent_invoke_ttl_options = ["8h", "7d", "30d"]
# admin_agent_invoke_ttl_options = ["8h", "7d", "30d", "never"]
# user_manage_ttl_options = ["30m", "2h", "8h", "1d"]
# admin_ttl_options = ["30m", "2h", "8h", "1d"]
```

- `hash_key_ref` is a required `env:`/`file:` ref. At runtime the referenced
  value must be base64url (`URL_SAFE_NO_PAD`) decoding to exactly 32 bytes.
- TTL strings parse with a unit suffix of `s`, `m`, `h`, or `d`.
- `default_agent_invoke_ttl` must not exceed `max_self_issued_agent_invoke_ttl`,
  which defaults to `30d` when unset.
- The four `*_ttl_options` arrays are exact, broker-enforced choices for their
  respective issuance surfaces. Their order is preserved in the authenticated
  session policy and portal. Defaults are the arrays shown above.
- Lists must be non-empty and contain no duplicate effective durations. Finite
  entries use the normal duration syntax. `never` is valid only in the two
  agent-token lists and is rejected in `user_manage_ttl_options` and
  `admin_ttl_options`.
- A configured `default_agent_invoke_ttl` must appear, by equivalent duration,
  in both agent-token lists. Configured `default_user_manage_ttl` and
  `default_admin_ttl` must appear in their corresponding lists. When
  `default_agent_invoke_ttl` is omitted, the effective self-service default is
  `max_self_issued_agent_invoke_ttl` (or `30d` when that is also omitted), which
  must appear in `self_agent_invoke_ttl_options`.
- Every finite self-service agent option must be at most
  `max_self_issued_agent_invoke_ttl`. The default self-service list is finite;
  an operator must explicitly add `never` to allow self-service non-expiring
  agent tokens. The administrator-issued agent list includes `never` by
  default. Management-token lists can never include it.
- A finite `ttl` or `ttlSeconds` request must match an entry in the applicable
  list by duration. An administrator may still supply a future absolute
  `expiresAt`; self-service absolute expiry remains bounded by
  `max_self_issued_agent_invoke_ttl`.
- Authenticated browser-session responses project these values into the
  caller-filtered `tokenIssuancePolicy` used by the portal. Changing TTL config
  therefore changes newly opened issuance forms after session refresh; it does
  not rewrite, expire, or revoke existing token rows.
- Every newly issued `agent_invoke` token must also carry a finite
  `allowedExecutionContexts` caveat in `scopes`: one or more contexts for both
  self-service and administrative issuance. Choices come from active effective
  grants for the principal, and selected services must be visible in at least
  one selected context. A token caveat can only narrow matching grants. A stored
  agent token without this field remains governed by current grants but does not
  independently restrict execution context. Stored token caveats cannot be amended.
  When token-copy containment matters, revoke tokens that lack this field and
  issue replacements with finite execution-context caveats.
- Issuance may add the request-level `serviceRestrictions` caveat to constrain
  selected services to immutable action lists and finite canonical resource
  values. It is derived from the configured service/action catalog and current
  target-principal grants; it does not add a broker TOML key, reusable template,
  policy object, or deployment setting.

### `[credential_encryption]`

```toml
[credential_encryption]
active_key = "k2026-06"

[[credential_encryption.keys]]
id = "k2026-06"
provider = "env"                # env | file
env = "AGENT_ACCESS_CREDENTIAL_KEY_K2026_06"
# For file keys instead:
# provider = "file"
# path = "/etc/agent-access/keys/k2026-06"
```

- `active_key` must match `^[A-Za-z0-9._-]{1,128}$` and reference a configured
  key id.
- `keys` must be non-empty; ids are unique and match the same identifier
  pattern.
- An `env` key requires a valid env var name and must not set `path`. A `file`
  key requires an absolute `path` and must not set `env`.
- At runtime each key value must be base64url (`URL_SAFE_NO_PAD`) decoding to
  exactly 32 bytes (AES-256-GCM).

### `[browser_auth]`

`browser_auth` is disabled by default. It supports managed-store local-password
login and one optional, single-tenant Microsoft Entra OIDC login provider.

```toml
[browser_auth]
enabled = true
public_origin = "https://broker.example" # required for Microsoft OIDC
session_cookie_name = "aab_session"      # default
csrf_header = "X-Agent-Access-CSRF"      # default
csrf_key_ref = "env:AGENT_ACCESS_BROWSER_CSRF_KEY"
session_ttl = "8h"                       # default
allowed_return_paths = ["/ui"]           # default

[browser_auth.local_password]
enabled = true
pepper_ref = "env:AGENT_ACCESS_LOCAL_PASSWORD_PEPPER"
min_password_length = 12                 # default
max_failed_attempts = 10                 # default
lockout_ttl = "15m"                      # default

[browser_auth.oidc.microsoft]
enabled = true
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "00000000-0000-0000-0000-000000000000"
client_secret_ref = "env:AGENT_ACCESS_MICROSOFT_OIDC_CLIENT_SECRET"
flow_key_ref = "env:AGENT_ACCESS_MICROSOFT_OIDC_FLOW_KEY"
flow_ttl = "10m"                         # default; 2m..15m
max_pending_flows = 10000                # default; 100..100000
jit_provisioning = true                  # default
external_membership_ttl = "8h"          # default; 15m..24h
```

- `public_origin`, when set, must be an `http` or `https` origin with no path,
  query, or fragment. Non-local `http` origins are rejected. Production
  deployments with `browser_auth.enabled = true` must set `public_origin`.
- `session_cookie_name` must be a valid cookie name and may not use the
  `__Host-` or `__Secure-` prefixes, matched case-insensitively, because the
  browser session cookie is scoped to `Path=/v1` and loopback development may
  run without `Secure`.
- `csrf_header` must be a valid HTTP header name and must not equal reserved
  `X-Agent-Access-Context`.
- `csrf_key_ref` and `local_password.pepper_ref` are `env:`/`file:` refs whose
  runtime values must decode from unpadded base64url to exactly 32 bytes.
- `session_ttl` and `local_password.lockout_ttl` use the same `s`/`m`/`h`/`d`
  duration syntax as broker-token TTLs.
- `allowed_return_paths` must contain literal absolute paths under `/ui`; query
  strings, fragments, backslashes, empty path segments, dot segments, and
  percent-encoded characters are rejected.
- Local password hashes are Argon2id PHC strings over an HMAC-SHA-256
  peppered password digest. New hashes use at least 64 MiB memory and 3
  iterations. Password hashes are stored in `principal_login_methods`; they are
  never serialized in API responses.
- Local passwords are checked by byte length, must be at least
  `min_password_length`, must be at most 1024 bytes, and must not equal the
  principal id case-insensitively.
- `max_failed_attempts` and `lockout_ttl` apply per `(principal, source)`. The
  source is the resolved client address after `network.trusted_proxies`: the
  full IPv4 address, or the /64 prefix of an IPv6 address; IPv4-mapped IPv6
  addresses and addresses in the well-known NAT64 prefix `64:ff9b::/96` use
  their embedded IPv4 address. Failed password
  verifications on login and password change count against that pair; reaching
  `max_failed_attempts` locks only that source out of that principal for
  `lockout_ttl`, and login from other sources is unaffected. A success clears
  the verifying source's count. Failures are forgotten once `lockout_ttl` has
  passed since the last failure and any lockout has expired. Attempts against
  principal IDs that do not exist count the same way, so lockout responses do
  not reveal whether a principal exists. Rotating sources does not avoid
  lockout: once a principal has failures recorded from 256 sources, failures
  from any further source share one overflow counter for that principal, which
  locks every source without its own counter under the same
  `max_failed_attempts` and `lockout_ttl`. The admin unlock route clears every
  source's lockout for a principal, including the overflow counter; setting or
  disabling the local password does too.
- Admin-set local passwords default to temporary passwords. The admin API and
  CLI can explicitly set `mustChangePassword = false`; otherwise the resulting
  browser session has `passwordChangeRequired = true` and cannot call
  self-service credential/token routes until the user changes the password.
- The portal admin create/reset flows generate temporary passwords in the
  browser, call the same admin API with `mustChangePassword = true`, and reveal
  the generated password once for copying.

Microsoft OIDC configuration is intentionally Microsoft-specific rather than a
generic provider list. `browser_auth.oidc.microsoft.enabled` defaults to
`false`; when disabled, the other Microsoft fields are not required and its
secret references are not resolved.

- `tenant_id` and `client_id` are required canonical lowercase, hyphenated
  UUIDs. The tenant is fixed once the managed store contains a Microsoft login
  method or external-group binding.
- `client_secret_ref` is an `env:NAME` or `file:/absolute/path` reference whose
  trimmed runtime value is the nonempty Entra application client secret.
  `flow_key_ref` is a separate reference in the same syntax whose trimmed value
  must be unpadded base64url and decode to exactly 32 random bytes. Do not reuse
  the browser CSRF, broker-token, credential-encryption, or password-pepper key.
- `flow_ttl` accepts `s`, `m`, `h`, or `d` duration syntax and must resolve to 2
  through 15 minutes. `max_pending_flows` is a global durable-flow cap from 100
  through 100,000.
- `external_membership_ttl` uses the same duration syntax and must resolve to 15
  minutes through 24 hours. Microsoft-derived group access is valid only until
  this TTL expires unless the user completes another Microsoft login. Local
  group memberships, roles, and direct grants are independent.
- `jit_provisioning = true` permits a new Microsoft user only when at least one
  group Object ID in the complete ID-token claim maps to an active broker group.
  An existing explicitly linked user may log in with a complete empty or
  unmapped group set; that authoritative set removes prior Microsoft-derived
  contributions without affecting local access. Set `jit_provisioning = false`
  to require administrators to link every Microsoft user Object ID first.
- Microsoft group claims that explicitly indicate overage, are distributed,
  contain more than 200 entries, or are malformed reject that login. The broker
  does not call Microsoft Graph to expand them. Microsoft groups can contribute
  ordinary broker-group membership, but cannot grant the broker `admin` role.

The following values are derived and cannot be overridden:

| Value | Derived setting |
| --- | --- |
| Provider id | `microsoft` |
| Issuer | `https://login.microsoftonline.com/{tenant_id}/v2.0` |
| Discovery | `{issuer}/.well-known/openid-configuration` |
| Redirect URI | `{public_origin}/v1/auth/oidc/microsoft/callback` |
| Scopes | `openid profile email` |
| Flow | authorization code in query mode with PKCE S256 |

When Microsoft OIDC is enabled, `public_origin` must be an HTTPS root origin
without a path, query, fragment, or credentials. Plain HTTP is accepted only for
loopback origins in `development` or `test`. Register the derived redirect URI
exactly in Entra; redirects and alternate issuers cannot be configured in the
broker. Disabling Microsoft OIDC skips its secret resolution and Microsoft
network access, which permits a local emergency disable even when the provider
or its secrets are unavailable. Unknown or generic OIDC keys are rejected by
strict TOML parsing.

Browser sessions are stored as `user_manage` broker tokens plus a
`browser_sessions` row. The raw token is carried only in an HttpOnly `/v1`
cookie. The JSON login/session responses return a CSRF token derived from the
session id; cookie-authenticated state-changing self-service routes must send it
in `csrf_header`. State-changing browser-auth routes reject cross-site requests
and requests whose origin cannot be established. Browser-auth routes use the
authentication source and principal budgets (`auth_requests_per_*_per_minute`)
before password verification.

### `[portal]`

`portal` is disabled by default and serves a built React app from the same
public listener as the broker API.

```toml
[portal]
enabled = false
mount_path = "/ui"
static_dir = "/var/lib/agent-access-broker/portal"
```

- The current portal requires `mount_path = "/ui"`.
- `static_dir` is required and absolute when `portal.enabled = true`. Its
  canonical directory is the asset boundary: internal symlinks are supported,
  but files or SPA/index fallbacks resolving outside it return 404. The root
  directory itself may be a symlink.
- Portal responses include no-sniff, deny-frame, self-only content-security, and
  cache headers; hashed assets are cacheable, while `index.html` is not.
- The app is theme-tokenized with CSS variables and persists a local preference
  of `system`, `light`, or `dark`. Theme application uses external CSS and root
  `data-theme` attributes so it stays compatible with the portal CSP.
- The repository contains source for the portal under `apps/portal`; generated
  build output is intentionally not checked in. Build it with
  `npm --prefix apps/portal ci` followed by
  `npm --prefix apps/portal run build`, then set `static_dir` to the generated
  `apps/portal/dist` directory or to a deployed copy of that directory.

## `[management]`

```toml
[management]
enabled = false                          # default
admin_principals = []                    # default empty
admin_groups = []                        # default empty
allow_classless_admin_identities = false # default
allow_classless_user_management = false  # default

[management.initial_admin]
mode = "disabled"                        # disabled | create_if_empty
# principal_id = "admin"                 # required for create_if_empty
# initial_password = "<insert-a-unique-generated-password>" # replace before create_if_empty
```

- `enabled = true` requires `[managed_store]` unless this is an explicit
  storeless classless-admin config-operations deployment:
  `allow_classless_admin_identities = true`, at least one admin principal or
  group, and `initial_admin.mode = "disabled"`.
- `admin_principals` must be valid principals; `admin_groups` must be valid
  identifiers.
- `allow_classless_admin_identities` defaults to `false`. Set it to `true` only
  during an explicit bootstrap window where a static TOML admin identity must
  grant the first DB `admin` role or recover managed admin access.
- `management.initial_admin.mode = "create_if_empty"` creates a managed
  `user` principal with DB role `admin` only when the principal table is empty.
  It requires browser local password login and a literal `initial_password`
  that passes the configured local password length and principal-id checks.
  Generate a unique password; configuration validation rejects the published
  placeholder literals. The generated local password method always requires
  password reset on first login.
  Use this mode only for controlled first deployment or local development; do
  not expose a fresh broker to an untrusted network before the initial password
  is reset.
- Once any principal exists, `management.initial_admin` does not rewrite,
  re-enable, or regrant anything. Existing stores must retain at least one
  active DB admin unless an explicit classless admin bootstrap path remains
  configured for recovery.

## `[policy]`

```toml
[policy]
authority = "toml"          # toml | managed
default_decision = "deny"   # default; validation requires exactly "deny"

[[policy.resources]]
id = "jira-eng"
resource_type = "jira_project"
selector = { kind = "exact", value = "ENG" }
allowed_execution_contexts = ["internal", "external"]
enabled = true

[[policy.resources]]
id = "jira-all"
resource_type = "jira_project"
selector = { kind = "all" }
allowed_execution_contexts = ["internal"]
enabled = true

[[policy.resource_groups]]
id = "engineering"
name = "Engineering"
included_resource_ids = ["jira-eng"]
excluded_resource_ids = []

[[policy.grants]]
subjects = ["group:agent-users"]
service = "jira"
actions = ["issue.view", "issue.create", "issue.child.create", "issue.parent.set", "issue.dependency.add", "search"]
resources = { resource_ids = [], resource_group_ids = ["engineering"] }
execution_contexts = ["internal", "external"]
credential_mode = "service"   # service | per_user
priority = 0                  # optional
```

- `authority` must be `toml` or `managed`.
- `authority = "toml"` loads resources, resource groups, and grants from TOML.
- `authority = "managed"` requires `identity.authority = "managed"` and
  `[managed_store]`, rejects inline TOML resources, resource groups, and grants, and loads the
  complete policy graph from the managed store at startup and reload. Managed
  grant management is exposed through `/v1/admin/policy/*`,
  `agent-access admin policy`, and the portal Admin > Policies screen.
  Managed grant IDs are generated UUIDs unless an admin supplies a safe slug
  containing 1-128 letters, numbers, dots, underscores, or hyphens, excluding
  `.`, `..`, `export`, and `validate`.
- Service policy management assignments exist only when management is enabled
  and both `identity.authority` and `policy.authority` are `managed`. They are
  managed-store records administered through the API, CLI, or portal; there is
  no TOML assignment syntax. Service/provider/gateway definitions remain in
  TOML. An assignment targets one exact configured service and one active
  account with role `service_policy_manager` and grants whole-service policy editing, not
  invocation access, service configuration, credential access, token
  administration, or assignment delegation.
- Management assignments are direct to accounts, never groups. One account can
  manage multiple services. Role changes away from manager remove assignments;
  disabling an account preserves them. Assignments for removed services stay
  dormant and reactivate if the exact service returns. The independent account
  `selfServiceEnabled` flag controls personal management; see [roles.md](roles.md).
- `default_decision` must be `deny` (deny-by-default).
- Each grant has a finite nonempty execution-context list. With an explicit
  `[execution_context]` section, TOML `execution_contexts` is required and every
  value must be unique, syntactically valid, and present in `allowed_values`.
  When the section is absent, an omitted TOML field normalizes to exactly
  `["default"]`. An explicit empty list is always invalid. Managed API,
  portal, CLI, list/get, and export representations use the canonical JSON field
  `executionContexts`; create and patch reject JSON null, empty, duplicate,
  malformed, unknown, or over-64 lists.
- Each TOML grant's required `subjects` array must be non-empty and contain
  exact `user:<principal>` or `group:<group>` values, where `user:anonymous` and
  `group:anonymous` are ordinary subjects. Managed active grants follow the same
  runtime rule, while disabled managed grants may be temporarily subjectless as
  draft/staging records. Repeat the field value inside the array to grant the
  same service/action/scope rule to multiple users or groups; duplicate entries
  in one grant are rejected.
- In TOML identity authority, non-anonymous `user:` subjects must reference
  configured static TOML principals, and non-anonymous `group:` subjects must
  reference configured TOML groups.
- In managed identity authority, non-anonymous `user:` and `group:` subjects
  are validated against the managed store at startup and reload. Missing DB
  principals or groups reject admission with `config_admission_failed`; disabled
  DB principals and groups may remain referenced but do not authenticate or
  authorize while disabled.
- `actions` must be non-empty; each action must be known for the service, must
  not repeat the service prefix, and must support the chosen credential mode.
- `credential_mode` must be `service` or `per_user`, and the matching
  credentials must actually be configured for the service, except for service
  mode on a backend explicitly declaring no execution credential.
- Grants require a `resources` reference selection. Empty selections and groups
  authorize nothing; they never imply unrestricted access.
- `priority` is a real optional integer key used for grant precedence at request
  time (defaults to `0` when omitted).

### Resource catalog and selections

`[[policy.resources]]` fields are `id`, `resource_type`, `selector`, optional
`display_name`, nonempty `allowed_execution_contexts`, and `enabled`.

- `resource_type` must name a registered resource type (see
  [resources.md](resources.md#resource-entries)); this build registers
  `git_repository`, `jira_project`, `confluence_space`, `cloudbees_ci_job`,
  `fake_project`, and `oauth_collection`.
- Exact selectors are `{ kind = "exact", value = "engineering/payments" }`.
- Namespace selectors apply to Git repositories and CloudBees CI jobs, for example
  `{ kind = "namespace", value = "engineering/platform" }` for a repository group.
  Matching uses complete path segments. OAuth collections support exact/all only.
- All selectors are `{ kind = "all" }`. They have no value and cover new,
  unregistered upstream objects. All resource types support them.
- The type and selector combination must be unique, independent of name,
  contexts, and enabled state. Unknown fields and invalid combinations are
  rejected. There is no Jira issue or Confluence page policy scope.

`[[policy.resource_groups]]` fields are `id`, `name`, `included_resource_ids`,
and `excluded_resource_ids`. Groups can mix types, but cannot contain other
groups. They have no context list or enabled state.

Grant `resources` has `resource_ids` and `resource_group_ids` arrays. Unknown
references and duplicate IDs in authored arrays are rejected. Overlap across
selected groups is deduplicated. Positive entries require their enabled state
and request context; exclusions apply regardless of those properties. Within one
grant, all selected exclusions win over all selected inclusions. Separate grants
retain independent authority and existing credential precedence.

For example, an all-repositories entry included in a group can be narrowed by
excluding an exact repository or namespace entry. No raw star or freeform scope
string is entered on the grant or token. See [resources.md](resources.md) for
context overlap, live token restrictions, lifecycle, and effective access.

Services use the registered provider and gateway contracts, with typed resource
references for policy boundaries. Managed stores must use a supported schema; see
[database schema requirements](database.md#schema-model).

## `[attribution]`

`[attribution]` is disabled by default. When enabled, the broker appends a
visible footer to configured Jira, Confluence, and GitLab REST text/body writes
after normal input validation and before upstream execution. Agents do not pass
new inputs for attribution.

```toml
[attribution.actions]
jira = ["comment.*", "issue.create", "issue.child.create", "issue.update"]
confluence = ["page.*", "blog.*"]
gitlab = ["issue.*", "merge_request.*"]
```

- Missing `[attribution]`, missing `[attribution.actions]`, a missing service
  key, or an empty list disables attribution for that service.
- Keys are service names. A key must name a configured service whose
  descriptor declares attribution-capable actions (currently `jira`,
  `confluence`, and `gitlab`); any other key fails startup/reload validation,
  including a key for a provider that is not configured.
- Patterns support only `*` for zero or more characters and `?` for one
  character. Matching is case-sensitive, and `.` is ordinary.
- Patterns may contain only ASCII letters, digits, `.`, `_`, `-`, `*`, and `?`;
  malformed patterns fail startup/reload validation.
- Each pattern must match at least one attribution-capable action that the
  service's current configuration enables. Content-format settings can remove
  actions: for example, Jira `comment.*` matches nothing unless
  `providers.jira.content.comment_formats` includes `adf`.
- Patterns match attribution-capable actions, not the full provider action
  catalog. For example, `confluence = ["page.*"]` includes page body writes,
  page draft create/stage/update, and page comment writes that are attribution
  capable; use exact action names when that breadth is not desired.

Attribution consumes body budget. A request that is within
`providers.<service>.content.max_body_bytes` before attribution can still be
rejected if the final broker-mutated body exceeds that cap.

## `[providers]`

`[providers]` configures the backends the broker binary registers: Jira,
Confluence, GitLab REST, CloudBees CI, Gmail, Teams, and the development `fake` backend. Each
`[providers.<kind>]` table enables one backend, whose service ID is its kind.
All sub-tables are optional, but a provider must be present for any
`policy.grant` to target its service: a grant against an absent provider fails
validation with `references unknown service <svc>`. Runtime action behavior lives in
[providers.md](providers.md) and its linked provider-specific docs; the keys
below are the config reference.

### `[providers.jira]`

```toml
[providers.jira]
tenant_host = "example.atlassian.net"               # required, lowercase normalized bare host
cloud_id = "00000000-0000-0000-0000-000000000000"   # optional UUID
allowed_upstream_hosts = [
  "https://example.atlassian.net/rest/api/3/**",
  "https://api.media.atlassian.com/**",
]

# Optional per-provider outbound proxy (see Egress proxy configuration):
# [providers.jira.egress_proxy]
# url = "http://jira-proxy.example:8080"

[providers.jira.attachments]
max_bytes = 10485760            # 10 MiB; per-attachment cap; default
max_total_bytes = 52428800      # 50 MiB; total across attachments; default
max_download_bytes = 104857600  # 100 MiB; single download cap; default
media_types = ["text/plain", "application/json", "image/png", "text/html"]

[providers.jira.content]
comment_formats = ["adf"]   # native formats only; [] disables comment writes
max_body_bytes = 1048576    # 1 MiB; default

[providers.jira.search]
max_results = 50            # default

[providers.jira.comments]
max_results = 50
max_property_value_bytes = 32768
allowed_property_key_prefixes = ["agent-access."]

# Visibility restrictions are rejected unless explicitly allowlisted.
# [[providers.jira.comments.allowed_visibility]]
# type = "role"
# value = "Developers"
#
# [[providers.jira.comments.allowed_visibility]]
# type = "group"
# identifier = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

[providers.jira.issue_links]
dependency_link_type = "Blocks"
dependency_outward = "blocks"
dependency_inward = "is blocked by"
```

- `tenant_host` is required and must be a lowercase, normalized bare host name
  with no scheme, path, userinfo, port, query, fragment, or surrounding
  whitespace.
- `cloud_id` is optional in general, but when `allowed_upstream_hosts` includes
  `api.atlassian.com` (the Atlassian gateway) it is required and must be a valid
  UUID.
- `allowed_upstream_hosts` must be non-empty. Each entry is an `https` origin
  with a concrete (non-wildcarded) host; only `*` and `**` are valid wildcard
  path segments, and credentials in the URL are rejected. `*` matches one path
  segment; `**` matches zero or more path segments while still requiring any
  later pattern segments to match. Including `api.atlassian.com` enables the
  gateway and requires a `bearer_token` execution credential (and vice versa: a
  `bearer_token` credential requires `api.atlassian.com` in the allowlist).
- `[providers.jira.attachments]` defaults: `max_bytes` 10 MiB, `max_total_bytes`
  50 MiB, `max_download_bytes` 100 MiB. All three must be non-zero; each
  `media_types` entry must contain a `/`. See the cross-section limits checks in
  [`[limits]`](#limits).
- `[providers.jira.content].comment_formats` is a native-representation
  allowlist and may contain only `adf`; do not add normalized `markdown` or
  `plain_text` values. When `adf` is enabled, comment write action schemas
  advertise `adf`, `markdown`, and `plain_text` through `contentFormat`. When
  the list is empty, required-content comment write actions are omitted from
  the Jira service descriptor, so they are absent from the caller-visible
  catalog and policy grants naming them fail validation as unknown actions. Jira issue-description actions always target ADF
  and continue to advertise all three formats. `max_body_bytes` defaults to 1
  MiB and must be non-zero. It independently bounds write source/final ADF and
  every declared native Jira description or comment body returned by a read or
  mutation readback. Oversized writes return `body_size_denied` (HTTP 413);
  malformed or oversized returned content fails without truncation as the fixed
  sanitized `upstream_protocol_failed` (HTTP 502).
- Normalized write format remains explicit caller input with no write default.
  Read response defaults are separate client presentation settings under
  `[defaults]`; they become top-level Broker request fields and never
  `inputs.contentFormat`.
- `[providers.jira.search].max_results` defaults to `50` and must be non-zero.
- `[providers.jira.comments].max_results` defaults to `50` and must be
  non-zero. `max_property_value_bytes` defaults to `32768`, must be non-zero,
  and must not exceed Jira's 32768-byte property-value cap.
- `[providers.jira.comments].allowed_property_key_prefixes` defaults to
  `["agent-access."]`. Entries must be non-empty ASCII prefixes with no
  whitespace or slash, must not duplicate each other, and must not use reserved
  Jira/JSM/system prefixes such as `sd.`, `jira.`, `atlassian.`, or
  `com.atlassian.`.
- `[providers.jira.comments.allowed_visibility]` defaults to empty, so caller
  inputs cannot set comment visibility restrictions. `type = "group"` entries
  require immutable `identifier`; `value` is optional display text. `type =
  "role"` entries require `value`; `identifier` is optional. Duplicate
  allowlist entries are rejected.
- `[providers.jira.issue_links]` controls the narrow dependency-link action.
  `dependency_link_type` defaults to `Blocks`, `dependency_outward` defaults to
  `blocks`, and `dependency_inward` defaults to `is blocked by`. All three
  values must be non-empty and contain no control characters. At runtime the
  broker fetches Jira issue link types and validates the configured type and
  direction names before creating `issue.dependency.add` links.

### `[providers.confluence]`

```toml
[providers.confluence]
tenant_host = "example.atlassian.net"               # required, lowercase normalized bare host
cloud_id = "00000000-0000-0000-0000-000000000000"   # optional UUID
allowed_upstream_hosts = [
  "https://example.atlassian.net/wiki/rest/api/**",
  "https://example.atlassian.net/wiki/api/v2/**",
  "https://example.atlassian.net/wiki/download/attachments/**",
  "https://api.media.atlassian.com/**",
]

# [providers.confluence.egress_proxy]
# url = "http://confluence-proxy.example:8080"

[providers.confluence.attachments]
max_bytes = 10485760            # 10 MiB; default
max_total_bytes = 52428800      # 50 MiB; default
max_download_bytes = 104857600  # 100 MiB; default
media_types = ["text/plain", "application/json", "image/png", "text/html"]

[providers.confluence.content]
page_formats = ["atlas_doc_format", "storage"]   # supported formats
blog_formats = ["storage"]                       # supported blog formats
comment_formats = ["storage"]                    # supported comment body formats
max_body_bytes = 2097152                          # 2 MiB; default

[providers.confluence.search]
max_results = 50            # default
```

- `tenant_host`, `cloud_id`, `allowed_upstream_hosts`, `[...attachments]`, and
  `[...search]` follow the same rules as Jira above. `tenant_host` must be the
  user-facing Atlassian tenant host because Confluence `webUrl` and `spaceUrl`
  results are normalized from it.
- `[providers.confluence.content].page_formats` is a native-representation
  allowlist containing only `atlas_doc_format` and/or `storage`. Current page
  create/update advertise their enabled native formats and advertise
  `markdown`/`plain_text` only when `storage` is enabled. Returned current page
  bodies expose the configured representations; normalized reads select present
  ADF first, otherwise present storage. It defaults to empty.
- `[providers.confluence.content].blog_formats` and `comment_formats` are native
  allowlists containing only `storage`. Current blog writes, blog drafts, and
  comment writes advertise `storage`, `markdown`, and `plain_text` when storage
  is enabled. Both default to `["storage"]`. Do not add normalized format names
  to these lists.
- Page draft writes use a hardcoded storage target and advertise `storage`,
  `markdown`, and `plain_text` independently of `page_formats`. A config-gated
  required-content action with no effective format is omitted from the
  Confluence service descriptor rather than advertising an unusable enum, so it
  is absent from the runtime catalog and policy grants naming it fail
  validation as unknown actions; direct invocation still fails closed at the
  provider format gate.
- `max_body_bytes` defaults to 2 MiB and must be non-zero. On writes it
  independently bounds the source and complete serialized native body after
  conversion and attribution; overflow returns `body_size_denied`/413. On
  reads it bounds every declared returned storage or ADF body in native,
  embedded, and whole-result modes; malformed or oversized upstream content
  returns sanitized `upstream_protocol_failed`/502. Conversion never truncates
  or falls back to native content. Unsupported write formats return
  `body_format_unsupported`/415.
- Normalized write format has no configuration, environment, or client default.
  Every Confluence rich-content write carries explicit `contentFormat`.
- Service-mode `blog.create` grants require `credentials.lookup.confluence` so
  the broker can resolve the authorized space key to the Confluence v2 `spaceId`
  before submitting the upstream create request. Per-user-only `blog.create`
  policy uses the caller's per-user Confluence credential for that lookup.
- The runtime catalog statically classifies `page.create`, `page.draft.create`,
  and `page.move` as lookup-backed. Service-mode grants for those actions
  require `credentials.lookup.confluence`; per-user-only policy uses the
  caller's per-user Confluence credential for their space, target, hierarchy,
  and parent lookups.
- Service-mode Confluence comment grants require `credentials.lookup.confluence`
  because the broker authorizes comments through the current parent page or blog
  before making the selected-credential comment request.
- Any Confluence draft grant (`page.draft.*` or `blog.draft.*`) requires
  `[broker_tokens].hash_key_ref` to resolve to a valid 32-byte base64url key.
  The broker uses that stable key to sign draft handles so they survive process
  restarts and service-mode handoff.

### `[providers.gitlab]`

```toml
[providers.gitlab]
api_base_url = "https://gitlab.example.com/api/v4"  # required, GitLab REST v4 base
web_base_url = "https://gitlab.example.com"         # required, web URL locator base
allowed_upstream_hosts = ["https://gitlab.example.com/api/v4/**"]

# [providers.gitlab.egress_proxy]
# url = "http://gitlab-proxy.example:8080"

[providers.gitlab.attachments]
max_bytes = 10485760         # 10 MiB; default per-file upload cap
max_total_bytes = 52428800   # 50 MiB; default aggregate cap
media_types = []            # unrestricted; include text/html in any explicit allowlist

[providers.gitlab.content]
max_body_bytes = 1048576      # 1 MiB; default
max_commit_actions = 25       # default
max_file_bytes = 10485760     # 10 MiB; default
max_raw_download_bytes = 104857600  # 100 MiB; default

[providers.gitlab.search]
max_results = 50            # default

[providers.gitlab.webhooks]
allowed_destinations = [
  "https://hooks.example.com/gitlab/**",
  "http://hooks.internal.example/**",
]
allow_disable_ssl_verification = false
```

- `api_base_url` is required and must end in `/api/v4`.
- `web_base_url` is required and is used only to validate and parse GitLab web
  URLs supplied as locators.
- `allowed_upstream_hosts` must include the configured API base path prefix; each
  entry follows the same allowlist syntax as Jira and Confluence.
- `[providers.gitlab.attachments]` declares upload limits: `max_bytes`,
  `max_total_bytes`, and `media_types`.
  `project.upload` accepts exactly one file and enforces both `max_bytes` and
  `max_total_bytes`, plus the global HTTP body and spool limits. These byte caps
  must be nonzero and must not exceed `limits.max_http_body_bytes`;
  `max_bytes` must not exceed `max_total_bytes`. Empty `media_types` permits all
  MIME types, including `text/html`; a nonempty list restricts them. GitLab
  raw downloads use the separate `content.max_raw_download_bytes` setting.
- `[providers.gitlab.content].max_body_bytes` defaults to 1 MiB and independently
  bounds caller-supplied normalized rich-content source bytes, the complete
  native Markdown body after conversion and attribution, and every declared
  issue/MR description or note/discussion body returned in native, embedded, or
  whole-result read mode. It also bounds merge and commit messages under their
  existing contracts. It must not exceed `limits.max_http_body_bytes`.
  Oversized write input returns `body_size_denied`/413; malformed or oversized
  upstream read content returns the fixed `upstream_protocol_failed`/502. No
  path truncates or falls back to a partial/native result.
- GitLab has no content-format allowlist. Each available covered action
  advertises `markdown` and `plain_text` directly in `contentFormat`; plain text
  is escaped into literal GitLab Markdown. There is no content-format config,
  environment override, filename inference, or client default. Callers supply
  the format explicitly and inspect the exact action catalog enum for support.
- Read-response defaults are client-wide, not GitLab provider configuration.
  Use `[defaults].read_content_format`/`output_format` or their environment
  variables described below; only actions advertising the matching capability
  receive a non-default ambient value.
- `[providers.gitlab.content].max_commit_actions` defaults to `25`, must be
  non-zero, and may not exceed `100`.
- `[providers.gitlab.content].max_file_bytes` defaults to 10 MiB and bounds
  decoded REST file create/update and commit action content and structured diff
  patches. It must not exceed
  `limits.max_http_body_bytes`.
- `[providers.gitlab.content].max_raw_download_bytes` defaults to 100 MiB and
  bounds GitLab raw file, current merge-request raw diff, and CI job trace
  downloads. It must not exceed
  `limits.max_download_bytes`.
- `[providers.gitlab.search].max_results` defaults to `50`; it bounds issue/MR
  searches, note/discussion lists, and every merge-request review-context
  collection. It must be non-zero and may not exceed GitLab's single-page REST
  cap of `100`. Draft-note list uses the same caller-visible cap for Broker-
  local slices of GitLab's single non-paginated response array.
- `[providers.gitlab.webhooks].allowed_destinations` defaults to `[]`. The
  absent/empty default denies project-hook creation and URL-changing updates,
  but does not disable catalog actions or management of existing hooks.
  Patterns require `http` or `https`, a concrete host, and optional `*`/`**`
  path segments. Userinfo, wildcard hosts, query components in patterns,
  fragments, invalid wildcard placement, and duplicate-normalized entries fail
  configuration validation. Destination URL queries are ignored for pattern
  matching, but any query change is still a URL change that must match a rule.
  Listing an `http://` pattern is the explicit authorization for plaintext
  delivery; there is no separate global HTTP switch.
- `[providers.gitlab.webhooks].allow_disable_ssl_verification` defaults to
  `false`. When false, creation cannot disable HTTPS certificate verification,
  and a URL-changing update cannot introduce or carry disabled verification
  onto the new destination. URL-preserving updates may preserve an existing
  disabled setting, and enabling verification is always allowed.
- Webhook destination configuration is deployment-wide TOML only. Managed
  policy grants, agent tokens, and the portal continue to express only actions,
  execution context, credential mode, and repository/namespace scope. A
  validated config reload applies the new destination ceiling to subsequent
  create and URL-change requests; it never retroactively quarantines an
  existing hook.
- GitLab REST credentials use `bearer_token` secret material. Managed per-user
  credentials use profile `gitlab-access-token`.
- Service-mode GitLab REST grants require `credentials.lookup.gitlab` because
  project, issue, merge request, note, discussion, branch, and commit actions
  confirm the authoritative project path before final repository-scope
  authorization.
  Per-user-only GitLab policy uses the caller's per-user GitLab credential for
  that lookup.
- Draft-note CRUD/publication and `merge_request.review.submit` should normally
  be granted with `credential_mode = "per_user"`: GitLab makes drafts and
  reviewer state belong to the upstream credential owner. Service mode remains
  valid for an intentional bot reviewer, but every Broker principal sharing
  that credential shares the bot-owned draft set and can affect it when their
  grants allow. A service-mode result must not be represented as the human
  principal's GitLab action.
- Formal approve/unapprove and suggestion application should likewise normally
  use `credential_mode = "per_user"`, because GitLab records the credential
  owner as the approver or source-branch commit author. Approval summary reads
  are free-tier; approval-state and approval-rule reads are Premium/Ultimate.
  Approval readiness and the fixed suggestion batch cap of 100 introduce no
  provider configuration keys.
- Suggestion application on a fork MR resolves both target and source
  repositories. A single selected policy grant must cover all resolved scopes
  using exact repository and/or namespace selectors; the Broker never combines
  grants to obtain coverage. The execution credential must also have GitLab
  push permission on the source branch.
- Attribution wildcard patterns such as `merge_request.*` also match inline
  discussions, replies, draft creation, publish-all summaries, and
  review-submit summaries. Use exact action names when that expansion is not
  intended. Draft update does not append attribution.
- Review participation adds no provider configuration switch. Position and
  draft bodies use the existing content/search bounds; policy grants control
  each action independently. `merge_request.review.submit` proves GitLab 19.2
  or newer at runtime and fails before publication when that minimum cannot be
  established.

### `[providers.cloudbees_ci]`

```toml
[providers.cloudbees_ci]
allowed_upstream_hosts = ["https://ci.example.com/team-ci/**"]
max_log_scan_bytes = 16777216 # default 16 MiB

[providers.cloudbees_ci.controllers.team-ci]
base_url = "https://ci.example.com/team-ci/"
# web_base_url = "https://ci-public.example.com/team-ci/" # optional
```

The provider requires at least one named controller. Controller aliases use the
broker service-name grammar. Each `base_url` must be a normalized absolute
controller URL ending in `/`, with no credentials, query, or fragment.
Production requires HTTPS. Optional `web_base_url` has the same URL validation
and identifies the public Jenkins root when it differs from the Broker-reachable
API root. The provider only validates and returns matching upstream URLs using
that value; it never sends requests there. The allowlist must cover every
generated job, build, queue, and artifact API path under each `base_url`;
an artifact storage redirect also needs an explicit HTTPS allowlist entry.
Controller Basic credentials are sent only to the configured controller base.
A request outside the allowlist fails closed. Core Jenkins JSON reads use fixed
`tree` projections; Pipeline REST reads use fixed endpoints and project the
returned fields. Upstream JSON responses are capped at the smaller of the Broker's
response-size limit and 1 MiB. Artifact, console-log, and test-report downloads
share the global `limits.max_download_bytes` cap. Console and test-report
downloads reject redirects. Bounded log reads use head, tail, or literal-search mode.
`max_log_scan_bytes` caps consumed source bytes, including replayed continuation
prefixes; it must be positive and at most `limits.max_upstream_response_bytes`.
Returned text has a separate `maxBytes` budget (1024–65536; default 16384). Reads
have a total deadline of the smaller of 20 seconds and
`limits.request_timeout_ms`, plus the streaming idle timeout. Tail must reach EOF;
head/search report incomplete coverage at the scan ceiling without an unusable
continuation. Raising the text budget does not raise the scan ceiling.
`[providers.cloudbees_ci.egress_proxy]` uses the usual provider proxy shape.
Only `basic_api_token` execution credentials are supported, from a service
secret or the `cloudbees-ci-api-token` managed per-user profile. See
[the provider contract](providers-cloudbees-ci.md).

### `[providers.teams]`

```toml
[providers.teams]
allowed_upstream_hosts = ["https://YOUR-ENVIRONMENT.environment.api.powerplatform.com/**"]
```

Teams requires managed policy, `[managed_store]`, and `[credential_encryption]`.
The allowlist contains exact commercial-cloud Power Platform HTTPS origins on
port 443 followed by `/**`; hostname wildcards, private paths, and signed query
strings are rejected. Optional `egress_proxy` uses the shared proxy settings.
The full signed Workflow URL belongs only in the exact destination resource's
private `webhookUrl` attribute, entered through admin management. TOML endpoints,
static/managed policy overlays, and separate Teams credentials are unsupported.
See [Teams Workflows](providers-teams.md) for trigger settings and grants.

### `[providers.fake]`

```toml
[deployment]
enable_fake_service = true

[providers.fake]
```

The development `fake` backend has no settings. It serves one `fake.echo`
action authorized against `fake_project` resources and needs no execution
credential. It is accepted only with `deployment.enable_fake_service = true`,
which production rejects.

## `[gateways]`

`[gateways]` configures host-matched broker endpoints whose public hostnames
are distinct from the normal broker API. The supported kind is `git_http` for
Git smart HTTP. Fetch discovery/upload-pack and push discovery/receive-pack
forwarding are implemented. Receive-pack POST bodies are parsed before upstream
credential use so malformed command lists, denied refs, delete/tag updates, and
denied capabilities fail closed before forwarding. Each `[gateways.<name>]`
entry becomes a service whose name is the config key and whose policy actions
are `repo.fetch` and/or `repo.push`.

Gateway config participates in normal validation and reloads, but it does not
bind network traffic by itself. Run `agent-access-broker serve` with
`--gateway-listen <addr>` to expose the dedicated gateway listener. The public
listener continues to serve `/v1` and `/ui`; those routes are not mounted on the
gateway listener.

```toml
[gateways.gitlab_git]
kind = "git_http"
display_name = "GitLab Git"
broker_hosts = ["git.example.com"]
upstream_base_url = "https://gitlab.example.com"
allowed_upstream_hosts = ["https://gitlab.example.com/**"]
auth_modes = ["basic_broker_token"]
basic_broker_token_username = "agent-access" # default
credential_modes = ["service"]               # service and/or per_user
redirect_policy = "none"                     # default; only supported value
correlation_headers = true                   # default
request_body_max_bytes = 536870912           # optional
response_body_max_bytes = 536870912          # optional
streaming_idle_timeout_ms = 30000            # optional

# [gateways.gitlab_git.egress_proxy]
# url = "http://git-proxy.example:8080"

[gateways.gitlab_git.git]
allow_fetch = true
allow_push = true
deny_ref_patterns = ["refs/heads/main"]
deny_delete_refs = true
receive_pack_prefix_max_bytes = 65536

[[policy.resources]]
id = "git-project"
resource_type = "git_repository"
selector = { kind = "exact", value = "team/project" }
allowed_execution_contexts = ["internal"]
enabled = true

[[policy.resources]]
id = "git-team"
resource_type = "git_repository"
selector = { kind = "namespace", value = "team" }
allowed_execution_contexts = ["internal"]
enabled = true

[[policy.grants]]
subjects = ["group:project-team"]
service = "gitlab_git"
actions = ["repo.fetch", "repo.push"]
resources = { resource_ids = ["git-project", "git-team"] }
execution_contexts = ["internal"]
credential_mode = "service"
```

Gateway keys (`[gateways.<name>]`):

- `kind` must be `git_http`; other values are rejected.
- `display_name`, `broker_hosts`, `upstream_base_url`,
  `allowed_upstream_hosts`, `auth_modes`, and `credential_modes` are required.
- `broker_hosts` lists exact lower-case DNS hosts handled by this gateway. No
  wildcard, placeholder, port, path, userinfo, trailing dot, or IP literal is
  accepted. A broker host can belong to only one gateway service.
- `upstream_base_url` must be an `https` URL without credentials, query, or
  fragment. A path prefix is allowed and is prepended to forwarded Git paths.
  The upstream must serve `.git` smart HTTP endpoints: the gateway accepts
  client repository URLs with or without `.git` and always uses `.git` for
  upstream discovery, fetch, and push. Repository authorization is unchanged.
- `allowed_upstream_hosts` follows the same allowlist rules as providers.
- `auth_modes` currently accepts only `basic_broker_token`. Git clients send a
  broker token using HTTP Basic auth; the username must equal
  `basic_broker_token_username`.
- `credential_modes` is required (non-empty); each value must be `service` or
  `per_user` and must have a matching configured credential for the gateway
  service.
- `redirect_policy` must be `none`; upstream redirects are not followed.
- `correlation_headers` controls whether forwarded upstream Git requests carry
  `X-Agent-Access-Request-Id` and `X-Agent-Access-Broker-Request-Id`.
- Request/response size caps and idle timeout are optional. When omitted they
  inherit `limits.max_http_body_bytes`, `limits.max_upstream_response_bytes`,
  and `limits.streaming_idle_timeout_ms`; when set they must be non-zero, and
  gateway request/response caps must not exceed the corresponding global
  limits. Git gateway transfers are not bounded by the global total
  `limits.request_timeout_ms`; that limit is used for upstream connect
  liveness, while `streaming_idle_timeout_ms` bounds stalled request uploads,
  upstream response header waits, and response body streaming.
- `egress_proxy` is an optional per-gateway outbound proxy.

Git settings (`[gateways.<name>.git]`):

- Required for `kind = "git_http"`.
- At least one of `allow_fetch` or `allow_push` must be `true`.
- `allow_fetch = true` exposes and forwards `repo.fetch`.
- `allow_push = true` exposes and forwards `repo.push`. Receive-pack command
  prefixes are parsed before upstream credential use; malformed pkt-lines,
  denied capabilities, tag updates, delete-ref updates, and configured denied
  ref patterns are rejected before forwarding.
- Upload-pack POSTs may forward one canonical `Content-Encoding: gzip` header
  with an opaque request body. Discovery requests, receive-pack POSTs, duplicate
  or unsupported `Content-Encoding` headers, and all `Trailer` headers are
  rejected before upstream forwarding.
- `deny_ref_patterns` contains exact Git ref names or suffix `/**` patterns
  such as `refs/heads/release/**`.
- `deny_delete_refs` denies zero-new-object ref updates when `true`; it defaults
  to `true`.
- `receive_pack_prefix_max_bytes` caps the buffered receive-pack command prefix
  before the pack body is streamed upstream. When omitted, the broker uses a
  conservative 1 MiB default, further capped by `request_body_max_bytes`. Prefix
  size must be non-zero when set.

Gateway services appear in `/v1/services` and `/v1/capabilities` with
`surface = "gateway"`, `gatewayKind`, `brokerHosts`,
`credentialVerificationInputs = ["repository"]`, and `resourceScopes` metadata. Their actions are grantable policy actions, not `/v1/invoke` actions.
For managed per-user Git gateway credentials, credential verification requires a
repository input and performs a read-only `repo.fetch` authorization check before
probing upstream with `git-upload-pack` discovery. The verification probe uses
`streaming_idle_timeout_ms` for stalled response header waits and discovery body
reads.

## Egress proxy configuration

An egress proxy can be configured at five scopes:

- `network.egress_proxy` (global)
- `providers.jira.egress_proxy`
- `providers.confluence.egress_proxy`
- `providers.gitlab.egress_proxy`
- each `gateways.<name>.egress_proxy`

Each `EgressProxyConfig` is `{ url, username_ref?, password_ref? }` and obeys
the same rules:

- The `url` must be a bare origin: `http` or `https`, a host is required, no path
  beyond `/`, no query, no fragment, and no embedded userinfo.
- `username_ref` and `password_ref` must both be present together (or both
  absent), each an `env:`/`file:` ref.
- An `http` (non-`https`) proxy URL with either credential ref is rejected.

The runtime resolution precedence (`NO_PROXY` -> environment proxy -> service
scope -> global -> direct) is described in `docs/design.md`. Delegated OAuth
requests have no service scope and use the global resolution, except that a
literal loopback registration `base_url` connects directly.

## `[limits]`

```toml
[limits]
auth_requests_per_principal_per_minute = 100
auth_requests_per_source_per_minute = 300
max_concurrent_requests = 100
max_concurrent_requests_per_principal = 10
max_http_body_bytes = 536870912           # 512 MiB
max_download_bytes = 104857600            # 100 MiB
max_upstream_response_bytes = 536870912   # 512 MiB
request_timeout_ms = 30000
request_body_timeout_ms = 300000          # five-minute total inbound body deadline
streaming_idle_timeout_ms = 30000
upload_spool_dir = "<cwd>/target/agent-access-upload-spool"
upload_spool_max_bytes = 2147483648       # 2 GiB (= max_http_body_bytes * 4)

[limits.invocations]
default = { requests = 100, window = "1m" }   # optional; built-in default shown

[limits.invocations.services.jira]            # optional per-service default
requests = 20
window = "1m"

# Only valid with identity.authority = "toml".
[[limits.invocations.principal_overrides]]
principal = "alice"
service = "jira"
requests = 10
window = "1m"
```

### Service invocation limits

`[limits.invocations]` limits how often one principal may invoke each backend
service. Each `(principal, service)` pair has one rolling window: at most
`requests` admitted requests in any trailing `window`. The anonymous principal
is an ordinary key. Many principals commonly share one source address (for
example everything arriving through a shared ingress proxy), so service-invocation limits are never
keyed on the source address.

A request is counted once, when it is admitted, however many upstream calls it
later makes:

- `POST /v1/invoke/{service}/{action}` in every IO form (JSON, raw download,
  multipart upload). The CLI and local stdio MCP reach the broker this way.
- HTTP MCP `tools/call` for tools that dispatch a service action.
- Git gateway `git-upload-pack` and `git-receive-pack` POSTs, counted against
  the gateway's service name. Ref discovery (`GET .../info/refs`) is not
  counted, but every pack POST is, including protocol v2 `ls-refs` POSTs,
  additional fetch negotiation rounds, and a push's probe POST, so one fetch
  or clone typically costs two or more. Leave room for that in gateway limits:
  a limit of 1 makes protocol v2 fetches impossible (see
  [Git HTTP gateway](git-http-gateway.md)).

Nothing else is counted: discovery (`/v1/services*`, `/v1/capabilities`),
runtime specs, `/v1/me`, MCP protocol messages and discovery helper tools,
self-service and admin management, and authentication routes. The count is
taken after identity resolution and after the service is known to be
configured, and before policy evaluation, credential selection, pre-policy
resource lookups, and upstream calls. Requests later denied by policy still
count; a request rejected by the limit is never recorded. Unknown services are
rejected by existing validation and never create limiter state.

The effective limit for a principal and service is the first of:

1. The principal's override for that service: `principal_overrides` with
   `identity.authority = "toml"`, or the managed store's
   `principal_service_limits` table with `identity.authority = "managed"`.
2. The service's limit, `[limits.invocations.services.<service>]`.
3. `[limits.invocations].default`.
4. The built-in default: 100 requests per `1m`.

Limits are read on every admission, so reloads and managed-store override
changes apply to the next request without a restart. Limiter history is held
in memory per broker process and survives reloads. When the effective window
length for a key changes, that key's history resets; when only `requests`
changes, the existing history is evaluated against the new value.

The window is kept as 60 sub-buckets per key. The broker never admits more
than `requests` in any trailing `window`, may be conservative by at most
`window / 60`, and memory per key does not depend on `requests`. Idle keys are
pruned by a periodic amortized sweep; there is no global key capacity that
could reject other principals.

Validation:

- `requests` is an integer from 1 to 1,000,000.
- `window` uses the broker duration syntax (`s`, `m`, `h`, `d`) and must be
  from `1s` to `1d` inclusive.
- `services.<service>` keys must be configured services (provider kinds and
  gateway names).
- `principal_overrides` is rejected unless `identity.authority = "toml"`. Each
  entry must name a configured static principal (or `anonymous`) and a
  configured service; duplicate `(principal, service)` pairs are rejected.
  Managed deployments store overrides in the managed store (see
  [database](database.md#principal-service-limits)).
- Unknown fields are rejected.

Rejected invocations return HTTP 429 `rate_limited` with a `Retry-After` header
and the reserved `broker/request.admit` envelope without a `result` (see
[HTTP API](http-api.md#rate-limits)).

### Authentication budgets and concurrency

The `auth_requests_per_*_per_minute` budgets protect authentication: local
login and password changes use the source budget and a principal budget keyed by
`(principal, source)`, so requests from one source cannot exhaust a user's
login budget at another. Every authentication-class use of
`auth_requests_per_source_per_minute` keys on the same grouped source as
local-password lockout (full IPv4 address; IPv6 /64 prefix; embedded IPv4 for
IPv4-mapped and `64:ff9b::/96` NAT64 addresses), so rotating addresses within
one IPv6 /64 does not reset it. Logs and audit keep the full address. Only the
well-known NAT64 prefix is recognized: clients reaching the broker through a
translator with a network-specific prefix (for example `64:ff9b:1::/48`) are
grouped by that /64 like any IPv6 address, so they share one authentication
source budget and one lockout source. Point `trusted_proxies` at such a
translator only if it forwards client addresses, or raise the authentication
budgets for it.
Before authentication, local login likewise holds a per-principal concurrency
slot keyed by `(principal, source)`, not the principal's own slots. Microsoft
OIDC login uses the source budget. Unauthenticated calls and invalid credentials,
including missing or invalid browser sessions, use authentication budgets.
Anonymous access on routes that permit it also shares the authentication
principal budget under its anonymous principal (anonymous service invocations
additionally count against the `anonymous` invocation limit). Malformed
execution-context and Git gateway classification requests use the
authentication source budget. These budgets use fixed 60-second windows starting
at the first counted request, held in memory per broker process, and reject with
HTTP 429 `rate_limited`. Ordinary control-plane routes verify supplied identity
before JSON/byte extraction. Anonymous or invalid identities spend the source
budget before body consumption; verified tokens and browser sessions remain
exempt. Password login and change always spend their authentication budgets.
A request spends the source budget at most once. Authenticated API, discovery,
spec, and management traffic does not consume it.

HTTP admission acquires the global concurrency permit before body extraction
or identity lookup and shares it with the handler and any supervised operation.
Health/readiness probes and bodiless portal asset reads bypass this admission;
downstream HTTP MCP has independent admission. Anonymous control-plane body reads
also use a pool capped at `max(1, max_concurrent_requests / 4)` and a per-source
slot capped by `max_concurrent_requests_per_principal`, released when the body
finishes. Source grouping matches the authentication budget. Verified management
identities bypass both anonymous limits, including behind the same source as a
stalled login. Instead, verified control-plane bodies hold a per-principal body
slot capped by `max_concurrent_requests_per_principal` until the body completes.
This pool is independent from handler execution permits and shared across
reloads; multiple tokens for one principal share it. Body slots apply only while
a body remains to be received. Bodiless writes, including owner pause/revoke,
bypass body slots while retaining authentication rate checks and handler execution
admission. A global limit of one cannot
reserve a separate authenticated slot.
Invocation and Git handlers authenticate before consuming bodies and retain their
existing caller admission.

Browser authentication bodies are capped at 16 KiB; control-plane JSON and
management bodies are capped at 1 MiB. Both are additionally limited by
`max_http_body_bytes` and the startup hard cap. Invocation JSON retains the
configured transfer cap so provider inline-content limits remain usable.
Multipart JSON metadata has a 1 MiB cap; file parts and Git uploads use the
configured transfer cap. Browser-auth bodies have a five-second total receive
ceiling, other control-plane bodies fifteen seconds. A smaller configured
`request_body_timeout_ms` also applies to these routes. Invocation and Git bodies
use `request_body_timeout_ms` directly (five minutes by default). All total
receive deadlines start at admission and progress does not reset them. Public
body idle timing uses `streaming_idle_timeout_ms`; Git retains its matched
gateway idle setting and byte-limit reason codes. Control-plane receive timeouts
return HTTP 408 with an explicit deadline message. Invoke timeouts retain
`body_malformed` with a distinct deadline message; Git retains its timeout reasons.
Downstream HTTP MCP uses its own configured intake limits.

Identity resolution precedes caller-specific checks. Consequently, rate rejections do not avoid the
identity lookup itself. Local login retains rate checks before password hashing.

Global and per-principal concurrency safeguards apply to every caller,
including verified browser sessions; they reject with `concurrency_limited`.

The values above are the built-in defaults. All numeric limits must be non-zero
and `upload_spool_dir` must be non-empty. `upload_spool_max_bytes` defaults to
`max_http_body_bytes * 4`.

`upload_spool_dir` participates in runtime state-lock admission even when no
current provider action is uploading at startup. The broker creates or validates
the directory, canonicalizes it, and locks `.agent-access-broker.spool.lock`
inside that directory before serving traffic or admitting a reload candidate.

Cross-section consistency checks tie the provider attachment limits from
[`[providers]`](#providers) back to these broker-edge limits:

- `providers.<svc>.attachments.max_total_bytes` and `max_bytes` must not exceed
  `limits.max_http_body_bytes`, and `max_bytes` must not exceed
  `max_total_bytes`.
- `providers.<svc>.attachments.max_download_bytes` must not exceed
  `limits.max_download_bytes`.
- An HTTP route's `max_response_body_bytes` must not exceed
  `limits.max_upstream_response_bytes`.

## `[audit]`

```toml
[audit]
type = "sqlite"                # required: sqlite | jsonl
path = "/var/lib/agent-access-broker/audit/audit.sqlite"   # required
retention_days = 30            # default
queue_capacity = 1024          # default
# terminal_queue_capacity = 100 # default = limits.max_concurrent_requests
enqueue_timeout_ms = 1000      # default
durability = "write"           # write | sync_data | sync_all; default

# JSONL only:
# rotate_bytes = 104857600     # 100 MiB; default
```

- Audit is disabled when `[audit]` is absent. When it is present, `type` and
  `path` are required. Unknown fields are rejected.
- `type = "jsonl"` writes one JSON line per record to `path`, rotates it to
  `<path>.<UTC timestamp>Z.<uuid>` at `rotate_bytes`, and deletes rotated files
  older than `retention_days`. Retention deletes only files whose names match
  that rotated-file pattern, never the state lock file or any other file that
  shares the `<path>.` prefix.
- `type = "sqlite"` writes each record to a standalone SQLite database at
  `path`, separate from the managed store. The broker creates the file
  owner-only (`0600`) before SQLite opens it, never follows a symlinked path,
  and keeps the `-wal`/`-shm` sidecars owner-only. `serve` creates the
  database if it is missing and always applies pending audit migrations at
  startup (there is no `auto_migrate` switch); a database with unknown or
  mismatched migrations fails startup, and the broker never resets or deletes
  audit data. Opening checks only the catalog (migration ledger, schema,
  `journal_mode = wal`, `auto_vacuum = incremental`, and the database's
  `database_id`), never a full scan. Records are committed in batches of at
  most 256 records and 16 MiB, and each request's acknowledgement waits for
  the commit that contains its record. A record whose serialized JSON plus
  full-text text exceeds 16 MiB fails only its own append. Retention deletes
  expired rows in bounded slices at most once an hour, between queued audit
  work; optional compaction slices (full-text merge, incremental vacuum,
  `PRAGMA optimize`, and a passive WAL checkpoint) never affect readiness.
  `agent-access-broker --config <file> audit verify` checks the database
  offline (see below). With `[management]` enabled, a SQLite audit store also
  serves the [audit query routes](http-api.md#audit-queries), the
  `agent-access audit` and `agent-access admin audit` commands, and the
  portal's Audit and Activity pages; JSONL records are not queryable through
  the broker.
- `path` may be relative. Its parent directory is created owner-only on
  startup, and it must not resolve to the `managed_store.path` database.
- `rotate_bytes` is valid only with `type = "jsonl"`, where it defaults to
  100 MiB; setting it with `type = "sqlite"` fails validation.
- `rotate_bytes`, `retention_days`, `queue_capacity`, and
  `enqueue_timeout_ms` must be non-zero. If `terminal_queue_capacity` is set, it
  must also be non-zero.
- `queue_capacity` bounds normal audit append and readiness probe work waiting
  on the dedicated audit writer. `enqueue_timeout_ms` bounds how long a request
  may wait for writer capacity before failing closed with `audit_unavailable`.
- `terminal_queue_capacity` reserves writer capacity for streamed-response
  terminal audit records. When audit is enabled, an explicit value must be at
  least `limits.max_concurrent_requests`; when omitted, the effective value is
  exactly `limits.max_concurrent_requests`.
- `durability = "write"` performs normal OS writes only: it is page-cache-only
  and is not crash-durable across an OS or host failure. For JSONL, `sync_data`
  calls `fsync`-equivalent data sync after each record and durable rotation
  metadata syncs, and `sync_all` additionally syncs file metadata. For SQLite,
  `write` sets `synchronous = NORMAL` (survives a broker crash; the latest
  records may be lost on power loss), `sync_data` and `sync_all` set
  `synchronous = FULL` (each commit is synced), and `sync_all` also syncs the
  parent directory after creating the database file. The sync modes trade
  throughput for stronger local durability.
- `serve` and reload admission lock a sibling `<path>.agent-access.lock` file
  before the audit writer can write records.
- Reload rejects a change of `type`, including adding or removing `[audit]`,
  with `config_admission_failed`; that change requires a restart. A new `path`
  with the same `type` is opened and validated before activation, and the
  reload record is written to the new store (required) and the old store (best
  effort). Reload never creates or migrates a SQLite audit database, so a new
  SQLite `path` must name a database that a broker startup already created.
  Other settings apply to the new generation's writer.
- Every record carries `auditId` (a UUIDv7 unique to that record) and `nodeId`
  (the effective `deployment.node_id`), assigned by the writer when it accepts
  the record.

`agent-access-broker --config <file> audit verify` runs offline against a
`type = "sqlite"` audit database. It takes the audit state lock (so the broker
must be stopped), checks the catalog as startup does without migrating, runs
`PRAGMA integrity_check` and the full-text index integrity check, prints each
result, and exits `1` if any check finds a problem. With `type = "jsonl"` or
audit disabled it exits `2` (usage error); an invalid config exits `3`.

## CLI client config and `config validate`

The `agent-access` CLI reads a separate `CliConfig` file (sample:
`agent-access.sample.toml`), with `deny_unknown_fields`:

```toml
[service]
url = "http://127.0.0.1:8787"   # default

[service.tls]
verify_certificates = true      # default
additional_ca_cert_files = []   # optional PEM CA/self-signed broker cert files

[identity]
# token_env = "AGENT_ACCESS_TOKEN"
# token_file = "~/.config/agent-access/token"
header = "X-Agent-Access-Identity-Token"   # default
scheme = "raw"                             # default; raw | Bearer
disabled = false                           # default

[defaults]
read_content_format = "native"             # native | markdown | text
output_format = "json"                     # json | markdown
```

`validate_cli_config` enforces:

- `service.url` must use the `http`, `https`, or `unix` scheme. A non-local
  `http` URL is rejected unless `identity.disabled` is `true`.
- `service.tls.verify_certificates` defaults to `true`. With verification
  enabled, the CLI keeps rustls certificate-chain and hostname verification and
  adds any parsed `service.tls.additional_ca_cert_files` certificates to the
  default trust store.
- `service.tls.additional_ca_cert_files` entries are trimmed and must be
  non-empty in both verification modes. Entries support `~` and `~/...`
  current-user home expansion; `~user/...` is literal. Relative paths resolve
  relative to the current working directory. Missing files are ignored, but
  existing directories, unreadable files, empty files, files with no valid
  certificate, malformed certificates, non-`CERTIFICATE` PEM blocks, or
  non-whitespace text outside PEM blocks are validation errors when
  `verify_certificates = true`.
- `service.tls.verify_certificates = false` disables certificate-chain and
  hostname verification for broker HTTPS requests. In that mode certificate
  file paths are not expanded, checked for existence, read, or parsed, but empty
  entries are still rejected.
- `identity.header` must be a valid header name.
- `identity.header` must not equal reserved `X-Agent-Access-Context`.
- `identity.scheme` must be `raw` or `Bearer`.
- `identity.token_env`, if set, must be a valid environment variable name.
- `identity.token_file`, if set, must be non-empty. `agent-access config
  validate` does not expand `~` or require the referenced file to exist.
- `defaults.read_content_format` must be `native`, `markdown`, or `text`.
- `defaults.output_format` must be `json` or `markdown`.

The corresponding environment variables are
`AGENT_ACCESS_READ_CONTENT_FORMAT` and `AGENT_ACCESS_OUTPUT_FORMAT`. Resolution
uses command flag, then client config, then environment, then the built-in
`native`/`json` defaults. The CLI determines config-key presence from the parsed
TOML document, so an explicitly present default still occupies the config tier.
Invalid config or environment values fail locally.
Valid non-default ambient values are omitted for commands whose actions do not
advertise the capability. `send` is file-driven and never injects these ambient
defaults.

`agent-access config validate` runs `validate_cli_config_file` locally with no
broker call, using the same core config and closed-format contract as command
execution. On success it prints `cli config valid: <path>` and exits `0`; on a
validation or load error it prints the errors and exits `3`. It also parses any
existing `service.tls.additional_ca_cert_files` entries when certificate
verification is enabled; missing files are intentionally ignored so a shared CLI
config can list host-specific trust-anchor locations.

The CLI config has no execution-context header setting, and invoke/send/typed
commands have no flag that sets it. Trusted ingress, not a caller or CLI token
file, supplies `X-Agent-Access-Context`.

When `identity.token_file` is configured, `agent-access auth token set`,
`status`, and `clear` provide local management for that file. `set` prompts for
the token, or accepts `--token-stdin`, and writes the trimmed token plus a
newline. `clear` truncates the file instead of deleting it. Existing token files
are truncated in place so owner, mode, ACLs, and inode are preserved; newly
created files use owner-only permissions on Unix.

Normal token resolution treats a missing or empty configured
`identity.token_file` as absent and falls through to lower-priority sources. An
unreadable configured file remains a CLI input/config error. Explicit token
sources such as `--token-file`, `--token-env`, and `AGENT_ACCESS_TOKEN_FILE` are
strict and fail when missing, unreadable, or empty.

The global CLI `--token-file` and `--token-env` flags are broker identity token
sources only. They do not provide upstream credential secret fields for
`credentials put` or `admin credentials put`; those commands use generic
schema-field sources such as `--field-file token=PATH`,
`--field-env token=ENV_VAR`, or `--field-stdin token`.

Broker-call commands resolve the effective CLI config and identity token once
per process invocation and reuse those settings for every request the command
performs. Multi-request commands such as `credentials put --verify` therefore
do not reread `--config` between schema fetch, put, and verify requests.

The local `agent-access auth git-credential get` command uses the same effective
token resolver and precedence as broker-call commands. It therefore preserves
identity-disabled behavior, token normalization, config discovery, and existing
token-source handling instead of maintaining a separate Git credential. The
helper rejects the otherwise highest-precedence `--token-value` source so token
material is not supplied in process arguments; `--token-file`, `--token-env`,
config, and environment sources retain their normal order. Configure Git to
invoke it only for a URL-specific brokered Git host; the helper itself is
intentionally host-agnostic. Its `store` and `erase` operations never write or
clear the configured Agent Access token.

For CLI identity token-file sources only, a leading `~` or `~/` expands to the
current user's home directory before the file is read or written. This applies
to config `identity.token_file`, global `--token-file`, and
`AGENT_ACCESS_TOKEN_FILE`; `~user` and unrelated file arguments are not
expanded.

`agent-access-broker config validate` is also an offline schema/configuration
check. It does not acquire managed-store, audit, or upload-spool state locks and
does not fail merely because a live broker currently owns those runtime locks.
`serve` startup and reload admission perform the runtime lock checks.

Both sample configs (`agent-access-broker.sample.toml` and
`agent-access.sample.toml`) pass the in-crate `sample_configs_validate` test.

For the full client flag/env/config precedence and exit codes, see
`docs/cli.md`.

## GitLab bot provisioning limits

`[providers.gitlab.provisioning]` accepts `enabled` (default false),
`max_access_level` (default 30), `max_token_lifetime_days` (default 30, range
1–365), and `allowed_token_scopes` (default api/read_api/read_repository).
These operator-owned caps apply alongside repository grants and upstream
permissions. See [GitLab bot provisioning](gitlab-bot-provisioning.md) for allowed
values, exact actions, and the issued-credential boundary.

### Trusted managed identity

Configuring `managed_store` requires `credential_encryption`, even under TOML
identity authority. Every human has an identity-access gate; new humans also
receive encrypted UUID v4 identity-token inventory during manual, bootstrap and
OIDC creation when encryption is configured. Service accounts receive neither.
Login never recreates removed inventory. Username access is independent of
whether inventory exists.

```toml
[identity.trusted_callers.managed_client]
credential_ref = "file:/run/secrets/managed-client-attestation"
credential_transport = "authorization_user"
username_namespace = "managed_workspace"
context_mode = "fixed"
execution_context = "workstation"

[identity.trusted_callers.identity_ingress]
credential_ref = "file:/run/secrets/ingress-attestation"
credential_transport = "caller_authorization"
username_namespace = "managed_workspace"
context_mode = "asserted"
allowed_execution_contexts = ["external", "workstation"]
allow_forwarded_identity = true
```

`credential_transport` accepts exactly `caller_authorization` (default) or
`authorization_user`. `username_namespace` is optional for dedicated-carrier
callers and required for direct callers. Its presence enables username assertions,
requires managed identity/storage and uses the safe configuration identifier
grammar. A direct caller must use fixed context and cannot enable fingerprint
forwarding. `allow_forwarded_identity` retains its fingerprint-only meaning.
A dedicated caller can permit both representations; a request cannot combine them.

Caller credentials must be unique. Direct caller credentials cannot match static
principal credentials or start with `aab_`. Username-capable secrets must contain
16–8192 visible ASCII bytes excluding commas and whitespace. Secret files hold
only the raw credential; the attester adds `Bearer `. Secrets are loaded on
startup/reload. Changing loaded caller security settings or secret contents
invalidates attested MCP sessions. An unchanged reload preserves them.

Direct username requests send `Authorization` plus `X-Agent-Access-User` on
`/mcp` or `/mcp/{service}` only. Relayed requests use
`X-Agent-Access-Caller-Authorization` plus that user header. Exact names are
1–128 ASCII bytes from `[A-Za-z0-9._@+-]`; the caller's namespace and an explicit
managed binding select the human. No query parameter, alternate header, cookie,
principal-ID inference or account provisioning supplies identity. The user header
is reserved from `identity.sources.*.header` and `browser_auth.csrf_header` and
rejected on other routes, including REST and Git.

Fingerprint requests send `X-AW-Identity-Token-SHA256: sha256:<64 lowercase hex>`
with the dedicated caller credential. Without a user assertion, an explicit
ordinary token keeps precedence, including denial for an invalid token. Every
supplied caller credential is validated in its configured transport even beside
ordinary authentication. Direct-only secrets cannot be used in the dedicated
carrier to acquire context authority. No caller credential alone authenticates
a human. See [Trusted callers](trusted-callers.md) for parsing and failure rules.

Fixed callers omit `X-Agent-Access-Context`; asserted callers provide one approved
context on governed requests and cannot inherit the direct default. Ordinary
clients without trusted assertions use `execution_context.default_context`, or
fail if none is configured. An absent execution-context section retains built-in
`default`. Attesters must control their assertions and credentials and use verified
HTTPS or an equivalent trusted local channel.

Git gateways opt into token-free fingerprint identity with
`allow_forwarded_identity = true`. All gateways validate protected assertions
regardless of that opt-in, and invalid explicit Basic credentials never fall back.
Username identity is not supported on Git. See [Managed identity](managed-identity.md)
for binding administration, shared pause, inventory and rotation.

Inventory mutations and administrator user creation serialize with configuration
reload. A request admitted under a retired configuration is rejected before it
can encrypt inventory using the old key ring, and the reload fence remains held
until its database write finishes even if the HTTP caller disconnects. OIDC JIT
performs this generation check after the external exchange. Initial-administrator
bootstrap into an empty store is startup-only; a reload that would bootstrap a
new administrator is rejected without provisioning one.

## Delegated upstream OAuth

The `[oauth.registrations]` configuration and delegated credential bindings are
documented in [oauth.md](oauth.md). They require managed storage/encryption and
browser management. A registration's `adapter` must name a linked OAuth dialect:
`google` for Gmail, `mcp_oauth` for approved imported MCP services, or the
development-only `stub`. This is separate from Microsoft OIDC browser login.
OAuth requests follow the global egress proxy resolution; a literal loopback
`base_url` connects directly.

## Gmail OAuth

`[providers.gmail]` has no settings and requires `credentials.per_user.gmail` of type
`oauth`. The `google` dialect fixes Google endpoints and accepts `openid` plus
`gmail.modify`, target `me`, audience `https://gmail.googleapis.com/`, form encoding,
`client_secret_post`, and `preserve_old` rotation. See the complete
[Gmail configuration fragment](providers-gmail.md#setup).

## Imported services operator controls

`[imports]` controls database-managed integrations independently of built-in
`[providers]` configuration. It is disabled by default. Enabling requires managed
identity and policy authority, a managed store, credential encryption, and enabled
management. It never contacts upstream during startup or reload.

```toml
[imports]
enabled = false
allowed_kinds = ["mcp_http"]
allowed_endpoints = ["https://tools.internal.example/mcp"]
disabled_services = []
```

The endpoint allowlist uses the same origin/path matching rules as upstream host
allowlists; prefer exact URLs. HTTPS is required except loopback HTTP outside
production. Administrators manage import definitions; auditors can inspect definitions and
saved previews without running discovery or changing state. Disabling imports
or naming a service in `disabled_services` prevents discovery and execution while
retaining definitions, grants, credentials and delegated manager assignments.
Credential deletion and disabling/retirement remain available.

Imported integrations grant whole actions without resource scopes.
Service and per-user credential ownership use existing grant selection rules.
Imported credential bindings come from the effective runtime catalog, separately
from the TOML credential definitions. See the [import workflow and supported
limits](imported-services.md).

## Imported MCP OAuth

Imported MCP services can use operator-approved `mcp_oauth` registrations and
individual user connections. See [registration and lifecycle setup](imported-oauth.md).

Each `[oauth.registrations.<registration>.permission_profiles.<profile>]` accepts
`scope_mode = "explicit"` (the default) or `scope_mode = "server_default"`.
Explicit mode requires a nonempty `scopes` list. Server-default mode is supported
only by `mcp_oauth` and rejects any supplied `scopes` field, including an empty
list. Unknown modes and registrations mixing profile modes are rejected.
`audience` and `target` remain required and must equal the configured MCP
`adapter_settings.resource` and imported endpoint exactly.

```toml
[oauth.registrations.internal_tools.permission_profiles.default]
scope_mode = "server_default"
audience = "https://tools.example.com/mcp"
target = "https://tools.example.com/mcp"
```

This mode omits the `scope` parameter from authorization, code exchange and
refresh requests. It delegates permission selection to the authorization server
without inventing scope names. It does not relax issuer, metadata, endpoint,
callback, PKCE or resource binding checks. Changing modes invalidates existing
connections and pending consent for that registration. Unchanged explicit
registrations retain their connections, whether `scope_mode` is omitted or set
to `"explicit"`.

OpenAPI imports use the compiled `openapi_http` adapter. Operator endpoint policy
must cover both the API base and its definition document URL. See
[OpenAPI imports](imported-openapi.md) for document authentication and scheme selection.
