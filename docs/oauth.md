# Delegated OAuth connections

The Broker can hold a user's delegated upstream OAuth connection and obtain a
short-lived access token when an authorized action needs it. [Gmail](providers-gmail.md)
provides a production Google dialect and typed mailbox actions. The development-only
records dialect uses the separate `oauth-provider-stub` repository. Microsoft Graph,
Atlassian and GitLab delegated adapters are not enabled.

This is separate from `[browser_auth.oidc.microsoft]`, which signs a person into
the Broker. A Broker browser session identifies the connection owner; connecting
an upstream account grants the Broker access to that account. An agent continues
to present its ordinary Broker invocation token and never receives upstream
access tokens, refresh tokens, client secrets or authorization codes.

## Supported integrations

| Adapter | Purpose | Setup |
| --- | --- | --- |
| `google` | Production Gmail account connection | [Gmail operator setup](providers-gmail.md#setup) |
| `mcp_oauth` | Personal OAuth for reviewed imported MCP services | [Imported MCP OAuth](imported-oauth.md) |
| `stub` | Development records provider and lifecycle fault tests; forbidden in production | [Test-provider configuration](#development-test-provider-configuration) |

The linked production adapters do not enable Microsoft Graph, Atlassian, or
GitLab delegated OAuth. OpenAPI imports use static Bearer/header-key credentials.
Microsoft OIDC remains a separate browser-login feature.

Permission profiles use `scope_mode = "explicit"` by default and require a
nonempty `scopes` list. Only `mcp_oauth` supports `scope_mode = "server_default"`,
which requires omitting `scopes` entirely and leaves permission selection to the
authorization server for the exact configured resource. A registration cannot
mix permission modes. See [MCP permission modes](imported-oauth.md#permission-modes)
for request, token-response and permission-boundary semantics.

## Connection lifecycle

1. A signed-in user opens **Credentials → Connected accounts** and clicks
   **Connect account**. Setup requires self-service enabled, a configured
   personal OAuth binding and a matching active `per_user` action grant for the
   user or their current groups. An administrator may connect their own imported
   discovery account through the import workflow's bounded discovery exception,
   including for later discovery refreshes.
2. The Broker stores an encrypted, five-minute, one-use flow bound to the owner,
   live browser session, registration configuration and connection generation.
   It generates independent state and an S256 PKCE verifier/challenge. Only one
   unexpired consent flow is allowed per owner/registration; finish, deny or let
   that flow expire before starting another.
3. The portal opens the configured provider's authorization page in a separate
   tab, leaving the original page and unsaved edits in place. If the browser
   blocks it, allow pop-ups for the broker and retry; the portal does not navigate
   the original tab instead. The person chooses an account and permissions.
   The provider redirects that tab to the
   registration's exact Broker callback with its issuer, state and authorization code.
4. The Broker checks issuer, state and browser ownership, exchanges the code
   using the configured client authentication plus PKCE. The dialect determines
   identity and target evidence: the test provider uses `/me` and `/targets`,
   Google identifies the connected account, and imported MCP OAuth may provide
   no upstream account identity. The Broker rechecks the active session,
   self-service setting, current grant/group authority and exact service binding
   before exchange and again before committing the connection.
5. Encrypted connection state contains any refresh family, available subject
   evidence, granted scopes, targets and versioned access cache. Ordinary management
   reads expose only account/status/permission metadata.
6. An authorized action obtains a lease for its registration, permission
   profile, audience and target. A usable cached token is reused. Expiring or
   absent access requires on-demand refresh when available, or reconnect for an
   access-only connection; there is no refresh-all timer.

The authorization tab has no access to its opener. Use **Return to
authorization tab** on the active connection to resume consent. On a callback
return (including an error page), close or focus, the original page refreshes
connection status from the Broker. Successful consent shows a small **Authorized**
page and attempts to close the tab automatically. If it remains open, use
**Close tab** or your browser’s tab controls. If script closure is blocked, the
page explains how to close it manually. Denied consent shows **Authorization
canceled**; other provider-reported errors show **Authorization was not completed**
without displaying provider text. Callback validation and exchange errors remain
visible as non-success JSON. The completion page also offers a link to open Broker in
a new tab. Navigating away from the original view leaves the tab open, including when the Connect request is still preparing authorization.
Closing a consent tab does not cancel the Broker's pending flow; its five-minute
expiry still applies. A pending flow can delay another connection attempt and use
of an existing connection until it finishes, is denied or expires.

When the provider supplies identity evidence, reconnect retains the expected
upstream subject and rejects a different account. The API's explicit
`replace_account` intent supports deliberate replacement. When imported MCP
OAuth supplies no identity evidence, the portal asks for explicit confirmation
before replacement because it cannot verify that the same account is selected.

Starting consent suspends invocation while the browser flow is pending and preserves
the previous connection's encrypted material. If the person cancels, consent
fails, or the flow expires, a refreshable connection renews and revalidates its
old authority before resuming. An access-only imported connection can continue
until expiry. For refreshable connections, cached access alone cannot restore it:
the provider may have changed permissions during consent. Revoked or uncertain
refresh material still requires a successful reconnect.

An active `per_user` grant provides setup authority even when its resources are
empty, disabled or unavailable in the current execution context, or another grant
wins invocation precedence. Setup does not broaden that grant: each invocation
still needs its own action, resource, context and credential authorization.

An existing owned connection stays visible and locally disconnectable after the
last setup grant is removed, while self-service remains enabled and a configured
service still binds the registration. Retired or blocked imports do not prevent
local cleanup. Reconnect requires a current setup grant. An empty target without
setup authority is hidden. Static API-token deletion retains its separate
configured-target authorization; this OAuth cleanup rule does not change it.

Disconnect of an owned connection removes local material and fences late callbacks
and refresh responses. It is idempotent: for a configured binding, an authorized
owner's repeated DELETE succeeds even when no connection remains. Browser,
self-service and CSRF requirements still apply; a setup grant is not required
for local disconnect. Without an owned connection, DELETE is a no-op and leaves
pending consent unchanged. It does **not** claim to revoke provider-side consent. Remove
that separately at the provider if desired. Disabling/removing a Broker principal
also removes its OAuth state. Existing provider requests already dispatched
cannot be recalled.

## Development test-provider configuration

A registration describes the upstream application and its token behavior. A
named permission profile describes the requested scopes, API audience and selected
target. A service's per-user credential points to that registration/profile:

```toml
[oauth.registrations.stub]
adapter = "stub"
base_url = "http://127.0.0.1:8099"
redirect_uri = "http://127.0.0.1:8080/v1/oauth/callback/stub"
client_id = "broker-local"
client_secret_ref = "env:OAUTH_STUB_CLIENT_SECRET"
client_auth = "client_secret_post"
encoding = "form"
rotation = "rotate_refresh"
allow_insecure_loopback = true

[oauth.registrations.stub.permission_profiles.read]
scopes = ["records.read", "offline_access"]
audience = "records-api"
target = "workspace-one"

[credentials.per_user.oauth_stub]
type = "oauth"
provider = "stub"
profile = "read"
```

This fragment also requires non-production `deployment.enable_fake_service =
true`, managed identity/store, credential encryption, browser authentication,
and management. The callback must exactly match `browser_auth.public_origin`
plus `/v1/oauth/callback/<registration>`, and must be registered verbatim at the
stub. The client secret reference accepts an environment variable or absolute
file path, not an inline secret. OAuth does not repurpose the existing static
credential PUT/reveal APIs.

`adapter` names the OAuth dialect the registration speaks: the wire protocol of
one family of authorization servers. Dialects register with the Broker binary
alongside its backends; configuration validation rejects an adapter that no
registered dialect claims and applies the dialect's own registration checks.
The binary links `google` and `mcp_oauth`; the host also registers the
development-only `stub` dialect. Production configuration and deployments without
`deployment.enable_fake_service` reject `stub`.

The stub dialect supports `client_secret_post` and `client_secret_basic`, form or
JSON token bodies, and `preserve_old`, `rotate_refresh`, or `rotate_both` refresh
semantics. Set these to the stub's matching configuration. It requires refresh
capability (`offline_access`) and records the actually granted token scopes;
requested scopes are not evidence that consent was granted. A resource action
requires both token scopes and the selected target's scopes.

HTTPS uses the Broker's existing outbound TLS trust configuration, including
configured development CA certificates. Plain HTTP requires the explicit
loopback opt-in and a literal loopback IP, such as `127.0.0.1`. It is rejected
for other hosts. The browser needs to reach the Broker and provider consent
pages; agent containers need only their ordinary Broker connection. Never
turn off TLS verification to run the development fixture.

Token, identity and target-discovery requests use the Broker's shared upstream
client. A registration may reach only its dialect's allowlist (for the stub,
paths under `base_url`), each request is sent once with a 15 second total and
5 second connect bound, and each records an `upstream_request_completed` trace
and carries the Broker's upstream correlation headers: the invocation's request
IDs during refresh, and the consent callback's during code exchange and
discovery. Each approved metadata, token, identity, or target endpoint origin
independently follows global egress proxy resolution (`NO_PROXY`, environment
proxy, then `network.egress_proxy`). Loopback IPs and `localhost` destinations
connect directly; the issuer's route does not determine another host's route. Records API reads use the same routing, are limited
to paths under `base_url`, are bounded by `limits.request_timeout_ms`, and are
traced and correlated like any backend request.

## Typed reads and policy

The following actions belong only to the development records provider. Production
Gmail actions are documented in [Gmail](providers-gmail.md); imported actions use
their reviewed runtime catalog.

| Action | CLI | Resource |
| --- | --- | --- |
| `oauth_stub.record.list` | `agent-access oauth-stub record list --collection alpha` | collection `alpha` |
| `oauth_stub.record.view` | `agent-access oauth-stub record view alice-alpha-1 --collection alpha` | collection `alpha` |
| `oauth_stub.account.view` | `agent-access oauth-stub account` | no resource selector; explicit action grant required |

All actions use `per_user` credential mode. Collection resources have type
`oauth_collection` with an `exact` selector or `all`; values contain 1–64 lowercase
ASCII letters, digits, underscores or hyphens. Grants and invocation tokens use
the existing typed resource IDs/groups and execution contexts. Denied actions
are rejected before acquiring or refreshing an upstream credential. Reading a
record supplies the authorized collection to the upstream API as well as the
ID, preventing an ID from bypassing collection policy.

These actions appear in caller-filtered catalog, OpenAPI, JSON send schema,
typed CLI and ordinary invoke/MCP discovery. Example generic invocation:

```bash
agent-access invoke oauth_stub.record.list --input-json '{"collection":"alpha"}'
```

The connection owner is credential identity, not a resource. Future mail
address/domain resources can be evaluated by mail actions independently of the
connected mailbox. The test records provider does not define mail actions; see
[Gmail](providers-gmail.md) for the connected-mailbox action set.

## Browser management API

| Method/path | Behavior |
| --- | --- |
| `GET /v1/oauth/connections` | Metadata for configured services the owner may inspect, including each service's `serviceDisplayName` and the `connectionDescription` its backend declares |
| `POST /v1/oauth/connect` | `{ "service": "oauth_stub", "intent": "connect" }`; returns an authorization URL and expiry |
| `GET /v1/oauth/callback/{registration}` | One-use browser callback; successful or canceled consent returns HTTP 200 HTML with a small completion page |
| `DELETE /v1/oauth/connections/{service}` | Idempotent local disconnect, including when no owned connection remains; reports `remoteRevocation: "not_requested"` |

Each connection target includes `canConnect`, `canDisconnect` and the required
nullable `connectUnavailableReason`. The reason is `null` when setup is available,
`no_personal_access` when the owner lacks a matching `per_user` grant, or
`service_unavailable` when the configured service cannot currently accept setup.
A retained connection can therefore offer Disconnect while Connect/Reconnect is
unavailable. These flags describe personal management, not invocation access.

Entitled service/profile bindings retain separate rows even when they share one
registration. Cleanup-only rows appear only for an actual owned connection, and
only once per registration when no entitled row represents it. Disconnect affects
every service sharing that owner's registration; those services do not have
independent token families. Prefer one compatible permission profile per
registration.

Each target also includes `scopeMode` (`explicit` or `server_default`) and
`requestedScopes`. Server-default targets have an empty `requestedScopes` array;
the mode identifies an authorization policy, not an absence of permissions.
`connection.targets[].scopes` contains current known scope evidence from token
responses or the adapter's documented rules for omitted `scope`. See
[MCP permission modes](imported-oauth.md#permission-modes) and
[Gmail OAuth](providers-gmail.md) for their response requirements and scope rules.
The array may be empty when scope details are unavailable. It neither limits
upstream authority nor proves what the latest token response reported. The portal
labels server-default targets **Server-default permissions**, with **Known scopes**
or **Scope details unavailable** as appropriate.

`intent` is `connect` (default), `reconnect`, or `replace_account`. These routes
accept optional `returnPath` on connect: `/ui/credentials` (the default) or
`/ui/admin/catalog`. The broker saves this fixed destination with the pending
flow for the completion page's link to open Broker in a new tab. For Catalog,
the link opens the initiating imported service's Import tab,
`/ui/admin/catalog/services/{service}/import`.
Other paths, supplied queries and external URLs are rejected. The callback does
not accept a destination or automatically navigate to the portal. Successful
authorization attempts to close its tab; canceled consent stays visible.
Both pages offer a Close button and the saved Broker link. The HTML excludes
callback values and removes the query from browser history. Responses set
`no-store`, `no-referrer`, a nonce-based content security policy and framing
protection. Invalid or failed callbacks retain non-success JSON errors and do
not attempt to close the tab. A signed-in visit to the callback with no query,
including a reload after its query was cleared, shows a neutral **Check connection
status** page. This page asserts no outcome, performs no consent operation and
writes no consent audit record. Any supplied callback query still undergoes the
normal validation and audit path.

These routes
require a signed-in browser session. Header-based user/admin management tokens
and agent invocation tokens cannot connect accounts. Writes use the normal
same-origin/CSRF controls. The provider callback uses state/session/issuer
validation instead of a CSRF header and accepts bounded, nonduplicate
`state`, `iss`, `code`, `error` and `error_description` parameters. Codes and
errors are not copied into audit output. Browser callback navigation receives a
broker-generated request ID when no API request-ID header is supplied. All OAuth
responses are `no-store`.

OAuth routes do not consult `credentials:self:*` rights. Ordinary setup uses the
current matching grant; a credential right alone cannot authorize it.
Management uses ordinary Broker envelopes; errors carry a sanitized OAuth code.
Broker setup authorization denial returns HTTP 403 with
`reasonCode: "service_action_denied"` and sanitized
`error.message: "oauth_setup_denied"`. An upstream permission or scope rejection
instead returns HTTP 400 with `reasonCode: "credential_invalid"` and
`error.message: "oauth_permission_denied"`;
it does not imply a Broker grant denial.
The portal is mounted at `/ui`; the current Broker configuration validator
rejects any other `portal.mount_path`; callback destinations stay within that portal.
The three JSON management routes advertise `browser_management` access in the
runtime specification. OpenAPI declares the configured browser cookie and
sensitive authorization URL. As with the existing browser login endpoints,
the HTML callback is documented here rather than as a JSON-send operation.

### Consent admission and policy changes

Consent start, callback claim and connection installation use the same setup
predicate. Each authoritative check loads the current published runtime rather
than retaining the request's earlier snapshot. With managed policy, grant rows
and effective group membership, including membership expiry, are read within the
same store transaction as admission. With TOML policy, grants come from the
current runtime. The service must still bind the flow's exact registration and
profile; imported flows must also match the current import revision. Existing
session, PKCE, issuer, generation and registration-fingerprint checks still apply.

If a valid matching callback loses setup authority or its binding changes before
exchange, the Broker retires that pending flow and returns the denial. It does
not exchange the authorization code. Retirement has cancellation semantics: it
removes the pending flow without clearing required revalidation of the previous
connection. If final admission fails after exchange, the new tokens are discarded
locally and the old connection is preserved. Provider-side token revocation is
not attempted. Invalid session/state callbacks and storage errors do not clear
another flow. Disabling self-service can reject a callback before the manager
runs, leaving that pending flow to its normal expiry.

Managed grant and membership changes are ordered against each admission
transaction. A later withdrawal, or a configuration reload racing installation,
can leave a stored connection; it cannot supply invocation authority that the
current policy denies.

## Refresh, durability and recovery

The managed store persists registration fences and encrypted owner/registration
slots. AES-GCM associated data binds owner,
registration, generation, configuration fingerprint and encryption key ID.
Key readiness and rewrap include these rows. Back up the database and encryption
key ring together using the existing managed-store procedures.

Removing a service binding does not remove that owner's registration slot. An
unbound retained slot is not invocable or exposed by the service-based connection
routes, but still participates in startup decryption, used-key inventory,
readiness and rewrap. Removing the registration, activating a changed
registration fingerprint, or disabling/removing the owner deletes the applicable
slots. Do not retire an encryption key merely because its connection is unbound.

The registration fingerprint includes a nondefault permission mode. Changing
modes invalidates that registration's connections, pending consent and delegated
leases, including connection-bound import discovery evidence. Explicit profiles
have the same fingerprint whether their default `scope_mode` is omitted or written
as `"explicit"`, so an unchanged explicit registration retains its connections.

An in-process shared refresh task plus a durable attempt fence prevents
concurrent requests from independently spending the same refresh token. An
HTTP caller disconnecting does not cancel an already-started refresh task. A
successful rotated successor is committed before fallible target discovery;
discovery can be retried without repeating that token exchange. A lease carries
the configuration fingerprint, connection generation and access version. The
runtime acquires it once policy has admitted the invocation and checks it again
just before dispatch: access revoked, disconnected, or awaiting new consent
since then stops the invocation, and access another invocation's refresh
superseded moves to the current version. The records provider receives only
this lease, never the manager; after an upstream 401 it may replace the access
once and retry.
Cached reads only decrypt the stored snapshot; they do not rewrite or re-encrypt
the slot. Expired consent flows are ignored for admission and pruned when a
subsequent lifecycle change already needs to write the slot.

Failures known not to have consumed a refresh token preserve the family. These
include failure to establish a connection and explicit non-consuming token
rejections. Repeated failures grow the cooldown exponentially, capped at five
minutes. An HTTP 429 from the authorization server holds refresh at least until
its `Retry-After` wait, bounded to one day, even when that is longer than the
five-minute backoff cap. The encrypted store persists the failure state, the
deadline, and the sanitized reason of the failure that started the cooldown, so
the cause survives restarts; retries occur only when another action requests a
token. There is no automatic retry loop. Connection metadata shows that
sanitized failure reason while material is preserved. Three consecutive
explicit permission or request rejections stop renewal attempts: permission
rejections require reconnect, and request rejections require operator action.
Successful renewal clears the failure state.
If the renewed token or discovered targets no longer authorize the requested
profile, metadata reports `oauth_permission_denied` while reads remain denied.
Invocation responses distinguish throttling and provider failures from
credentials that actually require reconnect. Only throttling is reported as a
rate limit: when the authorization server throttles refresh (HTTP 429, or a
dialect's explicit rate-limit error), invocations, including those made during
the cooldown that follows, return `upstream_rate_limited` naming the invoked
service, with the remaining cooldown as `retryAfterSeconds` and `retryAt`; they
never return the Broker's own `rate_limited`. A cooldown that follows any other
failure (a transport error, a 5xx or `server_error` response, a rejected or
invalid response, or an interrupted attempt) reports that failure's own class,
such as `upstream_connection_failed` or `upstream_protocol_failed`, with the
remaining cooldown as `result.retryAfterSeconds` and `result.retryAt` (and
therefore `Retry-After`) and a message saying refresh is paused after a failed
attempt until then. `Retry-After` values from the authorization server, in
delta-seconds or HTTP-date form, are parsed and bounded to one day by the same
rules as provider throttling; the five-minute cap applies only to the Broker's
own exponential backoff.

Each dialect explicitly declares whether refresh material is reusable or consuming,
independently of its successful-response rotation rules. Google declares reusable
material: transient failures and interrupted attempts preserve it with persisted
cooldown; malformed responses cannot issue access and stop renewal after three
consecutive failures. Invalid grants still require reconnect.

For consuming material, if a token request may have been consumed but its response
is lost, malformed, or ambiguous, the family becomes uncertain. The Broker does not retry the old
refresh token or continue handing out prior access leases. The owner reconnects.
A persisted unfinished attempt after process loss is likewise treated
conservatively. An upstream 401 on a read permits at most one version-aware
refresh/retry. Gmail also permits this one recovery after a mutation's explicit
401 authentication rejection; no timeout, transport or server-error replay occurs.
Leases stay pinned to their original connection/generation across both revalidation
and unauthorized recovery.

Reload prepares configuration without changing the active manager. Activation
fences removed/changed registrations and deactivates the old dispatcher. Client
secret rotation preserves the connection when its authority/client/configuration
identity is otherwise unchanged. Changing other registration fields, including
permission profiles, invalidates that registration's local connections and
requires reconnect. Account replacement, disconnect and disable always win
over stale responses.
Discovery results also check the captured refresh-material and consent state,
so a read started before reload cannot clear a newer consent requirement.

Structured service logs under `agent_access_core::oauth` record refresh attempts
and outcomes, connection status changes, and configuration activation. They use
connection/attempt identifiers and sanitized outcome codes, without tokens,
authorization codes, state values or provider response bodies. Ordinary action
and management audit entries retain the existing Broker audit boundary.

## Supported boundaries

The persistence and execution contracts separate owner, registration, stable
upstream subject, refresh family, permission profile, audience, target and access
version. The Broker supports **one connection and refresh family
per owner/registration**. Separate independent grant families under one
registration, adding permission profiles without reconnecting existing grants,
interactive target selection, delegated OIDC ID-token/claims validation, client assertions,
provider revocation orchestration and Microsoft/Jira/GitLab delegated adapters are
not supported. Changing the stub base URL does not provide a production adapter.

The stub's identity endpoint and fault controls are test protocols, not a
production identity provider. Production configuration rejects the stub
dialect.
The independent stub validates the browser consent and execution lifecycle;
production connections use their linked, provider-specific dialects.

## Imported MCP OAuth

Imported MCP services can use operator-approved `mcp_oauth` registrations and
individual user connections. See [registration and lifecycle setup](imported-oauth.md).

## Development test-provider validation

Build the Broker and CLI using the repository's documented build service, or
local Cargo when that service is unavailable, and build the portal:

```bash
# From the repository root.
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
  build-cli build cargo -- build --workspace
npm --prefix apps/portal ci
npm --prefix apps/portal run build
```

With the independent stub repository checked out separately, run its harness:

```bash
python3 /path/to/oauth-provider-stub/scripts/broker_e2e.py \
  --broker /path/to/agent-access-broker/target/debug/agent-access-broker \
  --cli /path/to/agent-access-broker/target/debug/agent-access \
  --portal-dir /path/to/agent-access-broker/apps/portal/dist
```

The harness starts isolated processes on free loopback ports, initializes an
encrypted managed store, connects an account through browser HTTP requests,
and invokes the actual CLI. It exercises readiness, configuration reload,
denial, replay, refresh, concurrent requests, restart, transient and uncertain
token responses, recovery after cancelled consent, revocation and disconnect. It
cleans up processes and temporary state. Add `--demo --state-dir /new/private/path`
to keep an interactive instance running until interrupted. Read its private
`connection-info.json` for the local URL, test login and CLI configuration;
do not publish that file or commit generated state. The stub's README documents
its independent protocol tests, fault controls and optional TLS listener.

A real browser test in `apps/portal/tests/oauth.spec.ts` uses this same harness:

```bash
cd apps/portal
OAUTH_STUB_REPO=/path/to/oauth-provider-stub \
  npx playwright test oauth.spec.ts
```

The browser test is skipped when the separate repository is not supplied. The
Broker's Rust OAuth tests and the stub's standard-library unit tests run without
any Microsoft tenant or other live upstream account.
