# Delegated OAuth connections

The Broker can hold a user's delegated upstream OAuth connection and obtain a
short-lived access token when an authorized action needs it. [Gmail](providers-gmail.md)
provides a production Google dialect and typed mailbox actions, and the
production [GitLab dialect](#gitlab) connects one GitLab instance's accounts.
The development-only `stub` dialect and `oauth_stub` records provider use the
separate `oauth-provider-stub` repository. Microsoft Graph and Atlassian
delegated adapters are not enabled.

This is separate from `[browser_auth.oidc.microsoft]`, which signs a person into
the Broker. A Broker browser session identifies the connection owner; connecting
an upstream account grants the Broker access to that account. An agent continues
to present its ordinary Broker invocation token and never receives upstream
access tokens, refresh tokens, client secrets or authorization codes.

## Supported integrations

| Adapter | Purpose | Setup |
| --- | --- | --- |
| `google` | Production Gmail account connection | [Gmail operator setup](providers-gmail.md#setup) |
| `gitlab` | Production GitLab account connection for GitLab REST and Git | [GitLab](#gitlab) |
| `mcp_oauth` | Personal OAuth for reviewed imported MCP services | [Imported MCP OAuth](imported-oauth.md) |
| `stub` | Development records provider and lifecycle fault tests; forbidden in production | [Test-provider configuration](#development-test-provider-configuration) |

The linked production adapters do not enable Microsoft Graph or Atlassian
delegated OAuth. OpenAPI imports use static Bearer/header-key credentials.
Microsoft OIDC remains a separate browser-login feature.

## Credential connections and shared registrations

A service uses OAuth through a
[credential connection](configuration.md#credential-connections) whose `oauth`
names a registration and one of its permission profiles; each service that uses
it names the connection from its `credentials.per_user` entry. Only `user`
principals use OAuth: a person connects their upstream account, and the Broker
never reads a stored token for them through that connection. Service accounts
and `system` principals cannot complete browser consent. They use the
connection's `token_profile` when it sets one, and otherwise have no personal
credential for its services. Nobody chooses between a token and OAuth, and the
Broker never falls back from one to the other.

Some upstream operations accept only a token, and their providers mark those
actions token-only. Where a person's winning grant is `per_user` and their
connection selects OAuth, a token-only action is hidden from discovery and
denied before the Broker acquires, refreshes or looks anything up through the
connection; a lower-priority grant never stands in. A `service` grant with its
static credential keeps the action usable for the same person. See
[token-only actions](provider-sdk.md#token-only-actions).

Several credential connections, and therefore several services, may reference
one registration. They must use the same permission profile, and they share
each person's OAuth connection: one consent and one refresh family per owner
and registration. Each service still acquires its own service-bound lease, and
its own grants decide what it may do. An invocation holds one lease for its
metadata lookups and its execution. Connecting, reconnecting or disconnecting
affects every service that uses a connection on that registration. Imported MCP
OAuth services publish their own single-service connection; see
[imported OAuth](imported-oauth.md).

Permission profiles use `scope_mode = "explicit"` by default and require a
nonempty `scopes` list. Only `mcp_oauth` supports `scope_mode = "server_default"`,
which requires omitting `scopes` entirely and leaves permission selection to the
authorization server for the exact configured resource. A registration cannot
mix permission modes. See [MCP permission modes](imported-oauth.md#permission-modes)
for request, token-response and permission-boundary semantics.

## Connection lifecycle

1. A signed-in user opens **My access > Credentials**, where each OAuth
   registration their credential connections use is one row, and clicks
   **Connect account**. Setup requires self-service enabled, a credential
   connection with `oauth` and a matching active `per_user` action grant on a
   service that uses it, for the user or their current groups. An administrator
   may connect their own imported discovery account through the import
   workflow's bounded discovery exception, including for later discovery
   refreshes.
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
   Google and GitLab identify the connected account, and imported MCP OAuth may
   provide no upstream account identity. The Broker rechecks the active session,
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
last setup grant is removed, while self-service remains enabled and a credential
connection still references the registration. Retired or blocked imports do not prevent
local cleanup. Reconnect requires a current setup grant. An empty target without
setup authority is hidden. Static API-token deletion retains its separate
configured-target authorization; this OAuth cleanup rule does not change it.

Disconnect of an owned connection removes local material and fences late callbacks
and refresh responses. It is idempotent: for a configured registration, an authorized
owner's repeated DELETE succeeds even when no connection remains. Browser,
self-service and CSRF requirements still apply; a setup grant is not required
for local disconnect. Without an owned connection, DELETE is a no-op and leaves
pending consent unchanged. It does **not** claim to revoke provider-side consent. Remove
that separately at the provider if desired. Disabling/removing a Broker principal
also removes its OAuth state. Existing provider requests already dispatched
cannot be recalled.

## GitLab

The `gitlab` dialect connects a person's account on one GitLab instance. GitLab
REST and a GitLab [Git gateway](git-http-gateway.md) on that instance consume
one credential connection, so a person connects once for both, and each
service's own grants still decide what it may do. GitLab REST's use of the
connection, including its lookups and 401 recovery, is described under
[GitLab REST OAuth connections](providers-gitlab-rest.md#oauth-connections).

### GitLab administrator setup

1. In the GitLab Admin area, open **Applications** and add an instance-wide
   application. Keep it **confidential**.
2. Set its redirect URI to the Broker's exact callback for the registration,
   `<browser_auth.public_origin>/v1/oauth/callback/<registration>`, such as
   `https://broker.example.com/v1/oauth/callback/gitlab`.
3. Select the [scopes](#gitlab-scopes) the Broker profile requests.
4. Optionally mark the application **trusted**, so people are not shown
   GitLab's consent screen. Only the Admin area can set this; the Applications
   API has no such setting. When GitLab's `disable_admin_oauth_scopes` setting
   is on, GitLab administrators can authorize only trusted applications with API
   or repository scopes.
5. Hand the application ID and secret to the Broker administrator, who stores
   the secret in a file or environment variable the Broker reads.

When people sign in to GitLab through an external identity provider, such as
Microsoft Entra ID, setting GitLab's `auto_sign_in_with_provider` to it lets a
trusted application connect without a click for anyone with a session. The
provider can still prompt, for example for multi-factor authentication. Keep a
GitLab administrator who can sign in without it; `?auto_sign_in=false` on the
sign-in page bypasses it. When the Broker also signs people in through Entra,
[login binding](#gitlab-login-binding) can require each connected GitLab
account to be the person's own.

### GitLab registration

```toml
[oauth.registrations.gitlab]
adapter = "gitlab"
base_url = "https://gitlab.example.com"
redirect_uri = "https://broker.example.com/v1/oauth/callback/gitlab"
client_id = "YOUR_GITLAB_APPLICATION_ID"
client_secret_ref = "file:/etc/agent-access-broker/secrets/gitlab-oauth-client-secret"
client_auth = "client_secret_post"
rotation = "rotate_both"

[oauth.registrations.gitlab.permission_profiles.default]
scopes = ["api", "write_repository"]
audience = "gitlab"
target = "https://gitlab.example.com"

[credentials.connections.gitlab]
display_name = "GitLab"
token_profile = "gitlab-access-token"
oauth = { registration = "gitlab", profile = "default" }

[credentials.per_user.gitlab]
type = "connection"
connection = "gitlab"

[credentials.per_user.gitlab_git]
type = "connection"
connection = "gitlab"
```

`config validate`, startup and reload check, without contacting GitLab:

- `base_url` is the instance base, including any relative URL root such as
  `https://example.com/gitlab`, without credentials, query or fragment. Every
  endpoint is below it.
- `client_auth = "client_secret_post"`, the default form encoding, no
  `adapter_settings`, and `rotation = "rotate_both"`, because every GitLab
  refresh replaces both the access and the refresh token.
- The registration has exactly one permission profile. It requests explicit
  `scopes`, its `audience` is `gitlab`, and its `target` is the normalized
  instance base: `base_url` with a lowercase scheme and host, no default port
  and no trailing slash.
- Every service using the connection acts on that instance: GitLab REST whose
  `api_base_url` is the target followed by `/api/v4`, and Git gateways whose
  `upstream_base_url` is the target. Any other consumer fails with
  `credentials.connections.<id>.oauth: <service> does not act on the upstream
  registration <registration> grants access to: it acts on <origin>, not the
  GitLab instance <target>`.

People always use their OAuth connection and never store a GitLab token
through it. With `token_profile` set, service accounts keep tokens an
administrator provisions, because GitLab service accounts authenticate only
with personal access tokens, and `system` principals store their own. Without
`token_profile`, only people have a GitLab credential.

### GitLab scopes

Scopes are deployment configuration: the GitLab application allows them and
the profile requests them. GitLab documents Git over HTTP for OAuth tokens only
under its repository scopes, so request one explicitly:

| Use | Scopes |
| --- | --- |
| REST reads and writes, Git fetch and push (default) | `api`, `write_repository` |
| Read-only REST and Git fetch | `read_api`, `read_repository` |
| REST reads, Git fetch and push | `read_api`, `write_repository` |

The Broker identifies the connected account at `/api/v4/user`, which `api`,
`read_api` or `read_user` allows; without one of them, connecting fails with a
permission error. Changing the profile's scopes changes the registration, so
every person reconnects.

### GitLab protocol

- The authorization page is `<base_url>/oauth/authorize`, requested with the
  profile's scopes, the flow's state and a PKCE S256 challenge. Code exchange
  and refresh are form-encoded POSTs to `<base_url>/oauth/token` carrying the
  client ID and secret; refresh also sends the registration's redirect URI.
- Each token response sets its access token's lifetime. Without `expires_in`,
  GitLab's default of 7200 seconds applies. GitLab 19.1 and later let
  administrators shorten it to as little as 300 seconds.
- The connected account's numeric `id` is its stable subject, and its
  `username` the name the portal shows. Reconnecting rejects a different
  account unless the person chooses to replace it.
- Granted scopes come from the token response's `scope`. When the code
  exchange omits it, the Broker reads `<base_url>/oauth/token/info` with the
  new access token; if that fails, connecting fails and nothing is stored. When
  a refresh omits it, the connection keeps the scopes originally granted, and
  the Broker sends nothing else between the refresh and storing its result.
  Requested scopes are never taken as granted.
- The connection's one target is the instance, with audience `gitlab` and the
  granted scopes. Leases carry that target and audience.
- Refresh material is consuming. GitLab invalidates both earlier tokens on
  every refresh, with no grace period, so an access token in use when another
  request refreshes stops working. A refresh whose outcome is unknown, such as a
  lost response, a 5xx answer or an unrecognized rejection, leaves the
  connection needing reconnect, for GitLab REST and Git together.
  `invalid_grant` also requires reconnect, and HTTP 429 holds refresh until its
  `Retry-After` wait.

GitLab refresh tokens do not expire. Disconnecting removes the Broker's copy
but does not revoke the grant in GitLab: the person revokes the application
under their GitLab **Applications** settings, or a GitLab administrator revokes
the application's tokens.

### GitLab login binding

Where people sign in to both the Broker and GitLab through Microsoft Entra ID,
a registration can require each connected GitLab account to belong to the
person connecting it: GitLab must report the account linked to the same Entra
user as the person's Broker account. Binding is off unless the registration
sets `login_binding`:

```toml
[oauth.registrations.gitlab.login_binding]
provider = "microsoft"
upstream_identity_provider = "azure_activedirectory_v2"
upstream_tenant_id = "00000000-0000-0000-0000-000000000000"
```

- `provider = "microsoft"` makes the Broker's
  [Microsoft sign-in](operator-guide.md#microsoft-entra-oidc-setup-and-operation)
  authoritative, so `browser_auth.oidc.microsoft.enabled` is required.
- `upstream_identity_provider` is GitLab's OmniAuth name for its Entra
  sign-in, as GitLab reports it in a user's `identities`, such as
  `azure_activedirectory_v2`, or the `name` of an `openid_connect` provider.
- `upstream_tenant_id` states that this GitLab provider signs people in
  through that Entra tenant. GitLab does not report the tenant, so the Broker
  relies on this statement, and it must be
  `browser_auth.oidc.microsoft.tenant_id`.

Before enabling it, check that:

- GitLab's Entra provider records each person's Entra object ID: set its
  `uid_field` to `oid`. GitLab's examples differ: some use
  `preferred_username`, and without `uid_field` GitLab records `sub`, which is
  not the object ID, so no account would connect. Never use
  `preferred_username`, which can be changed or reassigned; the Broker
  compares only object IDs.
- GitLab includes `identities` in `/api/v4/user` for the profile's scopes.
  GitLab documents the field but not which scopes expose it; request
  `/api/v4/user` with a token holding the same scopes and confirm it lists the
  Entra identity. Without it, no account connects.
- Each person's Broker account has a Microsoft sign-in: Microsoft
  just-in-time accounts have one, and an administrator can
  [link an existing account](administrator-guide.md#microsoft-onboarding).

With the binding set:

- A person without an active Microsoft sign-in in that tenant cannot connect.
  Their row in `GET /v1/oauth/connections` has `canConnect: false` and
  `connectUnavailableReason: "login_binding_required"`, which the portal
  explains, and starting consent fails with HTTP 400 and
  `error.message: "oauth_login_binding_required"`.
- After the code exchange, the Broker reads `/api/v4/user` and requires an
  `identities` entry whose `provider` is `upstream_identity_provider` and whose
  `extern_uid` is the person's Entra object ID, compared without regard to
  case. Otherwise the callback fails with HTTP 400 and
  `error.message: "oauth_login_binding_mismatch"`, and nothing is stored.
- The Broker checks the person's current Microsoft sign-in again inside the
  transaction that installs the connection, so a link removed or changed
  during consent prevents the installation.
- The Broker account's Microsoft sign-in counts whatever sign-in method the
  browser session used, including a local password.
- Errors, logs and audit carry only these codes, never object IDs.

The check runs whenever a connection is installed: on connect, reconnect and
account replacement. Later changes to either link do not affect an existing
connection until it is reconnected; disconnect it to end access sooner. Adding,
changing or removing `login_binding` changes the registration, so every person
reconnects; a registration without it keeps its connections. Only the `gitlab`
dialect reports linked identities, and validation rejects `login_binding` on
any other registration.

## Development test-provider configuration

A registration describes the upstream application and its token behavior. A
named permission profile describes the requested scopes, API audience and selected
target. A credential connection points to that registration and profile, and the
service's per-user entry names the connection.
The records service itself is configured by its own `[providers.oauth_stub]`
table, whose `base_url` names the records API. The fixture serves both from the
same test server:

```toml
[providers.oauth_stub]
base_url = "http://127.0.0.1:8099"

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

[credentials.connections.oauth_stub]
oauth = { registration = "stub", profile = "read" }

[credentials.per_user.oauth_stub]
type = "connection"
connection = "oauth_stub"
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
The Broker core provides no dialect of its own. The binary selects `google`,
`mcp_oauth` and the development-only `stub` dialect. The `stub` dialect and the
`oauth_stub` records backend are independent development selections; a build
that omits them has no test dialect, service or `oauth_collection` resource type.
Production configuration and deployments without
`deployment.enable_fake_service` reject both `stub` registrations and
`[providers.oauth_stub]`.

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
proxy, then `network.egress_proxy`). Only literal loopback IP destinations, such
as `127.0.0.1` or `[::1]`, connect directly. Host names, including `localhost`,
follow that resolution, and the issuer's route does not determine another
destination's route. Records API reads go to `[providers.oauth_stub] base_url`,
which must be a literal loopback IP origin and is reached directly. They are
limited to paths under that URL, bounded by `limits.request_timeout_ms`, and
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
| `GET /v1/oauth/connections` | One row per registration the owner's credential connections select: its `displayName`, the `connectionDescription` a consuming backend declares, the entitled `consumers` and the count of `otherConsumers` |
| `POST /v1/oauth/connect` | `{ "registration": "stub", "intent": "connect" }`; returns an authorization URL and expiry |
| `GET /v1/oauth/callback/{registration}` | One-use browser callback; successful or canceled consent returns HTTP 200 HTML with a small completion page |
| `DELETE /v1/oauth/connections/{registration}` | Idempotent local disconnect, including when no owned connection remains; reports `remoteRevocation: "not_requested"` |

Each row includes `canConnect`, `canDisconnect` and the required nullable
`connectUnavailableReason`. The reason is `null` when setup is available,
`no_personal_access` when the owner lacks a matching `per_user` grant on every
consumer, `service_unavailable` when an imported consumer cannot currently
accept setup, or `login_binding_required` when the registration's
[login binding](#gitlab-login-binding) needs a Broker sign-in the owner has not
linked. A retained connection can therefore offer Disconnect while
Connect/Reconnect is unavailable. These flags describe personal management, not
invocation access.

A row appears when the owner may set up at least one consumer of the
registration. An owned connection stays listed after grant loss, with no
entitled `consumers`, so its owner can disconnect it. It stays listed even when
no credential connection selects its registration any more, because its last
consumer was removed or rebound: that row has `null` profile fields
(`permissionProfile`, `scopeMode`, `target`), since the consented profile is not
recorded durably, and the portal shows it with Disconnect and no permission
text. Disconnect affects every
service whose credential connection uses the registration; those services do
not have independent token families. The portal's disconnect confirmation names
the entitled services and counts the others.

Each row also includes `scopeMode` (`explicit` or `server_default`) and
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
the connect request names the imported service in `importedService`, and the
link opens its Import tab, `/ui/admin/catalog/services/{service}/import`.
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
it does not imply a Broker grant denial. A registration's
[login binding](#gitlab-login-binding) refuses consent with HTTP 400,
`reasonCode: "credential_invalid"` and `error.message:
"oauth_login_binding_required"` when the owner has no linked sign-in, and
installation with `error.message: "oauth_login_binding_mismatch"` when the
upstream account is not linked to it.
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
current runtime. Admission is for the registration as a whole: at least one
consuming service whose credential connection selects OAuth for the owner, with
the flow's exact registration and profile, must have an active `per_user` grant
for the owner. An imported consumer also admits an administrator through its
import-discovery admission. An imported consumer counts only at the import
version it had when the flow started, and a consumer rebound to another
registration or profile makes the flow stale. Existing session, PKCE, issuer,
generation and registration-fingerprint checks still apply.

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

Removing every credential connection that uses a registration does not remove
that owner's registration slot. An unused retained slot is not invocable or
listed by the connection routes, but still participates in startup decryption,
used-key inventory, readiness and rewrap. Removing the registration, activating a changed
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
runtime acquires it once a candidate grant exists: when policy has admitted the
invocation, or earlier when an action's pre-authorization metadata lookup uses
the caller's `per_user` credential. The same lease then serves the
invocation's lookups and its execution, and the runtime checks it again just
before dispatch: access revoked, disconnected, or awaiting new consent since
then stops the invocation, and access another invocation's refresh superseded
moves to the current version. A provider receives only this lease, never the
manager; after an upstream 401 it may replace the access once per invocation,
whether the 401 answered a lookup or execution, and retry. A
pre-authorization lookup that fails because the connection awaits new consent,
is being refreshed or has its refresh throttled reports that failure, with any
retry time, instead of the concealed `scope_unresolved`.
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
refresh/retry. Gmail and GitLab REST also permit this one recovery after a
mutation's explicit 401 authentication rejection; no timeout, transport or
server-error replay occurs.
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
provider revocation orchestration and Microsoft/Jira/Confluence delegated adapters are
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
token responses, recovery after cancelled consent, revocation, setup-grant
withdrawal and disconnect. It cleans up processes and temporary state. Add
`--demo --state-dir /new/private/path` to keep an interactive instance running
until interrupted. Read its private
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
