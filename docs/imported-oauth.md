# OAuth for imported MCP services

The broker supports individual OAuth connections to MCP HTTP servers using the
`mcp_oauth` authentication adapter. Imports retain their service/action identities,
review workflow and grants when administrators change a personal binding from a
static token to OAuth. Binding changes require confirmation of affected grants.

Service-specific downstream connections (`/mcp/<service>` and
`mcp serve --service <service>`) use this existing personal connection. They do
not initiate consent or change the exact upstream resource, audience or target.
Never use the broker's scoped URL as the upstream OAuth resource. Missing or
revoked OAuth connections do not fall back to stored personal tokens, service
credentials or discovery credentials; a failed upstream write is never replayed.
OpenAPI and Swagger imports support static Basic, Bearer or header-key credentials only.

Upstream MCP selects `2026-07-28` or `2025-11-25` automatically before tool dispatch.
This protocol negotiation uses the existing OAuth connection, resource, audience
and permission profile; it needs no new consent or configuration/database
migration. A protocol incompatibility leaves the connection intact. See
[upstream compatibility](imported-services.md#upstream-mcp-compatibility).

## Operator registration

Register the broker as an OAuth client at the upstream authorization server, using
the broker callback URL. Configure the approved client in TOML, then reload. This
adapter uses preregistered clients; automatic client registration is not
implemented. Client ID metadata documents and dynamic client registration are not
required for a preregistered client.

```toml
[oauth.registrations.internal_tools]
adapter = "mcp_oauth"
base_url = "https://login.example.com/issuer"
redirect_uri = "https://broker.example.com/v1/oauth/callback/internal_tools"
client_id = "registered-broker-client"
client_auth = "none"
rotation = "preserve_old"

[oauth.registrations.internal_tools.adapter_settings]
resource = "https://tools.example.com/mcp"
protected_resource_metadata_url = "https://tools.example.com/.well-known/oauth-protected-resource/mcp"
authorization_server_metadata_url = "https://login.example.com/.well-known/oauth-authorization-server/issuer"
authorization_endpoint = "https://login.example.com/authorize"
token_endpoint = "https://login.example.com/token"

[oauth.registrations.internal_tools.permission_profiles.read]
scope_mode = "explicit" # Default when omitted.
scopes = ["tools.read"]
audience = "https://tools.example.com/mcp"
target = "https://tools.example.com/mcp"
```

Keep the exact endpoint allowed under `[imports]` with `allowed_kinds =
["mcp_http"]`, as described in [imported services](imported-services.md).
The `mcp_oauth` dialect is the OAuth companion of the `mcp_http` import kind:
the Broker selects it together with MCP imports, and only an import of that
kind can bind its registrations. Other dialects, including `google` and the
development `stub`, are never offered to imports.
`base_url` is the exact issuer identifier;
`resource`, profile `audience`, profile `target`, and the imported MCP endpoint must
match exactly. This adapter accepts HTTPS URLs without user information, queries,
fragments or wildcards.
Plain HTTP endpoints are available only for development fixtures: they require
`allow_insecure_loopback = true` and a literal loopback IP address, such as
`127.0.0.1` or `[::1]`, in every endpoint. `http://localhost` is rejected.
The Broker's metadata and token requests route each endpoint origin
independently through the global egress proxy resolution; only literal loopback
addresses connect directly, so `https://localhost` and a non-loopback endpoint
beside a loopback issuer still use the configured proxy.

For confidential clients use `client_auth = "client_secret_post"` or
`"client_secret_basic"` and set `client_secret_ref` to an existing supported `env:`
or absolute `file:` reference. Public clients use `none` and omit the secret
reference. Authorization code flows always use PKCE S256. Token requests use form
encoding. Shared OAuth and client-credentials grants are not implemented.

The metadata URLs may point to RFC 8414 or OpenID Connect discovery documents.
The broker verifies the resource, advertised issuer, authorization and token
endpoints, supported client authentication, code response type and S256 support
against this configuration. Metadata requests contain no access token. Discovery
cannot expand the approved destination set. Startup does not fetch metadata.

## Permission modes

Every permission profile has a `scope_mode`:

| Mode | Configuration | Requests and authorization evidence |
| --- | --- | --- |
| `explicit` (default) | A nonempty `scopes` list is required. | Requests configured scopes and checks that the token's known scopes include them. Extra returned scopes are accepted. |
| `server_default` | `scopes` must be absent, including no `scopes = []`. Available only to `mcp_oauth`. | Omits `scope` from authorization, code exchange and refresh requests. The authorization server chooses the resource's default permissions. |

All profiles within a registration must use the same mode. To use server-default
permissions, replace the explicit profile above with this profile:

```toml
[oauth.registrations.internal_tools.permission_profiles.default]
scope_mode = "server_default"
audience = "https://tools.example.com/mcp"
target = "https://tools.example.com/mcp"
```

The exact `resource` is still sent on authorization and token requests. Issuer,
metadata, endpoint, callback, client authentication, PKCE, audience and target
checks remain in force. These are configuration, metadata and request-binding
checks; the adapter does not introspect opaque access tokens or independently
verify JWT audience claims. A returned token-response `resource`, when supplied,
must match the approved resource.

Server-default permissions may exceed the tools exposed through the Broker, and
the authorization server can change its defaults without a Broker configuration
change. Explicit scopes are a requested and required minimum, not an enforced
upper bound on token authority. In both modes, reviewed tools and Broker
action/context grants limit agent invocations. A compromised upstream token can
carry broader authority than those grants. Review the authorization server's
permission policy before choosing server-default authorization.

Changing a registration's permission mode invalidates its existing connections,
pending consent and connection-bound discovery previews; users must reconnect
and administrators must repeat affected discovery. Adding `scope_mode =
"explicit"` to an unchanged explicit profile does not invalidate connections.

## Administrator and user workflow

1. Create or edit an imported MCP service. Enable Personal credentials, choose
   OAuth, and select the operator-approved registration and permission profile.
2. Choose personal discovery for the signed-in administrator, or supply a separate
   supported static discovery credential if the server permits it.
3. The discovery owner clicks Connect and signs in at the authorization server
   in a new tab. The original import page and unsaved edits stay open.
   The broker receives the browser callback and stores the connection encrypted.
   Approval shows a small **Authorized** page and automatically closes the tab
   when the browser permits it; otherwise use **Close tab** or the browser’s tab
   controls. Denial shows **Authorization canceled**; other provider errors show
   **Authorization was not completed**. Callback validation and exchange errors
   remain visible. The original
   page refreshes its connection status on completion, close or focus.
   If the browser blocks the tab, allow pop-ups for the broker and retry.
   **Return to authorization tab** resumes an open flow. Closing it can leave
   consent pending for up to five minutes; finish or deny consent to end it sooner.
   No token is exposed to the browser or agent.
4. Discover, review and accept tools, enable the service, and configure ordinary
   action/context grants using personal credentials. Each user connects their own
   account on the import's OAuth registration row in **My access > Credentials**.
   Connect/reconnect requires self-service enabled, the import's personal OAuth
   binding, which publishes its credential connection, and an active `per_user`
   action grant covering that user or a current group. Separate
   credential rights are not used. The base administrator has a narrow exception
   for their own import discovery, including later discovery refreshes.

Setup is independent of invocation selection: a matching grant can permit account
preparation even when resources, execution contexts or imported actions are
currently unavailable. Every agent invocation still needs current action/context
permission and a valid delegated credential. An existing owned connection remains
visible and disconnectable after grant removal while self-service remains
enabled; retired or blocked imports still permit cleanup. Reconnect remains
subject to current setup authority. See [connection management](oauth.md#browser-management-api)
for capability flags, shared registrations and retained unbound slots.

The import profile selector, discovery connection and Credentials drawer show
**Server-default permissions** for that mode. Connection details show **Known
scopes** when evidence is available, or **Scope details unavailable**. Missing
scope details do not mean the account has no permissions, and known scopes may
come from earlier consent rather than the latest token response.

Each pending browser flow retains its validated issuer and PKCE verifier. The
callback must match that flow, browser session, registration and current imported
service revision. The Broker rechecks the live grant/group authority and exact
service binding before code exchange and before saving a connection. Changing the
import while consent is pending requires restarting consent. Personal discovery previews retain an opaque connection revision, so
replacement, disconnect or token rotation invalidates an older preview.

## Token lifecycle and identity

The broker's existing connection manager handles encrypted storage, refresh
coordination, reconnect and delegated invocation leases. Each MCP request,
including either startup lifecycle and optional session cleanup, validates its
lease and exact target/audience before using the current access token. OAuth
and tool requests are sent once; an uncertain refresh requires reconnect. A 401
from a normal operation request invalidates only the exact access version sent,
for the next invocation. A best-effort cleanup 401 does not invalidate it or
change the operation's known outcome. Neither case triggers tool replay or a
switch to a shared credential. A timed-out legacy call may continue upstream;
disconnect does not establish that it was canceled.

Standard MCP OAuth does not require an account identity endpoint. This adapter
therefore reports the upstream account identity as unavailable. The broker still
knows which signed-in broker user owns the connection. Replacing a connection
requires explicit confirmation rather than claiming the upstream account matches.
Canceling replacement leaves an access-only connection usable until expiry; a
refreshable connection renews and revalidates the same family before reuse.

A server may issue an access token without a refresh token. That connection remains
usable until expiry and then requires reconnect. Token responses in this supported
profile must supply a positive bounded `expires_in` and a Bearer token type.
Returned scopes must be valid and are retained as evidence. In explicit mode,
an empty `scope` string is rejected; omitting `scope` from the response means the
scopes requested in that exchange were granted. In server-default mode, an empty
`scope` string is treated exactly like an omitted field: the initial response
leaves scope details unknown, and a refresh response uses the original consent's
scope evidence, which may also be unknown. Whitespace-only strings and other
malformed scope values remain invalid in both modes. Omitting `scope` on refresh
preserves the original grant; it does not request whatever defaults the server
now offers. Unusual OAuth flows need a compiled adapter.

Protocol references: [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
and [OAuth token response scopes](https://www.rfc-editor.org/rfc/rfc6749#section-5.1).
