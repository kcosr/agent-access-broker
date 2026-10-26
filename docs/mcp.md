# MCP client interfaces

For agents using an existing connection, the self-contained
[Agent Access MCP skill](../skills/agent-access-mcp/SKILL.md) covers tool discovery,
argument construction, resources, pagination, and result/error handling without
connection setup.

HTTP MCP accepts ordinary Broker invocation tokens and
[managed workspace identity](managed-identity.md) through a named trusted caller.
Managed clients can use a protected caller bearer plus `X-Agent-Access-User` to
select an explicitly bound human, directly or through an approved attester.
Registered fingerprint identity also remains available. All methods use current
Broker permissions; browser cookies do not authenticate MCP. Ordinary clients can
use the same endpoint without trusted assertions. Local stdio uses the CLI's REST
transport; it can use `--no-token` behind fingerprint-aware ingress, but does not
implement the username-header MCP transport.

Upgrade the Broker and CLI together. The current resource-access discovery
contract has no older helper-name, route, or response-shape aliases; refresh MCP
tool discovery after upgrading.

`agent-access mcp serve` is an MCP server for a local agent application and an
HTTP client of the existing broker. The application launches it as a subprocess
and exchanges MCP messages over stdin/stdout. No broker-side MCP endpoint or
separately managed daemon is needed.

The adapter uses the official Rust MCP SDK. It supports initialization and
protocol negotiation, tool listing, tool calls, and cancellation. It exposes
individual provider actions from the broker's runtime catalog, including Jira,
Confluence, GitLab, CloudBees CI, Gmail, and Teams operations, plus five broker discovery
helpers. It does
not expose generic `invoke`/`send` tools, broker management operations, or
gateway execution. Discovery helpers can describe that separate surface.

Jira `project.list` lists live authorized projects with only `maxResults` and
`pageToken`. It has independent action permission and supports whole-result
Markdown. Continue empty `scan_budget` pages using `nextPageToken` until
`exhausted`; issue search has its own contract. Local
`resource_access_describe` reports policy access and registered references.

Jira `project.view` accepts `inputs: {"project":"PROJ"}` to return project
details and searchable fields under its own project grant. Use a returned
`jqlReference`, such as `cf[12345]`, with a supported operator in the separately
authorized `search` tool. Optional `include` and `query` select and narrow
metadata; see [project discovery](providers-jira.md#project-details-and-searchable-fields).

The separately grantable `confluence.space.list` action accepts `inputs` with
only `maxResults` and optional `pageToken`. Results use canonical space grants,
not URL aliases. Continue `more` and `scan_budget` pages even when empty.
Local resource-access discovery describes policy and registered references. See
[space listing](providers-confluence.md#live-space-listing).

GitLab `project.list` lists live authorized repositories, including archived
projects, and accepts only `maxResults` and `pageToken`. It is independently
grantable from `project.search`, which adds optional project filters;
`resource_access_describe` describes policy access and Broker registrations. The six native
`search.*` actions search content across that authority or one explicit project,
subject to operator-configured engine/scope choices. `issue.search` and
`merge_request.search` retain their single-project structured-list contract.
MCP uses the same action schemas and bounded results as CLI/HTTP: preserve search
settings when passing `nextPageToken` as `pageToken`, continue empty resumable
pages, and treat `scanStatus=upstream_window` as incomplete coverage. A continuation
does not guarantee another authorized match. See
[GitLab search](providers-gitlab-rest.md#repository-discovery-and-content-search)
and the [MCP search workflow](../skills/agent-access-mcp/SKILL.md#gitlab-repository-discovery-and-content-search).

Teams `notification.send` uses the same destination alias and `simple` or
`microsoft` content modes on both MCP transports. Local stdio `requestFile`
contains the complete action input object; HTTP MCP takes inline inputs. The
encrypted Workflow URL never appears in the tool schema, arguments, or result,
and admin reveal remains outside MCP. The mutation returns endpoint acceptance,
not confirmation of Teams delivery. See [Teams payloads](providers-teams.md#action-and-clients).

## Service-specific connections

Register one connection for each canonical broker service ID you want to toggle
independently in your client:

| Transport | Aggregate connection | One-service connection |
| --- | --- | --- |
| HTTP | `https://broker.example.com/mcp` | `https://broker.example.com/mcp/monitoring` |
| Local stdio | `agent-access mcp serve` | `agent-access mcp serve --service monitoring` |

No upstream credential is placed in these URLs or commands. Use the same broker
authentication and execution context as the aggregate connection. Stdio does not
require `[mcp]` enabled and consumes no downstream HTTP MCP sessions. The service
selection is fixed for the connection/process lifetime, including after local
token or configuration rotation. Initialization can succeed before a stdio
service becomes available; refresh discovery after granting access.

The aggregate connection reports the executable's assembly name, such as
`agent-access-broker`, as `serverInfo.name`; every HTTP connection reports the
assembly version as `serverInfo.version`. Service connections report the
canonical service ID as `serverInfo.name` and expose provider tools without a
broker prefix or hash:

- Built-ins use canonical action names, such as `issue.view`.
- MCP imports use the exact accepted upstream tool name.
- OpenAPI imports use the exact accepted operation ID, or their saved canonical
  action ID when the document omits an operation ID.

Names preserve case and must contain 1–128 ASCII letters, digits, dots,
underscores or hyphens. The five broker helper names are reserved. Invalid or
conflicting names make the entire service connection unavailable. Aggregate
connections use the separate naming rules below. A client's own prefixes and
model-tool limits can still affect presentation. Dotted names and names over
64 characters are supported by this protocol interface, not a promise about
every client. Use the names returned by discovery and consult the client's
naming support when configuring it.

Arguments and results retain the broker contract, including the provider
`inputs` wrapper. Original names do not imply raw upstream MCP passthrough.
HTTP remains JSON-only; local stdio retains uploads, downloads, secret sources
and local output files. Imported MCP and OpenAPI results retain their sensitive
output markers and uncertain-write receipts. Do not replay an operation to fix
local output failure.

All five helpers remain. `services_list` returns at most the selected service;
other helpers still require `service`, constrained to the selected ID. The
`action` argument remains a canonical broker action ID, while
`actions_describe.mcpTool.name` is the callable name for this connection.
Cross-service discovery or calls are rejected even when the token can access
another service elsewhere. Imported search/list tools remain provider actions,
not broker resource-discovery helpers.

A connection view narrows discovery and execution on that connection. It does
not restrict the credential on other endpoints: use grants and token restrictions
for that boundary. Readiness is computed from every enabled published action
before caller filtering, including file actions omitted from HTTP. Admin import
screens distinguish committed readiness from provisional preview warnings.
Ordinary caller catalogs expose `scopedMcpReady` and nullable `scopedMcpName`,
without administrative source locators or credentials.

Each call and discovery request uses current permissions. Hidden, disabled,
quarantined or conflicting services become unavailable. An existing authenticated
HTTP session still permits its own ping, cancellation and DELETE for cleanup;
revoked credentials fail normal authentication. A session or tool cursor cannot
move between aggregate and service connections or between services. Refresh tool
listing explicitly after relevant grants or definitions change; no change
notifications or background import refresh are added.

Keep `mcp.public_url` at the canonical `/mcp` base. Scoped paths append exactly one
canonical service ID. Encoded aliases, extra segments, trailing slashes and query
strings are rejected without redirects. Allow both `/mcp` and `/mcp/<service>` in
reverse-proxy rules using the same identity, context, Host and Origin protections.
All connections share broker sessions, control concurrency, invocation limits and
audit. Two clients with four service connections each consume the default eight
sessions per principal. Allow headroom for restarts: abandoned sessions expire
after the default 15-minute idle timeout. Size global sessions for all principals
and control concurrency for simultaneous initialization/listing requests.

Stdio still fetches the whole caller catalog with a 16 MiB decode limit, then
selects the service. An unrelated large service can therefore prevent a small
service from loading. Its complete tool projection also has a fixed 64 MiB local
limit. Broker readiness uses `mcp.max_catalog_bytes`; a larger broker budget does
not raise these local client limits.

## HTTP endpoint

The broker can also serve Streamable HTTP MCP at `https://broker.example.com/mcp`
on its existing public listener, behind the existing trusted TLS ingress. Enable
`[mcp]` with `public_url` and either an `Authorization: Bearer` identity source
or a named trusted caller that permits username or fingerprint identity; see
[configuration](configuration.md#mcp). It is disabled by default.

HTTP offers the same five discovery helpers and individual JSON provider tools.
It excludes multipart upload and raw download tools. Those actions remain
visible in discovery, but `actions_describe` omits `mcpTool` for them. HTTP tools
require inline `inputs`; `requestFile`, `files`, `outputPath`, and `secretSources`
are rejected. Use the local stdio adapter for those filesystem operations.
Neither transport changes the broker's resource/grant enforcement.

For Codex, put the following in client configuration:

```toml
[mcp_servers.agent_access]
url = "https://broker.example.com/mcp"
bearer_token_env_var = "AGENT_ACCESS_TOKEN"
```

For Claude Code, use a client MCP JSON configuration:

```json
{
  "mcpServers": {
    "agent_access": {
      "type": "http",
      "url": "https://broker.example.com/mcp",
      "headers": {"Authorization": "Bearer ${AGENT_ACCESS_TOKEN}"}
    }
  }
}
```

The client process must inherit the token environment variable. To read a token
file, a launch wrapper can export `AGENT_ACCESS_TOKEN` from that file before
starting the client; the broker receives only the header and never reads a
client filesystem path. Restart or reconnect after changing credentials. These
settings follow the [Codex HTTP MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
and [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).
Pi requires an MCP-capable integration.

The portal shows this setup after it issues an `agent_invoke` token, when the
endpoint is enabled with `public_url` and a `broker_tokens` identity source reads
`Authorization` with scheme `Bearer`. Its **Connect an MCP client** section
gives the `/mcp` URL, the line that sets `AGENT_ACCESS_TOKEN` to the new token for
macOS/Linux or Windows PowerShell, and setup for Pi, OpenCode, Claude Code, Codex,
or Cursor, each using server name `agent_access`: a command (Cursor: an install
link) and a configuration file. For Claude Code it gives only
`claude mcp add --scope user`, which adds the server for all your projects;
Claude Code manages that configuration file itself. Only the environment line
contains the token.

Every HTTP request authenticates a current static principal, managed
`agent_invoke` token, or enabled username/fingerprint identity through an
authenticated trusted caller. Cookies, anonymous discovery, management tokens,
and OAuth login are not accepted. Sessions bind to the exact credential and execution
context, so replacing a token requires a fresh initialization. Permission checks
are repeated for tool calls. Restart and changes to MCP, identity, execution
context, token/store, or trusted-proxy configuration invalidate sessions; refresh
the client connection. Graceful shutdown delivers in-flight responses, then
closes every open session. Ordinary policy and provider reloads preserve sessions and
recheck current authority on each call. Missing or disallowed `Origin` values are
handled as described in configuration; the public Host must match `public_url`.

The supported HTTP protocol is `2025-11-25`. POST carries MCP requests and
cancellation notifications; DELETE closes a session. GET returns 405. There are
no server notification streams, result replay, background tasks, progress, or
`listChanged` notifications. Refresh tool discovery explicitly. Configure client
timeouts to accommodate the broker's operation timeout and response delivery.

Unlike stdio, HTTP allows catalog-declared sensitive inputs inline and retains
their schema constraints. This exposes those inputs to the calling model and
client history. Use local stdio secret sources when that exposure is unsuitable.
Sensitive output markers remain advisory in both transports.

Explicit cancellation before provider dispatch prevents execution. Session closure,
including at shutdown, and reload do not synthesize explicit cancellation for
already admitted work. Runtime publication and shutdown do remove pending rate
admission without dispatch; ordinary session preservation does not preserve a
queued call across publication.
Once dispatched, execution and audit remain owned by the broker until completion or the bounded
deadline; losing the HTTP response does not prove a mutation failed. An oversized
result returns `mcp_response_too_large` with correlation IDs, broker outcome,
execution state, and `retrySafe: false`. It does not rerun or retain the result.
The exact [delivery failure schema](../schemas/mcp/delivery-failure.v1.schema.json)
distinguishes execution from delivery. Inspect audit or upstream state before
retrying an uncertain mutation.

## Trusted username connections

The managed launcher, outside agent-controlled configuration, repeats one of
these pairs on every HTTP request to `/mcp` or `/mcp/{service}`:

```http
Authorization: Bearer <direct caller credential>
X-Agent-Access-User: alice
```

```http
X-Agent-Access-Caller-Authorization: Bearer <relay caller credential>
X-Agent-Access-User: alice
```

The first requires `credential_transport = "authorization_user"`, a configured
`username_namespace` and fixed context. The second requires
`credential_transport = "caller_authorization"` and a namespace; asserted callers
also supply `X-Agent-Access-Context`, while fixed callers omit it. The exact
namespace/name pair must have an enabled managed binding. Names are case-sensitive
1–128 ASCII bytes from `[A-Za-z0-9._@+-]`. No OS, email or principal-ID lookup is
performed, and username access works without identity-token inventory.

Use a client/launcher that protects both headers from user override and forwards
them only to the approved Broker endpoint. They are connection setup, never tool
arguments or URL parameters. A shared secret does not identify the human without
the controlled assertion. Broker does not accept username mode on REST, browser,
management, health or Git routes. See [caller configuration](trusted-callers.md)
and [administrator bindings](managed-identity.md#username-bindings).

## Read-only identity connections

An administrator can make a username binding or a human's identity token
[read-only](managed-identity.md#read-only-paths). A connection admitted through a
read-only path lists and executes only actions the current runtime catalog
classifies as reads. Its grants still decide which of those reads it has, and a
permitted read selects the same grant as on a full-access path.

- `initialize`, and `server/discover` within a session, append this sentence to
  the server instructions, on `/mcp` and `/mcp/{service}`: "This connection is
  read-only: only actions classified as reads are listed or executable."
- `tools/list` and the five discovery helpers omit write actions; the helpers
  remain available. A service with no remaining actions disappears, and its
  `/mcp/{service}` view returns the ordinary 404 for an unavailable service view.
- Calling a hidden write tool returns the ordinary `invalid_params` error for an
  unknown or unavailable tool, without dispatch.
- Unreviewed imported actions are writes, so they are hidden until an
  administrator classifies them as reads.

A request is judged against the runtime snapshot it was admitted with: a
reclassification applies to requests admitted after it is published. A call
already in flight for a changed imported action can still be refused by the
existing import fences, at grant selection (for command imports, "policy denied
command action") or before dispatch ("imported service changed or is
unavailable; repeat discovery"). Local stdio behind fingerprint-aware ingress
sees the same filtered catalog through REST, where a write call returns 403
`service_action_denied` with reason `identity access is read-only`. Read-only
paths do not restrict local output files.

## Trusted identity and session lifetime

Repeat the current credential and subject on initialization, initialized
notifications, discovery, calls, cancellation and DELETE. A session ID never
replaces authentication. Sessions pin the principal, identity method, context,
endpoint view, caller security contract and managed identity proof. Username
proofs include the namespace and binding ID/version; fingerprint proofs include
the inventory revision. Both include the path's read-only setting and the human's
gate incarnation/version.
Different aliases or methods cannot reuse a session even when they resolve to the
same human. Principal quotas aggregate across them.

Each request resolves live state. After body intake or queueing, final governed
admission checks the original proof against current binding, principal, gate and
caller state before credentials or provider work. A remapped request is rejected;
it never executes as the newly mapped human. Grants and groups are also evaluated
currently. A change committed before that final check denies the request; an
operation admitted before the change may complete under its existing outcome
contract. Pause responses do not promise cancellation.

Pause/resume, disable/enable, read-only changes, delete/recreate and
caller-security changes invalidate old attested sessions even if values are later
restored. A binding's Enabled or Read-only change ends only that binding's
sessions. Inventory churn and identity-token Enabled or Read-only changes
invalidate fingerprint sessions but leave username sessions intact. An update that
changes nothing ends no session. An unchanged reload
preserves sessions; identity-configuration changes can invalidate all MCP sessions,
including unaffected callers. Reinitialize after an identity transition.

Stale identity cannot cancel work or DELETE a session. Confirmed stale proofs are
pruned by background cleanup and before applying the principal's initialization
cap, without cancelling independently owned admitted operations. Store unavailability
is not proof of staleness: unconfirmed entries remain until checked or normally
expired, and new initialization fails 503. Existing idle/absolute timeouts still
apply. Reinitialization can therefore recover slots after a confirmed transition.

## Request header and body restrictions

Presence of `X-Agent-Access-User` selects username mode before principal-token
authentication. Duplicate/malformed names or bearer fields, both caller carriers,
a fingerprint alongside a username, and alternate principal credential carriers
are rejected. A wrong caller, wrong transport, missing capability or unknown/paused
human never falls back to an ordinary token, cookie or fingerprint. Queries are
rejected, including a bare `?` delimiter. Ordinary token precedence over fingerprint
identity applies only without the user header.

Protected `Connection` nominations are rejected. Every MCP `Trailer` declaration
and actual trailer frame, declared or not, is rejected; Broker consumes the full
bounded body before provider dispatch. For ordinary-token/fingerprint requests,
trailer rejection is HTTP 400 JSON
`{"error":"MCP request trailers are not supported"}`, with no-store, no JSON-RPC
ID and no Bearer challenge. Username mode returns the reserved
`identity_assertion_invalid` admission envelope. No trailer can supply identity.

Username failures before MCP handling use the canonical Broker JSON admission
envelope and outer 400/401/403/503 status. They use no-store and add a Bearer
challenge only for 401. Final tool-admission failures carry the same reserved
envelope inside an HTTP 200 MCP error tool result using negotiated JSON/SSE
framing. Discovery/control revalidation failures use the outer HTTP status.
A valid identity with a mismatched session keeps the existing invalid-session
response. Authenticated GET remains 405. See the exact
[admission failure tuples](trusted-callers.md#http-failures-before-provider-dispatch).

The remaining configuration and filesystem examples below describe **local
stdio MCP**.

## Configure a client

For Codex, add the following to `~/.codex/config.toml`, substituting the installed
executable and configuration paths:

```toml
[mcp_servers.agent_access]
command = "/absolute/path/to/agent-access"
args = ["--config", "/home/me/.config/agent-access/config.toml", "mcp", "serve"]
```

The referenced file is ordinary agent-access configuration:

```toml
[service]
url = "https://broker.example.com"

[identity]
disabled = false
header = "Authorization"
scheme = "Bearer"
token_file = "/home/me/.config/agent-access/token"
```

The client header and scheme must match the selected broker identity source.
`Authorization` with `Bearer` matches both published broker templates. Use an
issued token for managed identity, or a token registered by the configured static
identity source. The anonymous quickstart keeps client identity disabled.

Alternatively, set these variables in the environment that launches your MCP
client, then forward all four to the subprocess:

```bash
export AGENT_ACCESS_URL="https://broker.example.com"
export AGENT_ACCESS_TOKEN_FILE="/home/me/.config/agent-access/token"
export AGENT_ACCESS_IDENTITY_HEADER="Authorization"
export AGENT_ACCESS_IDENTITY_SCHEME="Bearer"
```

```toml
[mcp_servers.agent_access]
command = "/absolute/path/to/agent-access"
args = ["mcp", "serve"]
env_vars = [
  "AGENT_ACCESS_URL",
  "AGENT_ACCESS_TOKEN_FILE",
  "AGENT_ACCESS_IDENTITY_HEADER",
  "AGENT_ACCESS_IDENTITY_SCHEME",
]
```

The existing [CLI configuration precedence](cli.md#config-env-and-default-precedence)
applies; an existing config file can override environment settings. Custom TLS
trust, token files, named token environment variables, and connection flags use
the same resolver as CLI commands. Config and token files are read again for
each list or call request. An environment variable is inherited when the
subprocess starts; changing the parent's environment requires restarting it.

Other MCP clients should configure the same executable and arguments using their
stdio server configuration. The process must run on a machine that can access
both the broker and the local files named in tool calls. Paths inside a remote
executor refer to that executor's filesystem.

## Discovery and permissions

Native `tools/list` and all five discovery helpers filter actions and resources by
locally usable execution and lookup credentials. `services_list` and
`services_describe` retain authorized service summaries with `availability`:
`available`, `partial`, `unavailable`, or `unknown`. Missing, expired, disabled or
unreadable material hides the affected tools and schemas; unknown checks also hide
them. A service-specific connection with no usable provider actions exposes only
the five helpers, so setup requirements can still be inspected. Management/setup
workflows remain independent.

Checks do not contact upstream or refresh OAuth. A locally eligible refreshable
connection remains available. Every list request checks again, and every invocation
still validates its selected credential. The server does not push
`notifications/tools/list_changed`; harnesses may cache their initial list. After
setup, disconnect, or credential replacement, refresh the tool list or reconnect.
See [credential availability](http-api.md#credential-availability).

The adapter retrieves `GET /v1/spec/catalog` using the current identity and
projects each caller-visible `invoke` action into an MCP tool. Each tool carries
its service/action description and action input schema. Aggregate names join the
canonical service and action with an underscore, replacing punctuation with
underscores: `cloudbees_ci` action `build.log.read` becomes
`cloudbees_ci_build_log_read`. Names have no automatic hash suffix or truncation
and must fit 128 ASCII characters. Clients must use the names returned by `tools/list`.
Metadata includes `agent-access/service` and `agent-access/action`.

If distinct visible actions produce the same aggregate name, both provider tools
are omitted. Names that exceed the limit or match one of the five fixed helpers
are also omitted. Helpers and unrelated tools remain available. These checks
include visible file actions even on HTTP, where file tools cannot be called.
`actions_describe` explains an omitted name through `mcpToolUnavailable`:
`name_conflict`, `name_too_long`, or `reserved_name`, without revealing other
actions the caller cannot see. Administrators can review naming diagnostics in
the Broker log and correct proposed import action IDs before acceptance.

Tool names identify the current catalog binding. Removing an action can free its
name for a different action later; refresh discovery when the catalog changes and
review name-based client approval rules. No previous hashed-name aliases are
provided. Deploy matching Broker and CLI versions when upgrading and refresh
tool discovery and name-based allowlists.

Clients supporting native tool search can index these individual tools and load
the appropriate schemas on demand. Search and deferred loading are client
features, not a separate search implementation in this adapter. Clients without
search can list and call the same tools normally.

Discovery is filtered by identity, token restrictions, a
[read-only identity path](#read-only-identity-connections), grants, and execution
context. A listed action may be usable only on some resources. The broker
resolves the actual requested resource and authorizes every invocation. The
adapter never treats a tool listing as authorization to execute.

Listings paginate at 100 tools, including the fixed helpers. Cursors bind the
selected view, caller identity/context, and complete tool definitions; relevant
changes require restarting without a cursor.
Native tool lists and calls fetch a fresh catalog. Discovery helpers fetch their
own current broker capability sources. Service-specific helpers first validate
the current selected catalog and readiness, then restrict results before saving
any local output file. The adapter does not advertise push
`listChanged` notifications: refresh the client's tool list or reconnect to see
newly granted tools. Previously discovered tools cannot bypass revoked access.

## Discovery helpers

Action tool definitions keep descriptions and parameter guidance concise. Actions
with extended documentation include an explicit `actions_describe` instruction
using stable `service` and `action` arguments, for example `service="jira"`,
`action="search"`. Use those values even when the client prefixes or renames the
executable tool. The helper returns optional `documentation` with detailed
syntax, limits, and examples. This provider-owned JSON object is separate from
`inputSchema` and is not included in initial `tools/list` definitions or the
helper's `mcpTool` argument schema. Both HTTP and stdio MCP expose the same
usage documentation; fetching it is an ordinary tool call, not an automatic MCP
protocol operation.

Jira and Confluence search descriptions explain that `projects`/`spaces` may be
omitted to use effective broker authorization. An empty or ordering-only query
can browse that boundary. Jira needs finite project narrowing or a caller filter;
Confluence retains its page/blogpost type restriction even for all-space grants.


The following fixed names accept flat JSON arguments, without the provider
`inputs`/`requestFile` wrapper. They read broker metadata without changing
upstream state, and their successful object appears identically in text and
`structuredContent`. Local stdio helpers also accept optional absolute
`outputPath`; when set, that object is saved as JSON and the tool returns a file
receipt instead. Because this can overwrite a local file, stdio helper tools
advertise `readOnlyHint: false` and `destructiveHint: true` for their complete
argument contract. HTTP helpers reject `outputPath` and retain
`readOnlyHint: true` and `destructiveHint: false`. Both transports advertise
idempotent helpers.

| Tool | Arguments | Result |
|---|---|---|
| `services_list` | Optional `prefix` | `{services:[{service,displayName,surface,actions:[names]}]}` |
| `resource_access_describe` | Required `service`; optional `action`, `resourceType`, `prefix`, `limit`, `cursor` | `{service,executionContext,availability,coverageSemantics:"single_target",access:[...],registeredResources:{source:"broker_configuration",items:[...],nextCursor},liveListings?:[{service,action,resourceType}]}` |
| `actions_list` | Required `service`; optional `resource`, `resourceType`, `prefix` | `{service,resource?,actions:[names]}` |
| `actions_describe` | Required `service`, `action` | Full action definition; invoke actions include `mcpTool` |
| `services_describe` | Required `service` | Complete service capabilities, action schemas and authenticated caller limits |

`services_describe` includes [live service limits](http-api.md#live-service-limits)
on both transports, including service-scoped connections. Its process-local
observations describe this principal's effective rate, FIFO queue and shared
request occupancy; they reserve nothing. Anonymous detail omits `limits`, and
`services_list`/`tools/list` stay static. Describe retains independent bounded
capacity when invocation slots are full. Scoped stdio `services_describe` uses
that detail directly, requiring an authenticated, visible invoke service with
`scopedMcpReady: true`; it does not require a separate catalog request. Other
scoped helpers and provider calls retain their catalog admission.

Start with `services_list` when the service is unknown. Use
`resource_access_describe` to see effective local access by action and resource
type, registered references, and explicit live-listing hints. An optional `action`
is an exact canonical name. Omitting `resourceType` describes all types and
unscoped actions; no type filter is required for a service with several types.
`executionContext` identifies the admitted context. `availability` uses the
service list's readiness and remediation shape, explaining empty access from
missing credentials. Unknown and unavailable action filters both return
`action is not available`; invalid syntax returns `action name is invalid`.
An action/type filter combination that does not match the action's resource
binding is rejected.

The response's `access` entries are either
`{action,scope:"resource",resourceType,enforcement,coverage:[{selector,inputs?,restricted}]}`
or `{action,scope:"unscoped"}`. Scoped `enforcement` is `request` for Broker
request checks, `results` for native query/result containment, or `command` for
grants passed to a command that must check targets and filter results itself.
Unscoped actions omit this field. Selectors are `exact`, `namespace`, or `all`;
`restricted: true` means some values inside are withheld; useful exact/narrower
grants remain listed beneath restricted coverage. `coverageSemantics` is
`single_target`: the summary does not authorize combinations of targets, and
compound-only actions may have empty singleton coverage. It reflects current
local policy and usable credentials without verifying backend access or refreshing
OAuth. No discovery helper queries upstream inventory.

`registeredResources` has `source: "broker_configuration"`, `items`, and
`nextCursor`. These are enabled, context-eligible exact registered references;
empty items do not establish no access. Use a reference's `inputs` as-is when
present. Optional `liveListings` gives `{service,action,resourceType}` for
explicitly declared and available enumeration actions. Multiple hints can name
the same type, always within the described service. Each listing has its own
coverage and enforcement entry. With an `action` filter, describe the listing
action itself to inspect that entry. Each has independent grants and credentials;
even combining their results does not establish another action's complete
inventory. See [caller discovery](resources.md#caller-discovery).

Only registered references are paginated or filtered by `prefix`. Pages default
to 50 references, maximum 100; repeat service, action, resource type, prefix, and
limit with `registeredResources.nextCursor`. Every page repeats the full access
summary and hints. Changed policy, identity, context, credential availability or
resource metadata invalidates the cursor. No helper aggregates pages.
A cursor belongs to the Broker runtime that issued it and becomes invalid after
reload or restart. Multi-instance deployments need session affinity so every
page reaches the issuing instance; otherwise restart without the cursor.

The access summary is complete and unpaginated on every page. The reference
`limit` does not bound the whole response. Action and resource-type filters can
reduce its size, but even a single action is not guaranteed to fit. MCP and CLI
transport size limits fail closed rather than return partial access.
See [caller discovery](resources.md#caller-discovery) for oversized-response alternatives.


`actions_list` needs `resourceType` for resource-qualified checks when the service
authorizes several resource types.

`actions_list` accepts canonical project/space keys or repository paths, not
broker resource IDs. A broad grant can permit an unregistered locator. This is
a single-target policy check, not proof of upstream existence or permission for
every target in a compound request. Invocation still reauthorizes the request.

Aggregate stdio helpers use ordinary `/v1/services` visibility, including
anonymous access where the broker permits it, non-invoke surfaces, and supported
non-agent token classes. Their fixed names resolve through a bounded helper
registry without fetching the authenticated provider catalog. Native provider
tools require the complete caller runtime catalog and its bounded registry. Descriptions and raw schemas come from broker
capability definitions. Invoke `actions_describe` additionally checks the fresh
caller catalog and returns its IO, sensitive-field, presentation metadata and
exact native MCP wrapper schema. Non-invoke details omit `mcpTool`, as do actions
with an unavailable aggregate name (with `mcpToolUnavailable` explaining why).
Invoke-action
detail requires authentication: an anonymous caller receives the catalog's HTTP
401 as a broker tool error (CLI exit 6). Use `services_describe` for raw
definitions where service discovery allows anonymous access. A catalog
entry unavailable after service discovery produces an explicit detail error;
use `services_describe` for raw capabilities or retry. Conflicting snapshots or
failed fetches never produce stale or partial success.

Known helper calls with invalid arguments return tool errors. Broker failures
preserve the structured broker envelope. Unknown tool names and invalid
`tools/list` cursors remain protocol errors; a `resource_access_describe` cursor is a tool
argument and its rejection is a tool error. The session survives these errors.

## Tool arguments

For a JSON action, supply an `inputs` object matching the advertised action
schema. For example, a Jira issue-view tool takes:

```json
{"inputs":{"issue":"ABC-123"}}
```

For a large or frequently edited request, save that same action input object to
an absolute local file path and pass:

```json
{"requestFile":"/home/me/work/request.json"}
```

The file contains `{"issue":"ABC-123"}`, not a `send` or HTTP invoke envelope.
Exactly one of `inputs` or `requestFile` is required. This lets the agent edit a
file and submit its path without reproducing its contents in a tool call.

JSON and multipart-upload tools, including writes, accept optional `outputPath`:

```json
{"inputs":{"issue":"ABC-123"},"outputPath":"/home/me/work/issue.json"}
```

The adapter saves the complete successful broker envelope as JSON, including
nested Markdown when `responseFormat: "markdown"` is selected. It returns a
small receipt in text and `structuredContent` instead of the saved result.
The receipt keeps correlation/status identifiers, sets `operationStatus` to
`succeeded` for confirmed success, and adds
`output: {status, path, size, sha256, contentType, sensitive}`. `size` is the actual
byte count; `output.status` is `succeeded`; `sensitive` reflects declared catalog
output markers, not content inspection. Resource grants, result bounds, pagination, and the 16 MiB JSON
response limit still apply. Choosing a path never switches a bounded read to a
full download or collects additional pages. HTTP MCP rejects `outputPath` on
every tool.

The adapter reserves a private adjacent temporary file before a provider
invocation, including a download. An invalid destination fails before the upstream
action is sent; denied, failed, malformed, or explicitly cancelled requests
discard the reservation without replacing the destination. A destination can
still become unwritable while the action runs.

If a JSON or multipart-upload operation succeeds and saving its response fails,
the tool returns an error result
with structured `operationStatus: "succeeded"` and `output.status: "failed"`,
available request identifiers, and the local failure reason. The saved payload
is not returned or retained. Do not repeat the operation to retry saving its
response; this could duplicate a write. Remote failure or uncertain execution
never becomes confirmed success merely because output was requested. Dedicated
raw downloads check their destinations before transfer and retain their existing
transfer-failure handling.

An upstream `applied_unverified` mutation retains that `operationStatus` even
when saving succeeds. Successful and failed save receipts preserve compact,
non-sensitive mutation outcome and bounded reconciliation metadata; they never
turn an unverified write into confirmed success. Inspect that metadata rather
than repeating the write to recover output.
The compact fields are top-level `mutationStatus`, `retrySafe`, `verificationStage`,
and `safeLocators`; oversized or catalog-marked sensitive fields are omitted.

Upload tools additionally require `files`; use the role and fields advertised by
that tool's schema:

```json
{
  "inputs":{"issue":"ABC-123"},
  "files":[{"role":"attachment","path":"/home/me/work/report.pdf"}]
}
```

The adapter snapshots each file and derives its size, digest, and multipart
metadata from the snapshot before sending. Optional `filename` and, for actions
that allow it, `contentType` are supported. Provider limits still apply. A
refusal after Broker admission returns its denial envelope; authentication,
concurrency and rate-limit refusals do not read the file, so for a large file
they can instead fail as a closed connection.

Download tools require `outputPath` with an absolute local destination. The
adapter streams into a private temporary file, verifies the advertised length
and digest when present, and atomically replaces the destination. The tool
returns broker metadata plus the same `output` receipt; file bytes never go
onto MCP stdout. JSON reads use the same private temporary-file and atomic
replacement handling. Denied or failed reads and incomplete transfers leave an
existing destination intact. If parent-directory synchronization fails after
replacement, the reported local error indicates that the file was replaced.

Imported command downloads use this same contract: `outputPath` sits beside
`inputs` or `requestFile` and never reaches the Broker or command. Their receipt
includes computed size/SHA-256, filename, content type and bounded command
metadata under `result.upstreamCommand`; the output is marked sensitive, which
does not redact that metadata. A valid partial export may carry warnings; a
truncated transfer fails with `isError: true`. Explicit mutation outcomes survive
body or local save failures without replaying the command. Ordinary command
errors also return `isError: true` without replacing the destination. HTTP MCP
excludes these executable download tools but permits their action detail.

CloudBees CI `job.list` takes `controller`, optional `folder`, `maxResults`, and
`pageToken`, and returns a filtered JSON page of live jobs and containers. Continue
`more` and `scan_budget` even when empty; `upstream_window` means terminal
incomplete coverage. Other CloudBees CI actions take `controller` and `job`
(from `resource_access_describe` registered-reference or coverage `inputs`),
or a pasted Jenkins job or build `url`, and build-level
actions accept `buildSelector` permalinks such as `lastFailedBuild`; see
[locating jobs and builds](providers-cloudbees-ci.md#locating-jobs-and-builds).
CloudBees CI `build.log.read` is a JSON tool on both transports. It supports
`head`, `tail` (default), and literal `search` modes with bounded output; callers
should inspect scan coverage and pass only broker-issued continuation cursors.
See the [console-read guide](providers-cloudbees-ci.md#bounded-console-reads) for scan
ceilings, pending UTF-8 text, and continuation rules. Saving the JSON result
locally does not turn a bounded excerpt into a complete log download.

CloudBees CI `build.log.download` and `build.tests.download` use this same
`outputPath` interface, alongside artifact downloads. HTTP MCP excludes these
raw tools; direct HTTP invoke supports them with `Accept: application/octet-stream`.

All file paths are absolute; `-` is not stdin/stdout. Input files must be regular
files. Local request JSON and broker JSON responses are limited to 16 MiB;
uploads have a combined 512 MiB limit. Downloads use the Broker's configured
`limits.max_download_bytes` cap. Incoming MCP frames are limited to 16 MiB.
Use `requestFile` for requests that would exceed the frame limit after JSON
escaping. Broker/provider upload limits can be lower.

JSON requests and multipart uploads use the CLI's `[service].request_timeout_ms`
(default `30000`) for the whole HTTP request, including upload transmission,
Broker rate waiting and response. The 512 MiB upload cap is a size ceiling, not a
promise of completion before the deadline. Downloads use that setting for the
send/header phase and retain a separate 30-second body idle timeout. Compare
`services_describe`'s `maxWaitSeconds` with client/proxy timeouts and allow useful
execution time. No automatic timeout negotiation or retry occurs.

A timed-out request may still be queued or executing because close detection can
be delayed. Reconcile a mutation's outcome before resubmitting it.

An oversized incoming MCP frame ends the stdio session with a non-zero exit;
the client must restart the process. This bounds input buffering even for an
unterminated frame. Other concurrent requests may have uncertain outcomes. Use
the file input mode to keep large payloads out of protocol frames.

Actions advertising response presentation accept `readContentFormat` and/or
`responseFormat`. CLI defaults apply when supported. Explicit whole-result
Markdown overrides an ambient embedded-content default; conflicting explicit
formats are rejected. Responses retain the broker envelope in both MCP text and
structured content, or in the saved JSON envelope when `outputPath` is used.
Rate-limited tool errors are the one exception to the text copy; see
[rate limits](#rate-limits).

## Sensitive data and errors

Catalog-declared sensitive inputs cannot be supplied inline. Use `requestFile`
or a declared local source:

```json
{
  "inputs":{"project":"team/repository","webhookId":12},
  "secretSources":[{
    "pointer":"/inputs/token",
    "source":{"type":"file","path":"/home/me/.secrets/webhook-token"}
  }]
}
```

The precise action fields and sensitive pointers come from the tool schema.
Sources may be `file` (absolute path) or `env` (variable name); stdin sources are
unavailable. Secret sources have a 1 MiB limit. Tools that deliberately issue
credentials retain their sensitive-output pointers in
`_meta["agent-access/sensitive-output-pointers"]`. That metadata is advisory:
clients may still display or retain returned tokens, so use such tools only in
clients suitable for that workflow.

Broker denials and execution failures are MCP tool errors with the broker's
structured envelope. Local argument validation and broker HTTP failures return
safe tool errors without terminating the server; unavailable tool names are protocol
errors. Catalog/config failures fail discovery rather than advertising stale
permissions. HTTP redirects are rejected, preserving the broker identity
boundary.

### Rate limits

Optional Broker `max_wait` holds the same tool call in a FIFO queue for its
principal/service before execution. Waiting retains existing request/response
slots and consumes no rate unit until admission. HTTP MCP waiting and execution
share one absolute operation deadline; REST-backed stdio uses its configured
HTTP timeout and the Broker's existing ingress deadline. Do not resubmit calls
that remain pending.

If the absolute deadline is already elapsed during initial admission, before a
rate grant or queue insertion, HTTP MCP returns a tool error with
`operation_timeout`, `executionState: "not_dispatched"`, `retrySafe: true` and
`deadlineKind: "operation"` in the original action's result and audit.
The underlying Broker status is 504; native HTTP MCP retains HTTP 200 JSON-RPC
tool-error delivery. REST-backed stdio preserves `body_malformed` (HTTP 400)
with the same proof and
`deadlineKind: "body"`. The outcome is the same before, during or just after the
initial rate-settings read and consumes no rate unit. An actually queued deadline
expiry or a future FIFO turn that cannot fit still produces the existing
`rate_limited` tool error (Broker status 429). Only the correlated complete proof
establishes no dispatch; timeouts without it remain uncertain. It does not
guarantee unchanged access or
configuration for a later attempt, and neither transport retries automatically.

A tool call rejected with Broker status 429 is a tool error. For `rate_limited` (a
Broker limit on how often you may invoke the service) and
`upstream_rate_limited` (the upstream service throttled the request), both the
local stdio adapter and the Broker's HTTP MCP endpoint make the tool error's
text the Broker's message, which names the service and the wait, for example
`jira is rate limiting requests. Retry after 30s (at 2026-09-25T14:03:30Z).`
HTTP MCP does so whether the Broker refused the call at admission or the
upstream service throttled it after dispatch. The complete envelope stays in
structured content. Broker admission limits use the reserved
`broker/request.admit` tuple without `result`; upstream failures may include
`result.retryAfterSeconds`/`result.retryAt` when the wait is known. With
`outputPath`, the destination is left untouched. `concurrency_limited` keeps the
ordinary JSON text.

Agents should wait the reported duration (or retry later when it is absent)
before retrying, and must not retry in a loop. A validated, correlated
`broker/request.admit` tuple proves the request was not dispatched. An upstream rate limit
never claims that: a multi-step action may already have completed earlier
upstream calls, so inspect any reported outcome (such as `mutationStatus`)
first. Retry timing honors accepted waiters. On `concurrency_limited`, wait for
capacity without resubmitting in-flight requests, including rate waiters; this
rejection has no `Retry-After`. Neither transport retries automatically.

Stdio cancellation drops its local HTTP future. The Broker removes pending rate
admission without a charge or dispatch when it observes abandonment; HTTP MCP
explicit cancellation reaches its admission owner directly. Observed cancellation
before admission returns `operation_cancelled` with `executionState:
"not_dispatched"` and `retrySafe: true`. Runtime publication and shutdown likewise
cancel pending admission. Connection loss detection can be delayed, so local
cancellation or timeout alone does not prove that outcome. After admission,
existing operation ownership and explicit-cancellation dispatch checks apply;
delivery loss does not roll back a mutation. Reconcile an uncertain outcome
before retrying. Closing stdin ends the server; diagnostics use stderr.

## Validation

`cargo test -p agent-access --bin agent-access mcp::` covers catalog projection,
transport framing, pagination, local file/secret handling, multipart adaptation,
verified downloads, and safe errors. `cargo test -p agent-access --test mcp_stdio`
drives the real stdio binary against HTTP services, including the real broker's
policy enforcement. `cargo test -p agent-access --test mcp_cancellation` checks
in-flight cancellation, no retries, and current per-request protocol discovery.
Use the repository's build-service wrapper when available.

Gmail’s eleven JSON actions are available through both MCP transports when granted.
Read annotations come from the Gmail descriptor; account linking remains a browser
management operation. Mail is untrusted data. See [Gmail](providers-gmail.md).


## Imported MCP actions

Use the caller-filtered catalog for the service/action names and accepted schemas of
imported MCP tools. These are action-only grants without resource scopes. Results
preserve MCP content as JSON under `result.upstreamMcp`; images/audio remain bounded
JSON and resource links are not fetched. The entire opaque payload is catalog-marked
sensitive, including reads, so output markers cover private data as well as secret
exports. Writes are reported as applied but unverified on upstream success; failures
after dispatch may be uncertain and are never automatically replayed. Saving a local
response is separate from operation success. See the imported-services guide in
`docs/imported-services.md` for administrative setup and supported protocol limits.

Imported MCP services may use personal OAuth through the existing browser Connect
flow when the operator configures the supported `mcp_oauth` profile. The human
needs self-service enabled and a matching active `per_user` action grant, assigned
directly or through a current group; separate credential rights are not required.
Connecting does not expand Broker invocation access. A connection error requires
user/operator action; agents never receive OAuth refresh tokens or replace a
personal connection with a shared credential. See `docs/imported-oauth.md`.

Imported OpenAPI operations use the same discovered action interface. Follow their
accepted input schemas: parameters are separated into `path`, `query`, `headers`
and `body`. JSON results appear under `result.upstreamHttp`, marked sensitive;
write receipts retain `applied_unverified` or unknown outcomes. Never replay an
uncertain operation to retry authentication or local file saving. See
`docs/imported-openapi.md` for administrative setup and the supported profile.

## Trusted caller admission

HTTP MCP uses the [trusted-caller contract](trusted-callers.md) for exact username
bindings or registered fingerprints. Username mode is unique to HTTP MCP; the
existing fingerprint contract also serves ordinary HTTP invocation and Git.
A caller credential alone never authenticates the human. Attested sessions pin
the original proof and loaded caller security epoch alongside principal, context
and service view. Caller removal or secret/security changes invalidate sessions;
ordinary grant/group changes are reauthorized on the next request. Stdio clients
continue through their ordinary Broker REST ingress. See
[identity lifetime](#trusted-identity-and-session-lifetime).
