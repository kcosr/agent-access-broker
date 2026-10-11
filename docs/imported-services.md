# Imported services

Base administrators can connect a generic upstream MCP HTTP server or import an
[OpenAPI document](imported-openapi.md) and review operations as broker actions. Each import is an independent service with a stable ID,
its own credentials, invocation limit, and accepted action catalog. Nothing in the
importer depends on Grafana, Prometheus, or a particular vendor.

This model grants whole actions. A grant still names subjects, execution contexts,
actions, and a configured credential mode; imported actions have no broker resource
scopes. Use context-specific grants when the entire action is appropriate for that
context. An upstream search or generic API tool may reach everything its backend
credential can access. Importing it does not create folder, project, namespace, or
query-level containment. Use a compiled provider when that containment is needed.

## Operator setup

Enable managed identity and policy, managed-store encryption, and management, then
allow the destination in TOML:

```toml
[imports]
enabled = true
allowed_kinds = ["mcp_http"]
allowed_endpoints = ["https://tools.internal.example/mcp"]
disabled_services = []
```

Use exact endpoint URLs. The normal host network policy applies, including TLS,
egress proxy, bounded responses, and redirect rejection. Endpoint URLs cannot
contain user information, query credentials, or fragments. HTTPS is required;
loopback HTTP is available only outside production for development fixtures.
Startup and reload reconstruct accepted definitions locally without discovery.

Imports are database-owned. The TOML controls are an operator gate over them;
setting `enabled = false`, removing an allowed destination, or adding a service to
`disabled_services` stops discovery and execution while preserving records and
grants. Administrators can still inspect, disable, retire, and delete credentials.
Existing retained grants remain editable, but unavailable actions cannot be added
to new grants or expanded to additional subjects or contexts.

The managed store holds the import catalog and encrypted service-owned token
slots. All retained slots participate in key readiness, used-key inventory, and
credential rewrap. See [database operations](database.md).

## Administrative workflow

1. Open **Admin > Catalog** as a base administrator, choose **Import service**,
   and create a draft; the draft opens on the service's **Import** tab. Supply a service ID,
   display name, MCP endpoint, and execution credential bindings. The service ID,
   upstream destination, and accepted source-to-action mappings are durable
   identities. A different destination requires a new service ID.
2. Configure a shared execution token, personal credentials, or both. Discovery
   normally uses the shared execution token. Advanced setup can select a separate
   discovery token or the invoking administrator's personal token. A separate
   transport bearer token is supported when execution uses a different raw header.
   For personal discovery, enable the personal execution binding and use **Set
   personal token** in the Import tab's credentials section. This administrator-only
   path provisions your own credential before the draft has actions or grants.
   While the draft has no accepted actions, credential delivery may change.
   Changing it clears saved execution and discovery tokens atomically; the
   transport token is retained. Remove any personal credentials before changing
   delivery, then set the required tokens again. Delivery is fixed after actions
   are accepted.
3. Choose **Discover tools**. The broker reads the complete bounded tool list and stores a
   fifteen-minute preview. It does not call the tools. Unsupported definitions
   remain visible with a reason. Pagination failure publishes no partial listing.
4. Select tools and review their proposed action names and Read-only / Write-capable
   classification. Names are generated deterministically and may be edited before
   acceptance; accepted names remain stable. Upstream read-only hints are suggestions,
   not authority. Unconfirmed actions are write-capable.
   Choose short canonical action IDs: the aggregate MCP name combines the service
   and action IDs with underscores and must fit 128 characters. Acceptance rejects
   new names that collide after punctuation replacement, match a fixed Broker
   helper, or exceed that limit. This check includes disabled and quarantined
   non-retired actions as well as configured built-ins.
5. Accept the selection, then enable the service. Acceptance does not create grants.
   Assign service-policy managers and create grants through the existing policy UI.
   Users provision personal tokens through the existing credentials workflow.
6. Use manual discovery to refresh. New tools stay unselected. Missing, unsupported,
   or behaviorally changed accepted tools are quarantined immediately after a complete
   discovery. Existing grants are retained. Reviewing changed schemas/annotations or
   restoring such actions requires acceptance; affected grants require confirmation.

The service's **Actions** tab lists each saved action identifier, optional display
label and description without another discovery request. Long descriptions have
an expandable preview, and duplicate label/description text is shown only once.
Labels default to an upstream MCP title or OpenAPI summary/operation ID and can be
edited or cleared by the administrator. When an OpenAPI description is absent,
discovery uses the upstream summary, operation ID, or HTTP method and path.
Editing a label does not change that description. Agents receive the description
and input schema; the display label is management UI metadata. Labels
and Read-only / Write-capable classifications can be revised through a fresh discovery
review; changing classifications affecting existing grants requires confirmation.

Descriptions and display labels are metadata. Schema or execution-annotation changes
are behavioral changes. Disable is reversible. Retirement reserves the service/action
identity permanently. An administrator cannot recycle a retired name onto a different
upstream tool.

An upstream tool whose former action is retired can be reviewed under a fresh action
name. The retired name and its grants remain unchanged; existing grants never move
to the new action. Re-enabling a disabled service or action that has retained grants
requires explicit confirmation.

Existing records with incompatible aggregate MCP names remain manageable and do
not prevent startup or unrelated edits. Their affected aggregate tools are
omitted, with a reason in `actions_describe` and bounded administrative log
diagnostics. Re-enabling an incompatible action or service is rejected. Accepted
canonical IDs cannot be renamed: retire an affected action and review it under
a suitable new ID, then explicitly grant the replacement. Service-specific MCP
names use their own [readiness rules](#service-specific-mcp-readiness).

Mutations carry both the expected service version and catalog revision. A stale
request fails with a version conflict. Refresh the record and review again. A preview
also expires after configuration changes or selected discovery-credential rotation.
A canceled HTTP response waiter does not abandon a committed catalog publication.

## Limits and admission

Imports have fixed structural limits in addition to the configured upstream
request/response limits. Smaller deployment limits still apply. Discovery must
complete successfully within these bounds; a failed or incomplete listing does
not publish a partial catalog.

| Item | Limit |
|---|---|
| Retained imported services, including drafts and retired services | 256 |
| Tools in one complete MCP discovery | 2,048 |
| MCP tool-list pages in one discovery | 128 |
| Discovery manifest / cumulative serialized MCP listing results | 16 MiB |
| Accepted action definition, including schemas and metadata | 256 KiB |
| Each input or output schema | 256 KiB; JSON nesting depth 64 |
| Action description / optional display label | 16 KiB / 256 bytes |
| Non-retired action entries per service, including disabled/quarantined actions | 2,048 entries and 16 MiB total |
| Retired action entries per service | 8,192 entries and 32 MiB total |
| Complete retained imported catalog across all services | 64 MiB |
| Distinct regexes / combined regex source per schema | 32 / 8 KiB |
| Regex compilation and DFA budget per pattern | 256 KiB each |
| Regex backtracking budget | 100,000 steps |
| Total MCP discovery deadline | 60 seconds |
| Saved discovery preview | One per service; expires after 15 minutes |

Retirement reserves identities permanently and has its own allowance; it does
not consume the non-retired action allowance. Per-service allowances do not
reserve space in the shared 64 MiB catalog. Schema limits bound structure and
regex compilation; they are not a general CPU deadline for JSON Schema validation.

Publication also checks the complete executable catalog, including built-ins
and all available imported actions, before caller filtering. Both HTTP and
stdio MCP projections must fit `mcp.max_catalog_bytes`. The generated runtime
catalog, OpenAPI document and JSON-send schema must each fit a separate 64 MiB
projection ceiling. These checks include serialized schemas, helpers and metadata,
so a retained catalog that fits its storage limit can still exceed a projection
limit.

The broker checks candidate import mutations before committing and checks runtime
construction at startup and reload. An over-budget mutation or reload is rejected
without replacing the active catalog. It does not trim tools or weaken schemas to
fit. Reduce the accepted catalog or the size of its definitions; increasing the
MCP budget does not change the fixed storage and runtime-spec ceilings.

## Credentials and identity

Execution credential ownership and authentication mechanism are separate. Static
token execution supports bearer or an administrator-configured raw
header. A service binding uses its encrypted execution slot. A personal binding uses
the caller's managed `default` credential with profile `token`. The selected personal
credential never falls back to a shared service or discovery token.

The broker still authenticates the invoking user and enforces their agent token,
context, grant, rate limit, and audit identity when upstream uses a shared token.
Upstream sees whatever authority that token represents. Browser SSO does not by
itself supply an MCP API token or a delegated OAuth connection.

Personal OAuth connections are supported through operator-approved `mcp_oauth`
registrations. In the import form choose **Personal credentials → OAuth**, then
select the registration and permission profile for the exact MCP endpoint. Users
connect on the existing Credentials screen. The administrator whose personal
connection is selected for discovery can connect directly from the draft's
credentials panel before any actions or grants exist. Shared OAuth credentials
and client-credentials grants are not supported.

The operator chooses explicit OAuth scopes (the default) or `server_default`
permissions for the registration. Server-default profiles omit scope requests;
the portal displays **Server-default permissions**, with known scope details
when available. Broker action/context grants apply in either mode. See
[permission modes](imported-oauth.md#permission-modes) before selecting a profile.

The supported OAuth profile uses preregistered clients with PKCE S256, public
clients or client-secret post/basic, and approved resource and authorization-server
metadata endpoints. The broker validates metadata before consent and token
exchange; it never follows metadata to an unapproved destination. Authentication
is separate from tool discovery, and the selected OAuth connection never falls
back to a stored static token. See [OAuth setup](imported-oauth.md).

If the server does not disclose an upstream account identity, the UI says so.
Replacing that connection requires explicit confirmation; the broker does not
claim it has verified the same person upstream. Access tokens without a refresh
token work until expiry, then require a new connection. Refresh and MCP tool calls
are single-attempt operations; an upstream 401 never replays an imported write.

Other authentication adapters may be recorded as unsupported metadata, but cannot
execute. OpenAPI imports use the same lifecycle with a separate document parser,
security-scheme picker and HTTP executor; see [OpenAPI setup](imported-openapi.md).
Upstream stdio process hosting remains outside this release.

## CLI and HTTP management

`agent-access admin imports` has `list`, `get`, `create`, `update`, `discover`,
`preview`, `accept`, `status`, `action-status`, and nested `credentials put/delete`
commands. Create/update/accept take `--request-file`. Versioned commands take
`--expected-version` and `--expected-catalog-revision`. Shared token writes read
`--secret-file`, `--secret-env`, or `--secret-stdin`; they never return plaintext.
Retirement uses `--confirm`. Typed discovery allows 75 seconds for the server's
60-second discovery deadline. If a client times out, inspect the preview before
starting another discovery.

The matching admin routes are under `/v1/admin/imports`:

| Method | Suffix | Purpose |
|---|---|---|
| GET / POST | collection | List / create draft |
| GET / PATCH | `/{service}` | Inspect / update settings |
| POST | `/{service}/discover` | Discover or manually refresh |
| GET | `/{service}/preview` | Inspect pending preview and affected grants |
| POST | `/{service}/accept` | Accept reviewed source selections |
| POST | `/{service}/status` | Enable, disable, or retire |
| POST | `/{service}/actions/{action}/status` | Change an accepted action's availability |
| PUT / DELETE | `/{service}/credentials/{purpose}` | Write / remove execution, discovery, or transport token |

The runtime OpenAPI and JSON-send schemas carry exact request/result shapes and
mark token input sensitive. List, inspect, and saved-preview reads permit
administrators and auditors. Discovery and all changes require administrator
write authority and normal browser CSRF protection. They are not agent-facing MCP tools. Service-policy
managers may manage grants for approved actions but cannot import tools or change
credentials/endpoints through these admin routes.

## Upstream MCP compatibility

The imported `mcp_http` adapter supports exactly MCP `2026-07-28` and `2025-11-25`
over Streamable HTTP. Discovery, credential verification and invocation each
select a lifecycle automatically under their existing operation deadline:

| Selected version | Startup |
| --- | --- |
| `2026-07-28` | `server/discover`, then requests with current protocol metadata and headers |
| `2025-11-25` | `initialize`, validate the selected version and tools capability, then `notifications/initialized` |

Each operation first probes the current version, which is preferred when both
are available. A valid advertisement supporting only the previous revision, or
a recognized rejection of the startup probe, permits one legacy initialization
attempt. Rejection handling covers HTTP 400/404/405/415/422, including middleware
that rejects the protocol header before reading the request ID. Successful
responses always require a matching request ID. Version advertisements must be
valid and overlap the supported pair; modern header/capability errors remain
terminal. An HTTP 200 error permits fallback only for a valid previous-version
advertisement, method-not-found or invalid-request rejection.

Authentication challenges, HTTP 401/403/407/408/429, redirects, server errors,
network failures, timeouts, cancellation and unreadable or oversized responses
never trigger fallback. Startup has at most two attempts, carries no tool
arguments, and uses the same endpoint and selected credential throughout. Once
startup succeeds, the version cannot change within that operation. There is no
protocol cache or session pool across operations.

Discovery metadata, credential-verification audit and invocation audit record the
actual selected version after successful negotiation. A protocol mismatch does
not revoke an OAuth connection, change its scopes, or start consent. Existing
imports, accepted actions, grants and OAuth connections need no recreation,
configuration change or database migration.

### Legacy sessions and transport limits

A `2025-11-25` server may issue an `MCP-Session-Id` during initialization. The broker
keeps it private to this operation and sends it on subsequent requests to the
same endpoint. Sessionless servers also work. Session IDs are never persisted,
published in discovery, or included in logs/audit, and never cross users,
credentials or operations. Session headers on later responses are ignored.

After the outcome is known, the broker attempts best-effort DELETE cleanup of the
initialized session. If an eligible probe rejection selects legacy initialization
and supplies its own valid session ID, that ID is retained solely for one cleanup
DELETE and is never used for initialization or tool requests. Cleanup makes at
most one DELETE per distinct
ID, with the initialized session first, sharing a two-second budget within the
remaining operation deadline. Each DELETE revalidates the selected credential's
authority. Cleanup is skipped after cancellation, timeout, a normal-operation
401, or a session-bearing 404. Its failures never replace the known outcome or
invalidate an OAuth token, including a cleanup 401. Upstream session expiry and
retention remain the server's responsibility.
An ordinary operation deadline reached during cleanup preserves the captured
outcome through the HTTP MCP supervisor. Forced broker shutdown can still report
an unknown outcome under the [request lifecycle](design.md#request-lifecycle).

Both versions support bounded JSON responses and finite request-scoped SSE.
Legacy results without `resultType` are treated as complete. Server-to-client
requests, including legacy `ping`, are unsupported and terminate the operation.
Background GET streams, SSE polling/resumption, subscriptions, tasks, sampling,
elicitation, older protocol revisions, deprecated HTTP+SSE transport and upstream
stdio process hosting are unsupported. A stream closing before its final response
is a failure; the broker does not reconnect or replay the request.

## Invocation and outcomes

Accepted actions appear in the ordinary caller-filtered catalog. Use generic
`agent-access invoke`, JSON `send`, HTTP invocation, or the broker's downstream HTTP
or local stdio MCP adapter. Invocation uses accepted definitions and never
refreshes the tool list. Protocol selection happens only during startup; no tool
call is replayed after an authentication, session, transport or protocol failure.
A session-bearing HTTP 404 ends the operation. A future independent operation
starts with a new lifecycle and session.

Invocation audit records include the admitted import catalog, service and action
revisions alongside normal caller, context and outcome fields. These revisions
identify the definitions used for the call without recording credentials or tool
arguments.

The adapter enforces accepted input schemas and validates declared structured
outputs. Local references and anchors are supported within the bounded schema
profile; external references, base IDs, dynamic references, and references into
literal data are unsupported. Schema/manifest bytes and depth, regex backtracking,
request duration, SSE event size, and response size are bounded. Each schema permits
at most 32 distinct regexes and 8 KiB of regex source, with 256 KiB compilation/DFA
limits per pattern. Discovery compiles tools sequentially on a blocking worker.
Current-protocol header mirroring supports direct root primitive properties only;
nested annotations remain visible as unsupported tools. Integral floats used in
mirrored integer properties are sent as canonical JSON integers in both the body
and header. Legacy calls send accepted arguments without modern routing or
parameter headers. JSON Schema's validator has no general per-evaluation CPU
deadline; schemas are administrator reviewed and accepted under these structural
bounds.

MCP content is preserved under `result.upstreamMcp`, including explicit null
structured content, text, images, audio, and resource links. Images/audio remain
bounded JSON content in this release; the broker does not fetch embedded links or
convert them to native downstream image/file content. This entire opaque payload
is conservatively marked sensitive, including read results. Sensitive-output
markers cover imported private data as well as deliberate secret exports. Normal local
file-output receipts report that marker; output failures never replay the tool.

A successful write-capable MCP response is `applied_unverified`: it reports upstream
acceptance without independently proving the backend mutation. After dispatch,
transport/protocol/tool/output errors retain an uncertain mutation outcome with
`retrySafe: false`. Agents must inspect the backend outcome before deciding on a
separate operation. Read-only classification is a reviewed statement about upstream
effects, not a restriction on saving a local response file.

In the legacy protocol, disconnecting does not prove cancellation: a timed-out
call may continue upstream. Its uncertain write outcome remains `unknown` with
`retrySafe: false`.

## Connecting one imported service

Use `/mcp/<service>` or `agent-access mcp serve --service <service>` with the
canonical imported service ID. Both expose raw provider names without broker
prefixes, while retaining canonical action grants, current bindings, revision
fences and audit. Helpers stay inside the selected service; `actions_describe`
accepts the canonical action ID and returns the callable `mcpTool.name`.
Refresh client discovery after accepted definition changes. Raw names can resolve
to a replacement canonical action only under current grants; retiring the old
action never transfers its grant. See [connection setup](mcp.md#service-specific-connections)
for naming limits, shared HTTP quotas and stdio whole-catalog limits.

## Service-specific MCP readiness

Import detail and mutation responses include a derived `scopedMcp` object with
`ready`, bounded `issues` (codes and canonical action IDs), and `truncated`.
It describes the current published definitions, including actions the current
agent cannot see. Disabled, retired, and quarantined actions are excluded.
The ordinary caller catalog exposes only `scopedMcpReady` on services and
`scopedMcpName` on each visible action; source locators and credentials remain
administrative data.

Preview responses separately include `scopedMcpWarnings`, with `toolIndex`,
`proposedAction`, and `codes`. These provisional warnings do not block accepting
an otherwise supported aggregate action, and are outside the stored manifest
and its hash. Editing canonical names can affect warnings for unnamed OpenAPI
operations. Acceptance recomputes readiness from the final selection.

A scoped name must contain 1–128 ASCII letters, digits, underscores, hyphens, or
dots. The five broker discovery helper names are reserved. An invalid, reserved,
or duplicate name, an unavailable service, or an oversized scoped projection
makes the whole service-specific view unavailable. Aggregate import acceptance
and execution retain their existing rules and budgets. Diagnostics are bounded
to 128 issues and 16 canonical action IDs per issue; truncation never changes
the readiness decision.

Imported MCP names come from the accepted original tool name. OpenAPI names use
the accepted operation ID, or the saved canonical action ID when the document
omits an operation ID. Changing labels does not rename tools. An accepted
operation ID containing spaces or slashes cannot be locally aliased for scoped
use: change the upstream document and review the resulting new source identity.
An unnamed operation gaining an operation ID is a new source identity, with no
automatic transfer of grants. Invalid or duplicate document operation IDs remain
unsupported by import acceptance rather than becoming an unnamed fallback.
