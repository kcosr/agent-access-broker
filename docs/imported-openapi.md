# OpenAPI imports

The `openapi_http` adapter turns reviewed operations from an OpenAPI document into
ordinary broker actions. It uses the same imported-service administration, grants,
execution contexts, credential selection, limits, audit, CLI and MCP interfaces as
MCP imports. It does not infer business resources or resource scopes.
The shared [resource-access helper](resources.md#caller-discovery) reports
available OpenAPI actions as `scope: "unscoped"` and provides no live-listing
hints. An operation name or response schema does not declare resource enumeration.

## Setup

An operator enables `openapi_http` under `[imports].allowed_kinds` and allows both
the API base URL and the definition document URL under `allowed_endpoints`:

```toml
[imports]
enabled = true
allowed_kinds = ["mcp_http", "openapi_http"]
allowed_endpoints = [
  "https://tools.example.com/mcp",
  "https://inventory.example.com/api",
  "https://inventory.example.com/openapi.json",
]
```

Both destinations remain operator gates for discovery and execution. Removing
either one makes the service unavailable, including after restart. Startup loads
accepted operations from the database without fetching the document.

In **Admin > Catalog > Import service**, a base administrator:

1. Selects OpenAPI and enters a service name, API base URL and document URL.
2. Chooses public document discovery, or a separate discovery credential for a
   private document. The document credential can use Bearer or a named API-key
   header. It is independent of the credential used for API calls.
3. Fetches the document and selects a supported security scheme from the discovered
   names. The broker maps HTTP Bearer or a header API key into the execution
   credential's delivery settings. Operations remain unavailable until a scheme
   is selected and discovery is refreshed.
4. Reviews operations and explicitly assigns read-only or write-capable status,
   accepts the selection, provisions the execution credential and enables the
   service. Existing action/context grants control access. Operations stay
   write-capable until reviewed as read-only, and the classification also limits
   [read-only identity paths](imported-services.md#classification-and-read-only-identity-access).

Shared execution credentials and personal tokens use the existing service and
per-user modes. A missing personal token never falls back to the shared token or
the document credential. OpenAPI OAuth declarations do not create a working OAuth
integration: this adapter supports static Bearer and header API keys.

The API uses `adapterKind: "openapi_http"`, `endpoint` for the API base URL, and
these string-valued `connectionSettings`:

| Setting | Meaning |
| --- | --- |
| `definitionUrl` | URL of the OpenAPI JSON document |
| `securityScheme` | Selected `components.securitySchemes` name; omitted in an empty draft |
| `definitionAuthKind` | `none`, `bearer`, or `raw_header` |
| `definitionAuthHeader` | Header name for `raw_header` document authentication |

Public document discovery uses `discovery.kind: "anonymous"`. Private document
discovery uses `"slot"` and the encrypted `discovery` secret slot. Execution and
personal credentials are not reused for document fetching. The existing CLI
`admin imports` request-file commands accept the same definition and lifecycle
operations as the portal.

An empty draft can change its connection settings and authentication delivery;
its service ID, adapter kind and API endpoint remain fixed. Any settings or
delivery change clears saved shared execution and discovery tokens atomically,
so they cannot be reused for a different destination. Set the required tokens
again after selecting a scheme; private documents may need their discovery token
entered a second time. Existing personal credentials must be removed before
these draft settings can change; they are never silently repurposed or deleted. Once actions are
accepted, connection settings and delivery are fixed too. A configuration change
invalidates its preview. Changing settings and accepting an old preview in one
request is rejected. Use a new service identity for a different connection.

## Supported document and request profile

The supported document profile accepts OpenAPI **3.1.x JSON**. Operations use unique
`operationId` values as their source identities, or stable method/path identities
when no operation ID exists. Suggested action names derive from those IDs or
method/path values; administrators can edit them before acceptance. The accepted
HTTP method, path, parameters, security
mapping and response handling are frozen with each action. A later change is
quarantined by manual refresh and requires review; existing grants never silently
acquire new operations.

Inputs separate `path`, `query`, `headers` and `body` values. The adapter supports
primitive path and header parameters, primitive query parameters and primitive
query arrays using form serialization, and JSON request bodies. Required fields
and supported JSON Schema constraints are validated before dispatch. Path values
cannot contain slash, backslash, percent signs or dot-only segments, which avoids
upstream path normalization changing the selected operation. Query values are
escaped independently.

Documents are limited to 4 MiB (or the configured upstream response limit, if
smaller), 512 operations, and a 16 MiB expanded discovery manifest. Each accepted
operation and schema also has bounded size/depth/regex budgets. Oversized
discovery fails with an explicit limit error. A document server answering HTTP
429 reports `upstream_rate_limited` for the imported service, naming the wait
when the response carries a valid `Retry-After`.

References are local and bounded, targeting the appropriate `components`
collection; schema references target `components.schemas`. Request and response
schemas are self-contained; external references are not fetched. Server definitions and their overrides must
resolve to the configured API destination, with server variables fixed at their
document defaults. Input values, links and document metadata cannot choose another
destination. Operation security overrides are honored. A supported single-scheme
alternative may be selected; combined authentication requirements and unsupported
security profiles remain visible as unsupported operations.

OpenAPI 3.0 conversion, 3.2, YAML, cookie/query API-key authentication, multipart or
binary transfers, complex parameter serialization, callbacks/webhooks and external
references are outside this profile. Unsupported operations remain visible with a
reason instead of becoming partially executable actions. The
[OpenAPI 3.1.1 specification](https://spec.openapis.org/oas/v3.1.1.html) defines the
upstream format; these are explicit broker implementation limits.

## Results and execution

The adapter sends each API request once through the broker's TLS, proxy and
allowlist controls. It does not follow redirects, pagination links or callbacks,
and it does not retry a failed write or authentication response.

Results preserve bounded HTTP status and JSON content under `result.upstreamHttp`
as `status` and `body`. The opaque payload is marked sensitive across the catalog,
runtime OpenAPI, JSON-send and MCP surfaces. Declared response status/content and
schemas are validated. Error bodies that do not match a declared response are
omitted while retaining the HTTP failure status. Empty successful responses have
a null body.

Successful write responses are `applied_unverified`: receiving a success response
does not establish a verified business outcome. A failed write reports whether
its request was dispatched in `operationDispatched`, with a mutation receipt:

- after dispatch, including an HTTP error status, an invalid response or a
  timeout, the outcome is unknown: `mutationStatus: "unknown"` and
  `retrySafe: false`. Do not retry it automatically; inspect the API first.
- when the Broker refused the request URL or proved the request was never sent,
  such as a refused connection, nothing was applied: `mutationStatus:
  "not_applied"` and `retrySafe: true`, so the write can be repeated.

The failure keeps its ordinary reason code. Local output saving uses the
existing receipt behavior and never replays the API operation.

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
