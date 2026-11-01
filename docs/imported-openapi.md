# OpenAPI and Swagger imports

The `openapi_http` adapter turns reviewed operations from a Swagger 2.0 or
OpenAPI 3.1 JSON document into
ordinary broker actions. It uses the same imported-service administration, grants,
execution contexts, credential selection, limits, audit, CLI and MCP interfaces as
MCP imports. It does not infer business resources or resource scopes.
The shared [resource-access helper](resources.md#caller-discovery) reports
available OpenAPI actions as `scope: "unscoped"` and provides no live-listing
hints. An operation name or response schema does not declare resource enumeration.

## Setup

An operator enables `openapi_http` under `[imports].allowed_kinds` and allows
the API base URL under `allowed_endpoints`. When importing from a URL, allow
the definition document URL separately:

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

URL imports keep both destinations as operator gates for discovery and execution.
Removing either one makes the service unavailable, including after restart.
Uploaded documents require only the API destination; they have no document URL
or document-fetch credential. Startup loads accepted operations from the database
without fetching a document.

In **Admin > Catalog > Import service**, a base administrator:

1. Selects OpenAPI / Swagger and enters a service name and API base URL.
2. Chooses **From URL** and enters a document URL, or **Upload file** and browses
   for or drops a Swagger 2.0 or OpenAPI 3.1 JSON file. A private URL can use a
   separate Basic, Bearer or named API-key discovery credential. It is independent
   of the credential used for API calls. File uploads need no discovery credential.
3. Creates the draft, discovers the document and selects a supported security scheme from the discovered
   names. The broker maps HTTP Basic, HTTP Bearer or a header API key into the execution
   credential's delivery settings. Operations remain unavailable until a scheme
   is selected and discovery is refreshed.
4. Reviews operations and explicitly assigns read-only or write-capable status,
   accepts the selection, provisions the execution credential and enables the
   service. Existing action/context grants control access. Operations stay
   write-capable until reviewed as read-only, including POST search operations,
   and the classification also limits
   [read-only identity paths](imported-services.md#classification-and-read-only-identity-access).

Shared execution credentials and personal tokens use the existing service and
per-user modes. A missing personal token never falls back to the shared token or
the document credential. OpenAPI OAuth declarations do not create a working OAuth
integration: this adapter supports static Basic, Bearer and header API keys.
Basic uses the existing encrypted username/token credential and the personal
`username-token` profile; its `token` field contains the password or API token.
The username and secret preserve spaces and Unicode exactly. Usernames cannot
contain a colon, and neither field can contain control characters. Both must be
nonempty; usernames are limited to 256 UTF-8 bytes, with a 32 KiB combined
serialized-secret limit. There is no credential normalization or challenge retry.

The API uses `adapterKind: "openapi_http"`, `endpoint` for the API base URL, and
these string-valued `connectionSettings`:

| Setting | Meaning |
| --- | --- |
| `definitionUrl` | URL of the OpenAPI or Swagger JSON document; required for URL imports |
| `definitionSource` | `upload` for an uploaded document; omit for a URL import |
| `securityScheme` | Selected Swagger `securityDefinitions` or OpenAPI `components.securitySchemes` name; omitted in an empty draft |
| `definitionAuthKind` | `none`, `basic`, `bearer`, or `raw_header` |
| `definitionAuthHeader` | Header name for `raw_header` document authentication |

Public document discovery uses `discovery.kind: "anonymous"`. Private document
discovery uses `"slot"` and the encrypted `discovery` secret slot. Execution and
personal credentials are not reused for document fetching. The existing CLI
`admin imports` request-file commands accept the same definition and lifecycle
operations as the portal.

An upload definition uses `connectionSettings: {"definitionSource":"upload"}`
and `discovery: {"kind":"anonymous"}`. It must omit `definitionUrl`,
`definitionAuthKind` and `definitionAuthHeader`. Add `securityScheme` after
discovery, or include it when its exact name is already known.

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

### Uploading and replacing a document

Create the upload draft first, then send its document:

```bash
agent-access admin imports upload-document inventory \
  --document-file ./inventory.json \
  --expected-version 1 \
  --expected-catalog-revision 12
```

Use the revisions returned by create or the latest import detail. The CLI sends
the exact file bytes and only its basename as optional display metadata. It does
not send a local path, parse and rewrite JSON, or retry the request. Like
discovery, this command allows 75 seconds for the server's 60-second deadline.
The body has a separate receive deadline: the smaller of
`limits.request_body_timeout_ms` and 15 seconds from admission.
Generic `agent-access send` rejects this route because its JSON envelope cannot
preserve exact document bytes; use the dedicated file command above.
If the client times out or loses the response, inspect the current document
summary and preview before retrying: publication may already have completed.

The HTTP equivalent is `PUT /v1/admin/imports/{service}/document` with required
`expectedVersion` and `expectedCatalogRevision` query parameters, an optional
`filename` query parameter, `Content-Type: application/json`, and the raw UTF-8
JSON body. A filename is a basename of at most 255 UTF-8 bytes, without slashes,
backslashes, control characters or a dot-only name. It never selects a filesystem
path or an API destination. The response contains the ordinary discovery preview
and `service.document: {filename?, byteLength, sha256}` metadata, never the
retained document bytes. The SHA-256 digest is lowercase hexadecimal; absent
filenames and absent document summaries are omitted.

The Broker validates and compiles the document before atomically saving it and
publishing its preview. Malformed, duplicate-member, unsupported-version or
oversized documents leave the previous document, preview, accepted actions and
versions unchanged. Stale service or catalog revisions also refuse the upload.
Creation and upload are separate requests: if the upload fails after creation,
the portal keeps the created draft available for correction and retry. Do not
create another service merely to retry its file.

The saved document survives restarts and security-scheme selection on an empty
draft. **Discover** or **Refresh** recompiles that saved document without a
document HTTP request. To change it, upload a replacement from the import detail
page or use the same CLI command with current revisions. A successful replacement
produces a new preview and quarantines changed or missing accepted actions;
unchanged actions retain their accepted behavior. Review and accept the changes
through the existing flow. Replacing a file does not accept actions, grant access,
or change the service's API endpoint or credential delivery.

Switching an empty draft away from upload removes its saved document atomically.
After accepting actions, source settings remain fixed. Retained source bytes are
stored separately from catalog definitions and are not returned by management
reads or included in audit. Treat the database and its backups as containing the
uploaded API document; do not embed credentials in it.

## Supported document and request profile

The supported document profile accepts Swagger **2.0 JSON** and OpenAPI
**3.1.x JSON**, using the same compiler and HTTP executor. The root `swagger` or
`openapi` marker selects the reader; `info.version` is the upstream API's version
and does not select a specification dialect. Duplicate JSON members fail discovery
with a `duplicate JSON member` diagnostic; failed refresh keeps the accepted
generation. Operations use unique
`operationId` values as their source identities, or stable method/path identities
when no operation ID exists. Suggested action names derive from those IDs or
method/path values; administrators can edit them before acceptance. The accepted
HTTP method, path, parameters, security
mapping and response handling are frozen with each action. A later change is
quarantined by manual refresh and requires review; existing grants never silently
acquire new operations.

Inputs separate `path`, `query`, `headers` and `body` values. The adapter supports
primitive path and header parameters, primitive query parameters and primitive
query arrays using form serialization, JSON request bodies, and the scalar
URL-encoded form profile below. JSON bodies may be objects or arrays, and DELETE
may carry a body. GET, HEAD and OPTIONS bodies are unsupported. Required fields
and supported JSON Schema constraints are validated before dispatch; inputs
that break them are denied with `input_invalid` and the adapter's message,
without the field-specific [input explanations](http-api.md#input-explanations)
of native actions. Path values
cannot contain slash, backslash, percent signs or dot-only segments, which avoids
upstream path normalization changing the selected operation. Query values are
escaped independently.

Documents from either source are limited to 4 MiB (or the configured upstream
response limit, if smaller), 512 operations, and a 16 MiB expanded discovery
manifest. Authenticated upload requests also obey the configured HTTP body and
startup hard limits; anonymous requests retain the 1 MiB control-plane cap.
The entire upload body must arrive within the smaller of
`limits.request_body_timeout_ms` and 15 seconds from admission. This receive
deadline is separate from compilation and the CLI's 75-second request timeout;
body receive timeouts return HTTP 408. Invalid uploaded JSON or document structure
returns HTTP 400 `input_invalid`; exceeding an effective byte cap returns HTTP
413 `body_size_denied`. Each accepted
operation and schema also has bounded size/depth/regex budgets. Oversized
discovery fails with an explicit limit error. A document server answering HTTP
429 reports `upstream_rate_limited` for the imported service, naming the wait
when the response carries a valid `Retry-After`.

References are local and bounded, targeting the appropriate `components`
collection in OpenAPI, or `definitions`, `parameters` and `responses` in Swagger.
Reusable parameter map keys need not equal their wire names. Request and response
schemas are self-contained; external references are not fetched. Server definitions and their overrides must
resolve to the configured API destination, with server variables fixed at their
document defaults. URL imports resolve relative destinations against the document
URL. Uploads use the approved API base URL, including Swagger defaults when
`host` or `schemes` is omitted; a filename never participates in resolution.
Swagger `basePath` still defaults to `/`, so a non-root API base requires a
matching declared path. Relative OpenAPI server URLs use ordinary URL resolution
against the exact selected base.
Input values, links and document metadata cannot choose another
destination. Operation security overrides are honored. A supported single-scheme
alternative may be selected; combined authentication requirements and unsupported
security profiles remain visible as unsupported operations.

Swagger schema references must be acyclic; path-item references are unsupported.
Schema references may carry descriptive annotations, but not sibling validation
keywords. The Swagger profile rejects `x-nullable`, null or union types, and
`readOnly: true` in request schemas. These limits apply to referenced schemas too.

OpenAPI 3.0 conversion, 3.2, YAML, cookie/query API-key authentication, anonymous
execution, combined security schemes, multipart or binary transfers, complex
parameter serialization, callbacks/webhooks and external
references are outside this profile. Unsupported operations remain visible with a
reason instead of becoming partially executable actions. The
[OpenAPI 3.1.1 specification](https://spec.openapis.org/oas/v3.1.1.html) defines the
upstream format; these are explicit broker implementation limits.

### URL-encoded forms

Swagger `formData` parameters and supported OpenAPI form request bodies become
an ordinary JSON `body` object. MCP adds its usual `inputs` wrapper:

```json
{"inputs":{"body":{"query":"open items","ids":"123,456","page":2}}}
```

For fields with those declared types, the Broker validates the JSON and sends
`ids=123%2C456&page=2&query=open+items` with
`Content-Type: application/x-www-form-urlencoded`. Callers supply values rather
than encoded strings. Basic credentials are stored separately, never passed as
action inputs. HTTP MCP, local stdio MCP and generic CLI invocation support the
same accepted form actions. Uploading a definition does not enable file-valued
operation inputs or multipart requests.

Forms contain 1–128 declared scalar fields: string, integer, number or boolean.
Unknown fields, nulls, arrays, nested objects and files are rejected. Comma-list
strings remain single strings. An omitted optional field is absent from the
request; an empty string sends `name=`. An omitted optional body sends no body
or content type; an explicit allowed `{}` sends an empty form with its content
type. Fields are emitted once in deterministic name order and escaped once.

OpenAPI form schemas must be closed objects (`additionalProperties: false`) of
declared scalar properties. Local schema references and scalar constraints are
supported. Encoding Objects may be absent, empty, or explicitly use
`style: form`, `explode: true`, `allowReserved: false`; other serialization,
per-property content types, nonempty headers and content-encoding schema
annotations are unsupported. Swagger's declared form parameters determine its
closed object and required fields. Requiredness is validated before dispatch.

Request media declarations use parameter-free `application/json` or
`application/x-www-form-urlencoded`. If an OpenAPI request offers both supported
representations, JSON is selected; callers do not switch encodings. An invalid
JSON representation does not silently fall back to form.

Swagger body parameters require an effective `consumes` array containing
`application/json`; `formData` parameters require
`application/x-www-form-urlencoded`. Schema-bearing responses require an effective
`produces` array containing `application/json` or a supported JSON media type
ending in `+json`. Each operation inherits these arrays from the root unless it
declares its own. Missing or invalid required media declarations make the
operation unsupported. Bodyless operations do not require `consumes`.

Response media declarations must also be parameter-free and contain no whitespace.
This validation applies to accepted frozen plans at startup. Older versions could
load malformed `+json` declarations containing parameters or spaces; those
services now become unavailable. Correct the source declaration, refresh the
import and accept the corrected actions before using the service again. Valid
previously accepted JSON plans retain their stored representation.

Serialized invocation
inputs and the encoded form body each have a 1 MiB limit, including escaping
expansion. Pagination is explicit: callers supply the documented page or token;
the Broker does not follow it automatically.

## Results and execution

The adapter sends each API request once through the broker's TLS, proxy and
allowlist controls. It does not follow redirects, pagination links or callbacks,
and it does not retry a failed write or authentication response.

Results preserve bounded HTTP status and JSON content under `result.upstreamHttp`
as `status` and `body`. The opaque payload is marked sensitive across the catalog,
runtime OpenAPI, JSON-send and MCP surfaces. Declared response status/content and
schemas are validated. Error bodies that do not match a declared response are
omitted while retaining the HTTP failure status. Empty successful responses have
a null body. A Swagger response without a schema declares no response content,
even when `produces` names JSON. Nonempty content for that response is a protocol
failure. For a dispatched write, this yields an unknown mutation receipt with
`retrySafe: false`; correct the upstream response schema, rediscover and review
the changed contract rather than retrying the mutation to repair its receipt.

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

Accepted plans load offline after restart. Existing JSON plan bytes retain their
meaning. Newly accepted Basic or form definitions require a compatible Broker;
before rolling back to an older binary, restore a compatible backup or remove
the affected imports through the newer binary.

## Connecting one imported service

Use `/mcp/<service>` or `agent-access mcp serve --service <service>` with the
canonical imported service ID. Both expose raw provider names without broker
prefixes, while retaining canonical action grants, current bindings, revision
fences and audit. Helpers stay inside the selected service. The action-description
helper (wire name `actions_describe`) accepts the canonical action ID and returns
the Broker wire name `mcpTool.name` for that connection. Clients may rename or
hide tools; call a tool using the name your client exposes.
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
