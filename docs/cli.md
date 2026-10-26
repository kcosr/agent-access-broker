# CLI reference (`agent-access`)

Runtime catalogs use `agent-access.catalog.v2`. Every service includes
`scopedMcpReady`; every action includes `scopedMcpName` as an exact name or null.
These fields describe service-specific MCP projection only; canonical action IDs,
grants, invoke routes, and send envelopes are independent of that projection.
Catalog-dependent clients must support `agent-access.catalog.v2`. Missing required
metadata is a contract error. Upgrade the CLI and Broker together: resource-access
discovery requires the current route and response contract and has no compatibility
aliases.

`agent-access` is the broker client binary. It resolves a broker URL, an identity
token, and transport settings, then calls the broker's HTTP API. The CLI never
receives upstream credentials: it sends an identity token, and the broker
resolves and holds all upstream secret material on its side.

`mcp serve` runs a local stdio MCP adapter using this client's broker settings.
Add `--service monitoring` to expose only that canonical service ID, using raw
provider names. The selection is immutable for the subprocess, including after
configuration/token rotation. One service is accepted; repeated values, wildcards,
comma-separated lists and display names are rejected. Initialization does not
probe the broker; listing and calls require current visibility and readiness.
The full caller catalog must fit the existing 16 MiB decode limit, even for a
small selected service; the complete tool projection is bounded at 64 MiB.
Running the HTTP broker service is the job of the separate
`agent-access-broker` binary. See [local MCP](mcp.md) for client configuration,
individual action tools, and local file inputs and transfers.

Output is pretty-printed JSON by default, with these exceptions noted below:
`config validate` and `auth token ...` print plain status lines, `auth
git-credential ...` speaks Git's credential-helper protocol, eligible provider
reads can print Broker-produced Markdown, and successful stream downloads to
explicit stdout write raw bytes. `mcp serve` reserves stdout exclusively for MCP protocol messages.

## Save action results to a file

`--output PATH` chooses the local destination; `--output-format` chooses the
representation where supported. Provider JSON and multipart-upload actions,
including writes, plus runtime `spec` commands, service/resource/action discovery,
and `broker status` accept a destination. Omitting it, or using `--output -`,
preserves normal stdout output. Management commands, authentication, and other
local commands reject this option. Typed credential-issuance commands retain
their dedicated secret-output options, such as `--token-output`; generic action
invocation preserves the declared sensitive-output handling.

```bash
agent-access jira issue view PROJ-123 --output issue.json
agent-access invoke jira.issue.view --input-json '{"issue":"PROJ-123"}' --output-format markdown --output issue.md
agent-access invoke jira.attachment.download --input-json '{"issue":"PROJ-123","attachmentId":"10055"}' --output report.pdf
agent-access spec catalog --output-format json --output catalog.json
agent-access services list --output services.json
```

Typed JSON actions and `invoke` save the same successful representation they
would print: a JSON envelope or extracted Markdown. Generic `invoke --output`
also saves every catalog-declared raw download, including native and imported
command downloads. It fetches the current caller catalog once for planning,
selects the action's declared I/O, reserves the destination, and negotiates raw
bytes with the Broker. Missing actions or failed discovery prevent invocation.
Explicit unsupported Markdown/content conversion options fail locally; ambient
format defaults do not alter raw bytes.

Downloads require `--output`; relative paths are allowed. `--output -` verifies
the complete download in a temporary file before emitting only raw bytes on
stdout, without a JSON receipt. Without `--output`, generic invoke keeps its
ordinary JSON request and the Broker rejects a download before execution.
A stale catalog never causes fallback execution or automatic retry: refresh
discovery before making a separate invocation.

For JSON responses, `send` saves the full broker envelope, including when Markdown is nested in
`result`. Generic file output changes neither the selected action nor its bounds,
pagination, or resource/action authorization. For example, saving `build.log.read`
saves one bounded JSON chunk; `build.log.download` still retrieves the full
available console stream and requires an explicit destination.

A successful file write prints a small JSON receipt, not the saved content:
`output.status` is `succeeded`; `operationStatus` describes the upstream outcome
and is `succeeded` only for confirmed success. `output` also contains
`path`, `size` (actual bytes written), `sha256`, `contentType`, and `sensitive`.
Invoke receipts retain correlation/status identifiers. The `sensitive` flag
reflects catalog-declared sensitive outputs; it does not scan content. All raw
downloads retain their broker metadata and add the same
`output` receipt. Stdout destinations emit only the normal payload, unless a
`send` request explicitly selects a separate metadata destination.

Before a provider invocation, including a download, the client reserves a private
temporary file beside each requested destination. Missing or unwritable parents and
directory destinations fail before the operation is sent. The reserved file
atomically replaces the destination only after a successful, validated result.
Broker denials, execution errors, handled cancellation, malformed responses, and
incomplete downloads discard the temporary reservation and leave an existing destination intact
and retain normal error output/exit behavior. A reported directory-sync failure
after replacement means the destination has already changed. This is local
client output handling; no filesystem path is added to the broker request.

Provider response file output supports JSON, multipart-upload and raw-download
actions from the fresh catalog. `readOnly` classifies upstream effects and does not gate file
output. It also limits a [read-only identity path](managed-identity.md#read-only-paths)
to actions classified as reads. Discovery failure prevents dispatch when catalog
validation is required.

If a JSON or multipart-upload operation succeeds but saving its response fails,
the client reports `operationStatus: "succeeded"` and `output.status: "failed"`,
retains available request identifiers, and emits the structured error on stderr
with exit code `1`.
It reports the local failure without returning or retaining the original payload.
Do not repeat the operation to retry saving: a local output failure does not undo
an upstream change. Remote errors or uncertain execution are not reported as
confirmed success. A failed separate metadata-file write uses
`metadataOutput.status: "failed"` and preserves any
successful output receipt, including a completed stdout write. Raw
downloads check their destinations before transfer. Body or integrity errors
preserve a validated explicit mutation receipt; headers alone do not establish
that a streaming read completed. After all bytes have been verified, a local
commit or sync error can report known operation success with failed output.
`destinationReplaced`
records whether the failed destination was already replaced before a
directory-sync error.

An upstream `mutationStatus: "applied_unverified"` remains
`operationStatus: "applied_unverified"` in both successful save receipts and
local-output failures. Compact receipts preserve non-sensitive, bounded mutation
outcome and reconciliation metadata separately from the saved result. A saved
response does not establish that an unverified write was verified. Inspect its
reconciliation metadata; do not repeat the write to recover its response.
When present and safe to expose, the top-level receipt fields are `mutationStatus`,
`retrySafe`, `verificationStage`, and `safeLocators`. Oversized or catalog-marked
sensitive fields are omitted. A recognized `not_applied` outcome stays
`not_applied`; an unrecognized mutation status becomes `operationStatus: "unknown"`.

## Global flags

These flags are parsed globally. Command-specific restrictions are noted below:

| Flag | Type | Meaning |
| --- | --- | --- |
| `--output <PATH>` | path | Save a supported action result locally; `-` uses stdout. Downloads, including generic invoke downloads, require this option. Rejected on unsupported commands. |
| `--config <PATH>` | path | Path to the CLI config file (see config precedence below). |
| `--url <URL>` | string | Broker base URL. |
| `--token-value <STRING>` | string | Identity token, supplied literally. Rejected by management commands, `auth token` commands, and `auth git-credential` (see below). |
| `--token-env <NAME>` | string | Name of an environment variable holding the identity token. |
| `--token-file <PATH>` | path | Path to a file holding the identity token (trimmed when read). |
| `--identity-header <NAME>` | string | HTTP header used to carry the identity token. |
| `--identity-scheme <STRING>` | string | Token scheme; must be `raw` or `Bearer` (validated; any other value exits `3`). `raw` sends the token verbatim; `Bearer` sends it as `Bearer <token>`. |
| `--no-token` | flag | Send no identity token at all. |
| `--allow-insecure-broker-http` | flag | Permit sending a token over non-local plaintext HTTP (development only). |

There is intentionally no global, typed-command, `invoke`, or `send` execution-
context flag. `X-Agent-Access-Context` is a fixed trusted-ingress header: the
CLI targets the base URL for the desired trusted entrypoint. That ingress must be
a [named trusted caller](trusted-callers.md). Asserted ingress replaces client
context values with an approved value and injects its private
`X-Agent-Access-Caller-Authorization` credential; fixed ingress supplies its
credential and omits the context header. The CLI never needs that credential.
Do not configure either protected header as `--identity-header` or add it through
provider action inputs. `X-Agent-Access-User` is likewise not a CLI identity
header: trusted username authentication is HTTP MCP only. The CLI and local
stdio adapter use REST and cannot enable it with `--no-token`.

`--identity-scheme` must be `raw` or `Bearer`; the resolved scheme is validated
before any broker call, so any other value aborts with `identity.scheme must be
raw or Bearer` and exits `3`. `Bearer` sends the token as `Bearer <token>`; `raw`
(the default) sends it verbatim.

## Command catalog

Every command below targets the broker over HTTP except `config validate`,
`auth token ...`, and `auth git-credential ...`, which run entirely locally.

### `auth`

- `auth status` — `GET /v1/me`. Prints the identity summary as pretty JSON,
  including `readOnlyAccess` behind fingerprint-aware ingress and, for a person
  with a Microsoft sign-in, `microsoftMembership` (group evidence expiry and
  renewal state).
- `auth token status` — locally inspects the configured `identity.token_file`
  and effective token source without printing token material. A leading `~` in
  the configured token file is shown after expansion to the current user's home
  directory.
- `auth token set [--token-stdin]` — locally writes a prompted token, or a token
  read from stdin, to the configured `identity.token_file`. Existing files are
  truncated in place; newly created token files use owner-only permissions on
  Unix. A leading `~` in the configured token file is expanded before writing.
- `auth token clear` — locally truncates the configured `identity.token_file` to
  zero bytes. It does not delete the file or edit config.
- `auth git-credential get` — reads a Git credential request from stdin and
  returns the effective broker identity token as the password with the fixed
  username `agent-access`. The request must contain nonempty `protocol` and
  `host` fields. This command is intended to be called by Git, not interactively.
- `auth git-credential store` — consumes a Git credential request without
  persisting it or changing the Agent Access token.
- `auth git-credential erase` — consumes a Git credential request without
  revoking, deleting, or clearing the Agent Access token.
- `auth git-credential capability` — succeeds without advertising optional
  credential-helper capabilities.

The credential helper reads `key=value` records through EOF or the first blank
line. It ignores fields it does not need, including `path`, `username`, and
unrecognized fields. A successful `get` writes only:

```text
username=agent-access
password=<effective broker token>
```

If the request is malformed or no usable token resolves, the helper writes an
actionable diagnostic to stderr, writes only `quit=true` to stdout, and exits
successfully. This prevents Git from prompting or falling through to another
helper. Token management remains exclusively under `auth token set
--token-stdin` and `auth token clear`.

The successful `password` field is the helper's only token output. Credential
input and token material are not included in diagnostics, logs, traces, status
summaries, and the helper never copies the resolved token into another process's
arguments.

### `broker`

- `broker status` — `GET /v1/broker/status`. Prints the authenticated Broker's
  immutable build identity and contract versions as pretty JSON.

The response names the running assembly (`assembly.name`, `version`,
`qualification` and `source`), the linked `host` and `sdk` packages, every
compiled module package with its `roles`, an `inventoryFingerprint`, and
`catalogVersion`/`sendSchemaVersion`. For example, abbreviated to one module:

```json
{
  "assembly": {
    "name": "agent-access-broker",
    "version": "0.1.0",
    "qualification": "unqualified",
    "source": {"revision": "3c14665eb32caf14e21373a762da328ea78b79a2", "provenance": "evidence"}
  },
  "host": {"crate": "agent-access-broker-host", "version": "0.1.0", "source": {"revision": "3c14665eb32caf14e21373a762da328ea78b79a2", "provenance": "evidence"}},
  "sdk": {"crate": "agent-access-provider", "version": "0.1.0", "source": {"revision": "3c14665eb32caf14e21373a762da328ea78b79a2", "provenance": "evidence"}},
  "modules": [
    {"crate": "agent-access-jira", "version": "0.1.0", "roles": [{"role": "native", "id": "jira"}], "source": {"revision": "3c14665eb32caf14e21373a762da328ea78b79a2", "provenance": "evidence"}}
  ],
  "inventoryFingerprint": "sha256:6f1c9d0e2b7a4c58e93d1f60a2b4c7e8d9f0a1b2c3d4e5f60718293a4b5c6d7e",
  "catalogVersion": "agent-access.catalog.v2",
  "sendSchemaVersion": "agent-access.send.v1"
}
```

Each `source.provenance` is `evidence`, `declared`, or `unavailable` with a
`null` revision; an unstamped local build reports every source as unavailable.
The module list is what the executable compiles in, not what its configuration
enables. See [the HTTP API](http-api.md) for every field. The command uses
normal Broker identity and request-ID handling, but requires no admin right,
provider grant, or execution context. It is intended to verify the deployed
binary without exposing branch, dirty state, build time, host, or path
metadata; it does not replace health or readiness checks.

### `config`

- `config validate` — runs the local CLI config validator (`validate_cli_config_file`)
  with no broker call. On success it prints `cli config valid: <path>` and exits
  `0`. On failure it prints each validation error and exits `3`.

### `services`

- `services list [--prefix <prefix>] [--verbose]` fetches caller-visible service
  capabilities and projects a sorted compact object:

```json
{"services":[{"service":"jira","displayName":"Jira","surface":"invoke","actions":["issue.view","search"],"availability":{"state":"available","requirements":[],"message":"Required credentials are locally available; upstream access has not been verified."}}]}
```

Surfaces use the broker's canonical `invoke` or `gateway` spelling. Action names replace counts. `--verbose` returns an unwrapped array of
complete service objects, including action schemas. `services describe SERVICE`
returns one complete service object, including authenticated callers' effective
`limits`, FIFO queue/rate observations and shared request occupancy in JSON and
text output. Observations are process-local estimates, not reservations; anonymous
detail omits them. Lists remain static. See [live service limits](http-api.md#live-service-limits).
An empty compact list is `{"services":[]}`.
`availability` reports local credential readiness. Missing or unusable credentials
hide actions, schemas, resources and coverage; an authorized service remains with
empty actions and safe setup requirements. Partial services retain only usable
access. Unknown readiness also hides affected capabilities. Resolve the reported
user/administrator requirement and refresh discovery. No upstream check or OAuth
refresh occurs while listing. See [availability](http-api.md#credential-availability).

### `resource-access`

`resource-access describe --service SERVICE [--action ACTION] [--resource-type TYPE] [--prefix PREFIX] [--limit N] [--cursor CURSOR]`
describes effective local access per action and resource type, followed by
registered references and optional live-listing action hints. `--action` is an
exact canonical action name. `--resource-type` is optional even for services with
several types; without it, all types and unscoped actions are described.
`executionContext` identifies the admitted context; `availability` uses the same
credential readiness and remediation shape as `services list`, including when
missing credentials leave `access` empty.

```json
{"service":"jira","executionContext":"default","availability":{"state":"available","requirements":[],"message":"Required credentials are locally available; upstream access has not been verified."},"coverageSemantics":"single_target","access":[{"action":"issue.view","scope":"resource","enforcement":"request","resourceType":"jira_project","coverage":[{"selector":{"kind":"exact","value":"ENG"},"restricted":false}]}],"registeredResources":{"source":"broker_configuration","items":[{"id":"jira-eng","type":"jira_project","value":"ENG","displayName":"Engineering"}],"nextCursor":null}}
```

Scoped `access` entries contain `coverage` of `exact`, `namespace`, or `all`
selectors and optional action `inputs`. Their `enforcement` is `request` for
Broker request checks, `results` for native query/result containment, or `command`
for grants passed to a command that must enforce them. `restricted: true` means
some values inside are withheld. Useful exact or narrower entries remain under restricted
broad coverage. Unscoped actions use `{action,scope:"unscoped"}` without
`enforcement`. Coverage reflects policy and locally usable credentials, not backend existence or access.
It describes single targets; invocation authorizes a complete multi-target
request. A compound-only action can have empty singleton coverage. An unknown or
unavailable `--action` returns `action is not available`; invalid syntax returns
`action name is invalid`. An action/type filter combination that does not match
the action's resource binding is rejected.

`registeredResources.items` contains enabled, context-eligible exact references,
with optional configured display names and action `inputs`. Empty items do not
imply no access. Pass a reference's `value`, not its catalog `id`, to
`actions list --resource`. Optional `liveListings` entries identify separately
granted enumeration actions as `{service,action,resourceType}`. Several can list
the same type, always within the described service. Their own access can differ from another action's; use their schemas and pagination when invoking.
Each has its own coverage and enforcement entry: with `--action`, describe the
listing action itself to inspect that entry. Combining listings does not establish
another action's complete inventory.
See [caller discovery](resources.md#caller-discovery).

Only registered references are paginated: default 50, maximum 100. `--prefix`
filters those references only. Follow `registeredResources.nextCursor` with the
same service, action, resource type, prefix, and limit. Every page repeats the
complete access summary and hints. JSON `send` exposes this as HTTP operation
`resource_access.describe` at `/v1/services/{service}/resource-access`.
The CLI does not aggregate pages. A stale, changed-filter, or foreign cursor
fails; restart without the cursor.
A cursor belongs to the Broker runtime that issued it and becomes invalid after
reload or restart. Multi-instance deployments need session affinity so every
page reaches the issuing instance; otherwise restart without the cursor.

The access summary is complete and unpaginated on every page. The reference
`limit` does not bound the whole response. Action and resource-type filters can
reduce its size, but even a single action is not guaranteed to fit. MCP and CLI
transport size limits fail closed rather than return partial access.
See [caller discovery](resources.md#caller-discovery) for oversized-response alternatives.

### `actions`

`actions list --service SERVICE [--resource LOCATOR [--resource-type TYPE]] [--prefix PREFIX] [--verbose]`
returns sorted canonical action-name strings (`--resource-type` is needed with
`--resource` only when the service authorizes several resource types):

```json
{"service":"jira","resource":"ENG","actions":["issue.view","search"]}
```

Without `--resource`, the result omits `resource` and lists service-wide visible
actions. With it, the broker checks single-target policy using a Jira project
key, Confluence space key, or canonical repository path. A registered entry is
not required: broad grants can cover a known locator. A well-formed locator
with no policy access returns `"actions":[]`. This does not prove upstream
existence or authorization of a multi-target request. Local credentials are
checked during discovery and again during invocation.
Execution still authorizes every resolved target together.

`--verbose` returns an unwrapped array of raw action definitions selected by the
same filters. It fetches selected names first, then service details, and only
keeps their intersection. A second-fetch failure fails the command.

`actions describe --service SERVICE ACTION` returns one full action definition
with `service` added. For invoke actions, a fresh caller-visible runtime catalog
supplies IO, presentation, and sensitive-field metadata. Actions with an available
aggregate MCP name also include `mcpTool` containing the exact name and argument
schema. The top-level `inputSchema` describes
raw broker inputs; `mcpTool.inputSchema` describes the local MCP wrapper.
Non-invoke actions return raw service action metadata without `mcpTool`.
Invoke actions with an unavailable aggregate name omit `mcpTool` and include
`mcpToolUnavailable`: `name_conflict`, `name_too_long`, or `reserved_name`.
This concerns MCP naming, not CLI invocation eligibility. See
[MCP discovery](mcp.md#discovery-and-permissions).

Service discovery supports all its existing token classes and surfaces; native
MCP tools and augmented invoke-action details require caller catalog visibility.
Invoke-action detail also requires an authenticated identity: the runtime catalog
rejects anonymous callers with HTTP 401 (CLI exit 6), even when service discovery
allows anonymous access. Anonymous callers should use `services describe` for
the raw definition; non-invoke action details retain service visibility.
When an action appears in the service document but lacks catalog detail, the
command reports unavailable caller-visible catalog detail and recommends
`services describe` or retry. It does not silently return a partial definition.
Conflicting definitions between reads also require retry; HTTP failures retain
the normal broker error mapping.

All list prefixes are literal, case-sensitive, and applied before resource
pagination. They match service IDs, action names, or resource values respectively.
Compact service/action lists are objects, including empty results; explicit
verbose lists are arrays.

Syntax errors exit `2`; local argument and absent/unavailable action-detail
errors exit `3`. Missing and hidden actions in the returned service document
both report `action is not visible or does not exist`. Broker errors retain
HTTP-derived exit codes (400 → 3, 401 → 6, 403 → 2). Hidden and missing services
both receive 403 `service_action_denied`; invalid query semantics on a visible
service receive 400 `input_invalid`. Malformed broker responses fail rather
than becoming empty success.

### `spec`

Fetches authenticated, caller-filtered runtime specs from the broker:

- `spec catalog [--auth include|omit] [--visibility caller|all] [--output-format json] [--output PATH]`
  — `GET /v1/spec/catalog`.
- `spec openapi [--auth include|omit] [--visibility caller|all] [--output-format json] [--output PATH]`
  — `GET /v1/spec/openapi.json`.
- `spec send-schema [--auth include|omit] [--visibility caller|all] [--output-format json] [--output PATH]`
  — `GET /v1/spec/send-schema.json`.
- `spec send-schema --offline` — prints only the compiled generic `send`
  envelope schema. Offline mode is not a dispatch authority and cannot include
  configured provider policy, service allowlists, or
  management availability.

`--output` always means a destination. Use `--output-format json` to select
the spec result representation.

Spec endpoints require normal broker authentication when `auth=omit` is
used; that flag only controls whether rendered docs include auth descriptions.
`visibility=all` permits admins and auditors with administrative read access and
is intended for operator tooling. Normal callers
see only provider actions and HTTP routes visible to their token class, policy,
service/action caveat, resolved execution context, and management rights.
Finite resource caveats do not rewrite input schemas. Caller catalog JSON
includes the resolved
`executionContext`; administrative `visibility=all` omits it because that view is
context-independent configuration inventory. Re-run discovery through the same
trusted-ingress base URL that will execute the action.

Use the spec that matches the access surface under automation:

- Typed CLI wrappers are documented in this CLI guide and map to canonical
  catalog actions.
- Generic CLI `invoke` should consult `spec catalog` for canonical
  `service.action` names and input schemas.
- JSON request-file automation with `agent-access send` should consult
  `spec send-schema`.
- Direct HTTP clients should consult `spec openapi`.

These runtime specs are hot broker contracts. Config reloads, provider
enablement, token class, policy grants, service allowlists, token action boundaries, and management rights can change what a
caller sees without changing the installed CLI binary.

### `invoke` (generic)

- `invoke <service.action> [--input-json <JSON> | --input-file <PATH> | --input-stdin]
  [--read-content-format native|markdown|text] [--output-format json|markdown] [--output PATH]`
  — `POST /v1/invoke/{service}/{action}`. The positional argument is split at
  the first `.` into service and action. Omitted input defaults to `{}`.
  The compact input is the provider action input object; the CLI
  wraps it as the broker `InvokeRequest`. The response flags are common
  top-level fields, not members of the provider input object. When an output
  destination is explicit or either effective format is non-default, generic invoke first fetches the
  caller-filtered catalog. An explicitly requested option fails locally with
  exit 3 if the action is absent or does not advertise it. An ambient config or
  environment default is instead omitted in either case, and invoke proceeds
  with protocol defaults. If required discovery itself fails, no invoke request
  is made.
  With `native` plus `json` and no explicit output destination it retains the
  current single-request path.

### `send` (JSON envelope)

- `send (--request-json <JSON> | --request-file <PATH> | --request-stdin)` —
  executes an agent-first JSON envelope through the CLI. Before dispatch, the
  CLI fetches `GET /v1/spec/catalog` using the same URL, token, TLS, and
  request-id behavior as other broker calls. If the runtime catalog cannot be
  fetched, has an unsupported version, or does not expose the requested
  action/route, `send` fails closed.

Provider invoke envelope:

```json
{
  "version": "agent-access.send.v1",
  "kind": "invoke",
  "service": "jira",
  "action": "issue.create",
  "inputs": {
    "project": "PROJ",
    "issueTypeId": "10001",
    "summary": "Document deployment rollout"
  }
}
```

Invoke-kind request files may add top-level `readContentFormat` or
`responseFormat` when the selected action advertises them. `send` never injects
the CLI config or environment defaults and never overwrites an explicit value.
`responseMode` remains `json`; formatted Markdown remains under
`result = { "format": "markdown", "value": "..." }` in the Broker envelope.

HTTP route envelope:

```json
{
  "version": "agent-access.send.v1",
  "kind": "http",
  "method": "GET",
  "route": "/v1/admin/policy/grants",
  "query": {
    "service": "jira",
    "subject": "user:alice"
  }
}
```

The `route` field must match a route template from the fetched catalog. The CLI
percent-encodes `pathParams`, encodes declared scalar/array query parameters,
rejects unknown path/query keys, rejects `body: null`, and never accepts
arbitrary external URLs.

Routes marked `requestBodyKind: "raw_json"` require exact document bytes and are
excluded from the generated `send` schema. Generic `send` rejects those routes.
For imported documents, use `admin imports upload-document` with `--document-file`
so whitespace and duplicate JSON members reach the Broker unchanged.

Upload sources must be regular files; directories, named pipes, and devices are
rejected before hashing or opening a transfer. A symlink to a regular file is
accepted. Keep the source unchanged until the upload completes; an integrity
mismatch is rejected rather than silently uploading changed bytes.

Known multipart actions use `files` descriptors and catalog upload metadata to
build the broker's existing multipart invoke request. Known raw download actions
require `"responseMode": "stream"` and an explicit `output` sink. JSON and
multipart-upload actions also accept `output` while retaining
`"responseMode": "json"`:

```json
{
  "version": "agent-access.send.v1",
  "kind": "invoke",
  "service": "jira",
  "action": "issue.view",
  "inputs": { "issue": "PROJ-123" },
  "output": { "type": "file", "path": "./issue.json" },
  "metadataOutput": { "type": "stderr" }
}
```

A file destination returns the receipt described above to stdout, or to
`metadataOutput` when selected; raw downloads also retain broker metadata. `"output":{"type":"stdout"}` writes only the normal payload,
unless `metadataOutput` selects stderr or a separate file. `metadataOutput`
requires `output`; two file destinations must be different. These settings also
apply to mutations and multipart-upload responses.
HTTP-kind `send` requests do not support them. A file sink rejects the bare path
`-`: use `{"type":"stdout"}` for stdout or `./-` for a file literally named `-`.
`send --output PATH` supplies the
invoke envelope's destination only when the envelope has no `output`; specifying
both is an error.

Sensitive fields advertised by the runtime catalog must use local
`secretSources` instead of inline values when the envelope is passed with
`--request-json`, so secrets do not appear in process arguments. Supported local
secret sources are `env`, `file`, and `stdin`; only one stdin secret source is
allowed, and it cannot be combined with `--request-stdin`. Runtime
`send-schema` variants include `secretSources` for invoke actions only when the
catalog declares sensitive input pointers for that action.

Content attribution, when enabled, is broker-side config. The CLI and generic
invoke payloads do not include attribution flags or footer fields; agents should
submit only the content they intend to write.

### `credentials` (self-service)

Operates on the calling principal's own tokens for its credential connections:
the per-principal credential slots that one or more services consume, such as
one `gitlab` connection for GitLab REST and the GitLab Git gateway (see
[credential connections](configuration.md#credential-connections)). All
`credentials` subcommands reject `--token-value` (see "Commands that reject
literal or alternate token sources").

- `credentials list` — `GET /v1/credentials`: your connections, each with its
  method (`token`, `oauth` or `unavailable`), the services using it that you are
  entitled to, and any stored token, plus the retained stored credentials the
  configuration no longer selects.
- `credentials targets` — `GET /v1/credentials/targets`: the connections whose
  token you can store now, each with the token profiles (token types) it
  accepts from you in `tokenProfiles`, their labels and input forms.
- `credentials inspect <connection>` — `GET /v1/credentials/connections/{connection}`.
- `credentials put <connection> [--profile <PROFILE>] [field flags] [--verify] [--verify-service <SERVICE>] [--verify-repository <REPO>]`
  — fetches the broker-owned input schema of the chosen profile first
  (`GET /v1/credentials/connections/{connection}/input-schema`, with
  `?profile=...` when `--profile` is set), builds the secret body from the field
  sources, then `PUT /v1/credentials/connections/{connection}` with that
  `profile`. `--profile` chooses the token profile to store, one of the
  connection's `tokenProfiles` in `credentials targets`; it is required when the
  connection accepts several, and may be omitted when it accepts one. The
  broker refuses a profile the connection does not accept from you. With
  `--verify`, it follows up with
  `POST /v1/credentials/connections/{connection}/verify`.
- `credentials delete <connection>` — `DELETE /v1/credentials/connections/{connection}`.
- `credentials verify <connection> [--service <SERVICE>] [--repository <REPO>]` —
  `POST /v1/credentials/connections/{connection}/verify`, probing as you through
  a service using the connection that you hold a `per_user` grant on. Without
  `--service`, the broker picks the first such service with an identity probe,
  or checks the token locally. `--repository <namespace/repository>` selects a
  Git gateway service, for example
  `credentials verify gitlab --service gitlab_git --repository team/project`.
- `credentials delete-retained <credential-id>` —
  `DELETE /v1/credentials/retained/{credentialId}`, for a retained row that
  `credentials list` shows. A connection's active token is deleted with
  `credentials delete <connection>` instead.

OAuth connections are connected and disconnected only in the portal, with a
signed-in browser session; `credentials list` shows their method as `oauth`,
their `registration`, and its `remoteRevocation`: `revoked`, `pending`, `failed`
or `unconfirmed` once the Broker ended a family it revokes at the provider
(GitLab), otherwise `not_requested`. `failed` and `unconfirmed` mean you should
revoke the Broker application at the provider, in the account the ended
connection used; such a connection stays listed while its revocation is
`pending`, `failed` or `unconfirmed`, even after you lost its grants. See
[remote revocation](oauth.md#remote-revocation).

There is no `agent-access git ...` command. Git fetch and push use the
normal `git` executable against the broker gateway listener; the CLI only manages
the broker tokens and managed upstream credentials those Git requests use.

### `tokens` (self-service)

Manages the calling principal's own `agent_invoke` tokens. All `tokens`
subcommands reject `--token-value`.

- `tokens list [--include-revoked] [--include-expired]` — `GET /v1/tokens`.
- `tokens issue --name <NAME> --execution-context <CONTEXT> [--execution-context <CONTEXT> ...] [--ttl <DUR> | --expires-at <TS> | --never] [--service <SVC> ...] [--action <SERVICE=ACTION> ...] [--resource-id <SERVICE=ID> ...] [--resource-group-id <SERVICE=ID> ...] [--restrict-resources <SERVICE> ...] [--service-restrictions-file <PATH>]`
  — `POST /v1/tokens`. There is no `--token-class` flag; self-service issuance is
  always `agent_invoke` server-side. Repeatable `--service` narrows the issued
  token's service allowlist. Repeatable `--action`, `--resource-id`, and
  `--resource-group-id` construct `serviceRestrictions`. Each referenced service
  must also appear in `--service`; a service with resource flags needs at least
  one action. `--restrict-resources SERVICE` expresses a present empty selection
  unless IDs are added. Omitting resources follows grants; present empty means
  no resource access. Group membership remains live. Alternatively, use
  `--service-restrictions-file` with the canonical service map; do not combine
  it with action/reference flags. Provider policy is evaluated on every request.
  `--ttl` must match a configured
  `self_agent_invoke_ttl_options` duration. `--expires-at` is the advanced
  future-RFC3339 form and remains bounded by
  `max_self_issued_agent_invoke_ttl`; it need not match a listed duration. The
  broker accepts `--never` only when the self-service option list contains
  `never`. Supply the required repeatable `--execution-context` at least once;
  every value must be an effective choice from `GET /v1/tokens/options`.
  Omitting `--service`, `--action`, and resource flags creates a simple token
  that follows current policy within the selected contexts. Supplying them is
  the advanced form and creates an immutable service/action/resource ceiling.
- `tokens inspect <token_id>` — `GET /v1/tokens/{token_id}`.
- `tokens pause <token_id>` — `POST /v1/tokens/{token_id}/pause`.
- `tokens resume <token_id>` — `POST /v1/tokens/{token_id}/resume`.
- `tokens revoke <token_id>` — `DELETE /v1/tokens/{token_id}`.

Pause and resume apply only to an owned `agent_invoke` token and preserve its
secret, caveats, expiry, and dynamic policy lookup. Paused tokens remain in the
default list. Revocation is permanent and remains the correct response to a
possibly disclosed token.

### `audit` (self-service)

Queries the calling principal's own audit records: every record whose
`principal` is the caller, including records made with their agent tokens. It
takes the same callers as `tokens` (`user_manage` tokens of active managed
principals); agent-invoke and admin-class tokens get
`broker_token_class_denied`. All `audit` subcommands reject `--token-value`.
The routes need `audit.type = "sqlite"`; otherwise they return 404
`audit_query_unavailable` (exit `3`). See "Audit queries" in
[http-api.md](http-api.md) for filter semantics, visibility, and limits.

- `audit events list [--from <RFC3339> | --since <DURATION>] [--to <RFC3339>] [--service <NAME>] [--scope-service <NAME>] [--action <NAME|PREFIX.*>] [--decision allow|deny|error] [--reason-code <CODE>] [--phase <PHASE>] [--token-id <ID>] [--grant-id <ID>] [--node <ID>] [--request-id <ID>] [--query <TEXT>] [--limit <N>] [--cursor <CURSOR>]`
  — `GET /v1/audit/events`. Prints one page of records, newest first, in the
  management envelope: `result.items` and `result.nextCursor` (`null` on the
  last page). The CLI never follows cursors itself. There is no `--principal`
  option here (Clap rejects it, exit `2`).
- `audit requests inspect <broker-request-id>` —
  `GET /v1/audit/requests/{brokerRequestId}`. Prints the request's visible
  records, oldest first (at most 100), as
  `result = {"brokerRequestId": ..., "items": [...]}`. The CLI percent-encodes
  the ID into the path and leaves validation to the broker: a value that is not
  a UUID returns 400 `input_invalid`, and a request with no visible records
  returns 404 `audit_request_not_found` (both exit `3`).

Audit filter suggestions are also available through the generic JSON `send`
route operations `audit.options` and `admin.audit.options`. They return canonical
broker action names for the caller's visibility tier without reading audit
history; see [HTTP audit options](http-api.md#audit-queries) for the result.
`--service broker` selects internal activity, while `--scope-service jira`
selects Jira calls and broker administration concerning Jira. Combine both
filters to select only that broker administration.

List options (shared with `admin audit events list`):

- Each filter is sent as the camelCase query parameter of the same name
  (`--scope-service` as `scopeService`, `--request-id` as `requestId`), except
  `--query`, which is sent as `q`. `--action` matches exactly or, ending in
  `.*`, by prefix (`admin.policy.*`); `--request-id` matches a record's
  `brokerRequestId` or `agentRequestId`; `--query` is full-text search.
- `--from` and `--to` take RFC 3339 instants and are converted to UTC (`Z`)
  before sending, so an offset such as `+02:00` never reaches the query string.
- `--since <DURATION>` takes the broker duration syntax (`30s`, `15m`, `24h`,
  `7d`) and sends `from = now - duration` as a UTC instant, to the second. It
  cannot be combined with `--from`.
- Malformed instants and durations, `--since` with `--from`, and `--decision`
  or `--phase` values outside their lists are rejected by Clap argument
  parsing (exit `2`). The broker validates everything else, including
  `--limit` (1 to 200, default 50) and `--query` (at most 256 characters and
  16 terms), and returns 400 `input_invalid` (exit `3`).
- `--cursor <nextCursor>` fetches the next page and may be combined only with
  `--limit`. The cursor already holds the first request's filters, with
  `--since` resolved to an absolute instant, so every page covers the same
  window. The CLI rejects any filter option alongside `--cursor` before
  sending the request (exit `2`). A cursor the broker no longer accepts, for
  example after a reload changed `audit.path`, returns 400 `input_invalid`
  with `cursor is invalid or stale; repeat the request without cursor`: rerun
  the first command.
- Too many concurrent audit queries return 429 `concurrency_limited` (exit
  `7`); a query that exceeds its time budget returns 503 `audit_query_timeout`
  (exit `5`): narrow the filters.

```sh
agent-access audit events list --since 7d --service jira
agent-access audit events list --cursor <nextCursor> --limit 100
agent-access audit requests inspect 0199a0c4-5d3e-7a41-9c2b-8f1e2d3c4b5a
```

### `admin`

See [Account roles and self-service](roles.md) for role and credential-class boundaries.

Managed human identity has three command groups:

| Command | Arguments |
| --- | --- |
| `admin principals identity-access inspect` | `PRINCIPAL` |
| `admin principals identity-access pause` / `resume` | `PRINCIPAL --expected-version N` |
| `admin principals identity-bindings list` | `PRINCIPAL` |
| `admin principals identity-bindings create` | `PRINCIPAL --namespace NAME --username NAME [--read-only]` |
| `admin principals identity-bindings update` | `PRINCIPAL BINDING_ID [--enabled BOOL] [--read-only BOOL] --expected-version N` |
| `admin principals identity-bindings delete` | `PRINCIPAL BINDING_ID --expected-version N` |
| `admin principals identity-token inspect` / `reveal` / `generate` / `remove` | `PRINCIPAL` |
| `admin principals identity-token set` | `PRINCIPAL` and exactly one of `--identity-token-file PATH` or `--identity-token-stdin` |
| `admin principals identity-token update` | `PRINCIPAL [--enabled BOOL] [--read-only BOOL] --expected-revision N` |

Identity-access pause gates trusted username and fingerprint invocation together;
it does not pause issued Broker tokens or browser login. Bindings are exact
namespace/name mappings to humans. Each binding and the identity token has its
own Enabled and Read-only settings; the two `update` commands require at least
one of `--enabled` and `--read-only`, each taking `true` or `false`, while
`identity-bindings create --read-only` is a flag without a value. A read-only
path can use only actions classified as reads. Read the current version or
revision before a mutation; a conflict requires refreshing state. Disabling a
binding reserves its name; renaming or moving it requires delete/create.
Disabling the identity token keeps its secret. Inventory changes preserve
bindings, the shared pause and the identity token's settings. Import bytes are
exact, so files must not end with a newline; only `reveal` returns the stored
secret. All commands use an administration credential. Inspect/list permit
auditors; reveal and changes require the administrator role. See
[managed identity](managed-identity.md) for lifecycle and
[access path controls](managed-identity.md#access-path-controls).


Administrative management of principals, rights, tokens, credentials, and
policy, plus audit queries. Metadata reads also permit auditors; changes require global admin authority;
assigned service policy managers can use only the scoped policy and audit
commands described below. All `admin` subcommands reject `--token-value`.

- `admin store status` — `GET /v1/admin/store/status`.
- `admin config status | reload` — `GET /v1/admin/config/status` or
  `POST /v1/admin/config/reload`.
- `admin principals list | inspect <principal> | create <principal> [--kind <KIND>] [--display-name ...] [--email ...] [--external-subject ...] [--role ...] [--self-service-enabled true|false] | update <principal> [--display-name ... | --clear-display-name] [--email ... | --clear-email] | enable <principal> | disable <principal> | access set <principal> [--role user|auditor|service_policy_manager|admin] [--self-service-enabled true|false] | groups add <principal> <group> | groups delete <principal> <group> | login-methods list <principal> | login-methods oidc link <principal> --user-object-id <UUID> | login-methods oidc unlink <principal>`.
  `create --kind` defaults to `user`. `update` sends only fields selected by
  flags and requires at least one field flag. Microsoft link takes the Entra
  user Object ID, not an email, UPN, tenant ID, or encoded subject. Link returns
  the structured Microsoft login method; unlink revokes its browser sessions
  and external membership but leaves local identity state and independently
  issued broker tokens intact.
- `admin groups list | inspect <group> | create <group> [--display-name ...] [--description ...] [--auto-enroll-new-microsoft-users] | update <group> [--display-name ... | --clear-display-name] [--description ... | --clear-description] [--auto-enroll-new-microsoft-users true|false] | enable <group> | disable <group> | members list <group> | members add <group> <principal> | members delete <group> <principal> | external-group-bindings list <group> | external-group-bindings create <group> --external-group-id <UUID> | external-group-bindings enable <group> <binding-id> | external-group-bindings disable <group> <binding-id> | external-group-bindings delete <group> <binding-id>`.
  List, inspect, and member-list work in both TOML and managed identity
  authority modes. Mutating group commands require managed identity authority;
  TOML groups are static config resources changed by editing TOML and
  reloading. Existing `admin principals groups add|delete <principal> <group>`
  remains as the principal-owned membership form for the same managed-store
  membership operation. External-group binding commands configure Microsoft
  group Object IDs against existing managed broker groups. A binding must be
  disabled before deletion.
  `create --auto-enroll-new-microsoft-users` enables automatic local membership
  for new Microsoft JIT accounts; it defaults to off. On `update`, supply an
  explicit `true` or `false`; omitting the option preserves the setting. Only
  active groups enroll new accounts, after existing mapped-group admission.
  Disabling a group pauses enrollment without clearing the setting. Existing
  accounts are never backfilled or re-added on sign-in, and clearing the setting
  leaves their local memberships intact. See
  [Microsoft onboarding](administrator-guide.md#microsoft-onboarding).

Microsoft user Object IDs, group Object IDs, and binding IDs are parsed as UUIDs
by the CLI before any request is sent and are serialized as canonical lowercase
UUID strings. Invalid values are rejected by Clap argument parsing (exit 2).
The server still performs its own validation and conflict checks.

The two local-membership delete forms print the management result containing
both `removed` and `effectiveMembershipRemains`. The latter can be true after a
successful local removal when current Microsoft evidence independently supplies
the same effective group.
- `admin principals password reset <principal> [--password-env <NAME> | --password-file <PATH> | --password-stdin] [--no-must-change-password]`.
  Resets only an existing active local password; absent or disabled methods return
  `local_password_not_enabled` (409) and remain unchanged.
- `admin principals password enable <principal> --acknowledge-separate-sign-in [--password-env <NAME> | --password-file <PATH> | --password-stdin] [--no-must-change-password]`.
  Enables an absent or disabled local method with a fresh password; an active
  method returns `local_password_already_enabled` (409). The required flag
  acknowledges a separate Broker sign-in path that does not use Microsoft
  authentication policies. It does not enable a disabled principal.
- `admin principals password disable <principal> | unlock <principal>`.
  Disable removes local sign-in access; unlock only clears source lockouts.

  `password reset` and `password enable` prompt interactively with confirmation when no password source
  flag is supplied. By default the password is treated as temporary; the user's
  browser session must complete `/v1/auth/local/password/change` before
  credential/token self-service. Use `--no-must-change-password` only when the
  admin intentionally sets an immediately usable password.
  The CLI intentionally has no literal `--password` flag so passwords do not
  appear in shell history or process listings.
- `admin principals service-limits list <principal> | set <principal> <service> --requests <N> --window <DURATION> | clear <principal> <service>`
  — `GET /v1/admin/principals/{principal}/service-limits` and `PUT`/`DELETE`
  `/v1/admin/principals/{principal}/service-limits/{service}`. `list` prints
  the effective invocation limit for every configured service with
  `overridden`; `set` stores the principal's override and prints the new
  effective item; `clear` removes it and prints the service limit or default
  that now applies. `--window` uses the broker duration syntax (`30s`, `1m`,
  `2h`, `1d`) and is sent as `windowSeconds`; a malformed duration is rejected
  by Clap argument parsing (exit 2). The broker validates `--requests` (1 to
  1,000,000) and the window (1s to 1d). These commands require managed
  identity authority; TOML deployments configure
  `[[limits.invocations.principal_overrides]]`. Changes apply to the
  principal's next counted request and reforecast pending waiters without
  extending deadlines. These overrides select requests/window only; service or
  default `max_wait` still applies independently.

  ```sh
  agent-access admin principals service-limits list alice
  agent-access admin principals service-limits set alice jira --requests 10 --window 1m
  agent-access admin principals service-limits clear alice jira
  ```
- `admin audit events list [--from <RFC3339> | --since <DURATION>] [--to <RFC3339>] [--principal <ID>] [--service <NAME>] [--scope-service <NAME>] [--action <NAME|PREFIX.*>] [--decision allow|deny|error] [--reason-code <CODE>] [--phase <PHASE>] [--token-id <ID>] [--grant-id <ID>] [--node <ID>] [--request-id <ID>] [--query <TEXT>] [--limit <N>] [--cursor <CURSOR>] | requests inspect <broker-request-id>`
  — `GET /v1/admin/audit/events` and
  `GET /v1/admin/audit/requests/{brokerRequestId}`. Admins and auditors see every record;
  assigned service policy managers see records whose scope service is one of
  the services they manage now. `--principal` filters by exact principal ID
  and, like every other filter, cannot accompany `--cursor`. Options, output,
  paging, and errors otherwise match `audit events list` and
  `audit requests inspect` (see the `audit` section above). Each invocation
  fetches one page; pass the previous page's `result.nextCursor` to continue:

  ```sh
  agent-access admin audit events list --since 24h --decision deny
  agent-access admin audit events list --cursor <nextCursor>
  ```
- `admin rights list | grant <principal> --right <RIGHT> [--service ...] [--credential-name ...] [--expires-at ...] [--reason ...] | revoke <right_id>`.
  A credential right names a credential connection: `--service` is the
  connection ID and `--credential-name` is `default`.
- `admin tokens list | issue <principal> --name <NAME> [--token-class <CLASS>] [--execution-context <CONTEXT> ...] [--service <SVC> ...] [--action <SERVICE=ACTION> ...] [--resource-id <SERVICE=ID> ...] [--resource-group-id <SERVICE=ID> ...] [--restrict-resources <SERVICE> ...] [--service-restrictions-file <PATH>] [--ttl ... | --expires-at ... | --never] | pause <token_id> | resume <token_id> | revoke <token_id>`.
  Unlike self-service `tokens issue`, `admin tokens issue` accepts `--token-class`
  (default `agent_invoke`). The broker validates expiry input on the shared
  admin issue route: pass at most one of `--ttl`, `--expires-at`, or `--never`.
  `--ttl` must match the configured option list for the selected class;
  `--expires-at` accepts a future RFC3339 timestamp without requiring a listed
  duration. `--never` is valid only with `--token-class agent_invoke` and only
  when `admin_agent_invoke_ttl_options` contains `never`. `user_manage` and
  `admin` option lists prohibit it. Omitting expiry requires the selected
  class's configured default. Issuing `--token-class admin` also requires the
  target principal to be an active human with DB role `admin` or `auditor`.
  The token follows the principal's current role: an auditor can read permitted
  administration metadata but cannot gain administrator write capabilities.
  `agent_invoke` issuance requires one or more repeatable
  `--execution-context` flags selected from
  `GET /v1/admin/principals/{principal}/agent-token-options`; repeatable
  `--service` is optional. The four typed restriction flags use the same rules
  as self-service issuance and are nested under `scopes.serviceRestrictions`
  on the generic admin route. All six agent caveat flag families are rejected
  for `user_manage` and `admin` tokens. For a canonical shape not expressible
  by these flags, use direct HTTP or the runtime `send` surface; there is no
  token-boundary JSON file flag.
  Pause and resume likewise accept only `agent_invoke`; authentication,
  management, and browser-session backing tokens cannot be paused.
- `admin credentials list <principal> | list-stored [--principal <PRINCIPAL>] | targets <principal> | inspect <principal> <connection> | put <principal> <connection> [--profile <PROFILE>] [field flags] [--verify] [--verify-service <SERVICE>] [--verify-repository <REPO>] | delete <principal> <connection> | verify <principal> <connection> [--service <SERVICE>] [--repository <REPO>] | inspect-by-id <credential-id> | delete-by-id <credential-id> | rewrap --from-key <ID> --to-key <ID>`.
  `admin credentials put` mirrors the self-service `credentials put` field-source
  set, `--profile` choice and `--verify` follow-up, with a leading `<principal>`
  positional; the principal's kind decides which profiles it accepts, and
  `targets <principal>` lists them. It uses
  the `/v1/admin/principals/{principal}/credentials/connections/{connection}`
  routes. These apply only when the connection selects a token for the
  principal, such as a service account's administrator-provisioned token.
  Verification probes as the principal, so an administrator needs no invocation
  grants of its own. `list <principal>` uses
  `GET /v1/admin/principals/{principal}/credentials`, the principal's
  connections and retained rows in the shape of its own `credentials list`,
  including each OAuth connection's `remoteRevocation`, which shows whether
  disabling the principal revoked its GitLab tokens; an
  active token whose owner lost every grant stays listed with no entitled
  consumers. `list-stored` uses `GET /v1/admin/credentials`, every stored row,
  active and retained, with its stored `service` and `name`; `inspect-by-id`
  and `delete-by-id` use `/v1/admin/credentials/{credential_id}` for cleanup of
  any row.
- `admin policy status | catalog | grants list [--subject ...] [--service ...] [--execution-context ...] [--status ...] | grants inspect <grant_ref> | grants create [--grant-id <ID>] --subject <SUBJECT> [--subject <SUBJECT> ...] --service <SERVICE> --action <ACTION> ... --execution-context <CONTEXT> [--execution-context <CONTEXT> ...] --credential-mode <MODE> [--resource-id <ID> ...] [--resource-group-id <ID> ...] [--resources-json <JSON> | --resources-file <PATH>] | grants update <grant_ref> --expected-version <N> [field flags] | grants validate [--grant-id <ID>] [--expected-version <N>] [field flags] | grants subjects add <grant_ref> --subject <SUBJECT> --expected-version <N> | grants subjects remove <grant_ref> --subject <SUBJECT> --expected-version <N> [--last-subject-behavior reject|disable_grant] | grants enable|disable|delete <grant_ref> --expected-version <N> | grants export`.
  Policy grant create requires one or more repeatable `--subject` flags. Update
  and validate accept repeated `--subject` flags as a full replacement list when
  present; the CLI sends the plural HTTP `subjects` field.
  Create also requires one or more repeatable `--execution-context` flags.
  Update and validate use repeated flags as the full replacement
  `executionContexts` list when present. The catalog supplies configured choices;
  omission never means all contexts.
  `--grant-id` is optional on create and validate-create calls. If omitted, the
  broker generates a UUID. If supplied, it must be a durable safe slug: 1-128
  characters using letters, numbers, dots, underscores, or hyphens, excluding
  `.`, `..`, `export`, and `validate`.
  Repeat `--resource-id` / `--resource-group-id`, or supply `--resources-json`
  / `--resources-file` with `{ "resourceIds": [], "resourceGroupIds": [] }`.
  A grant with an explicit empty selection uses `--resources-json '{}'`;
  omitted update reference flags leave its selection unchanged. Grant resources
  must reference typed resource entries or resource groups.
  The CLI percent-encodes grant refs in paths, so refs such as `toml:0` can be
  passed directly.
- `admin policy resources list | types | get <id> | create | update <id> | delete <id> | used-by <id> | reveal <id> <attribute>`.
  Create/update accept `--attributes-file PATH`, a JSON object of private string
  attributes. Ordinary responses remain redacted; omission on update preserves
  values. Explicit admin `reveal` returns the secret in `result.value`. Keep this
  output private. The attributes file must be a regular file of at most 64 KiB.
  `types` prints the broker's registered resource types (`GET /v1/resource-types`)
  with labels, examples, and supported selector forms.
  Create accepts optional `--id`, `--resource-type TYPE` (a registered type ID),
  `--selector-kind exact|namespace|all`, `--selector-value` for exact/namespace,
  optional `--display-name`, and repeatable `--execution-context`. Update and
  delete require `--expected-version`. The broker validates the type and whether
  it supports the selector form; in this build namespace selectors apply only to
  Git repositories and CloudBees CI jobs. Disable an entry with update
  `--enabled false`; its exclusion references remain effective.
- `admin policy resource-groups list | get <id> | create | update <id> | delete <id> | used-by <id>`.
  Create accepts optional `--id`, `--name`, and repeatable
  `--included-resource-id` / `--excluded-resource-id`. Update/delete require
  `--expected-version`; update can use `--clear-included` or `--clear-excluded`
  to replace a membership list with an empty list. Groups do not nest.
- `admin policy effective-access --request-file <PATH>` previews a grant
  selection with `service`, `actions`, `executionContexts`, and `resources`.
- `tokens effective-access --request-file <PATH>` previews token caveats for
  the caller. `admin tokens effective-access <principal> --request-file <PATH>`
  previews the same caveats for an administered principal. Requests use the
  canonical token caveat fields; results retain policy generation and symbolic
  coverage with exclusions. See [resources.md](resources.md).
- `admin policy managers list [--service <SERVICE>] | grant --service <SERVICE> --principal <PRINCIPAL> | revoke --service <SERVICE> --principal <PRINCIPAL>`.
  Administrators can change assignments; auditors can list them. Grant is
  idempotent and accepts an active account with role `service_policy_manager`;
  revoke is idempotent. Repeat grant for each service an account manages. Assignments require managed identity and managed policy authority
  and target one exact configured service.

An assigned service policy manager uses the existing `admin policy status`,
`catalog`, and grant commands, and the `admin audit` commands, with an ordinary
`user_manage` token. Results are server-filtered to assigned configured
services; `grants export` and `policy managers list` require global administrative read access. The
manager retains normal self-service commands when `selfServiceEnabled` is true. The assignment does not grant
service invocation, and self-service agent-token issuance still requires an
effective invocation grant.

### `jira` (typed)

Each typed Jira command lowers to a generic `invoke` of the corresponding
`jira.<action>` (`POST /v1/invoke/jira/<action>`). There are no typed HTTP
routes; typed commands only build the invoke input for you.

The typed Jira family covers project listing and field discovery, issue view/create/update/search, parented child
creation, parent assignment, dependency links, issue comments and comment
properties, issue attachments, and verification helpers. Issue locators accept
issue keys and, where documented, tenant browser URLs. Provider-specific
actions, required inputs, typed examples, generic `invoke` payloads, JSON
`send` payloads, and lookup behavior are documented in
[providers-jira.md](providers-jira.md).

### `confluence` (typed)

Each typed Confluence command lowers to a generic `invoke` of the corresponding
`confluence.<action>` (`POST /v1/invoke/confluence/<action>`).

The typed Confluence family covers space listing, page and blog view/search/create/update,
drafts, footer and inline comments, attachments, and verification helpers.
Page and blog locators accept numeric IDs and, where documented, tenant browser
URLs. Provider-specific actions, body formats, draft handle rules, typed
examples, generic `invoke` payloads, JSON `send` payloads, and lookup behavior
are documented in [providers-confluence.md](providers-confluence.md).

### `gitlab` (typed)

Each typed GitLab command lowers to a generic `invoke` of the corresponding
`gitlab.<action>` (`POST /v1/invoke/gitlab/<action>`). These wrappers cover the
GitLab REST provider actions, not Git fetch/push gateway traffic.

The typed GitLab family covers project, issue, merge-request review context,
direct and draft review participation, discussion positions,
current/historical diff, branch, protected-branch,
repository-file, commit, pipeline, and job REST actions. Git
transport remains a separate Git HTTP gateway surface. Provider-specific
actions, locators, note/discussion terminology, typed examples, generic
`invoke` payloads, JSON `send` payloads, and lookup behavior are documented in
[providers-gitlab-rest.md](providers-gitlab-rest.md).

## Read and output formats

JSON is the default for provider commands. Jira comment-list,
comment-property-list, and attachment-list commands and Confluence current/draft
attachment-list commands print the standard JSON envelope by default.
Eligible retrievals use `--output-format markdown`.

Typed commands expose `--read-content-format native|markdown|text` exactly on
actions whose result can contain a declared rich body. Non-native modes preserve
the native field and add `renderedBody` beside its owning result entity. They
expose `--output-format json|markdown` only on eligible non-streaming retrievals.
Whole-result Markdown prints only `result.value` on an `allow` result; Jira or
Confluence verification mismatches returned as `allow_with_result` also print
the Markdown value and retain exit 2. Denials and errors remain JSON. Direct HTTP and `send`
always preserve the JSON envelope.

For Jira, embedded read formats are supported by `issue view`, `issue create`,
`issue update`, `issue comment view`, `issue comment add`, `issue comment reply`,
and `issue comment update`. Whole-result output is supported by `project list`, `project view`, `issue-type list`, `issue view`,
`issue search`, `issue comment list`, `issue comment view`, `issue comment
property list`, `issue comment property get`, `issue attachment list`, and
`issue verify`. Other Jira typed commands reject these flags during argument
parsing with exit 2. A malformed promised Markdown wrapper is a malformed Broker
response and exits 5.

For Confluence, embedded read formats are supported by current page/blog view,
page/blog draft view, every page/blog footer/inline comment list/view/reply-list
read, page/blog footer-comment add, every page/blog footer/inline comment
update, and every page/blog footer/inline reply add. Whole-result output is
supported by space list, current page/blog view/search/verify, page/blog draft view/verify,
current and draft attachment lists, and every page/blog footer/inline comment
list/view/reply-list read. Search and attachment output remains body-free;
comment and reply lists format only the bodies already returned.

Where a Confluence read command exposes `--body-format`, the only supported
value is `storage`; it selects that action's upstream native representation.
Current `page view` does not expose `--body-format`: its returned
`atlas_doc_format` representation, when present, is enabled by the Broker's
`[providers.confluence.content].page_formats` configuration rather than a
caller flag. `--read-content-format` preserves the native body and adds a
companion, while `--output-format` selects whole-result presentation. If a
current page result contains both representations, normalization selects
present ADF before storage and does not fall back when selected ADF is
malformed. `renderedBody` is beside the entity's `body`, never inside the
native representation map.

- `attachment download --output -`, `gitlab file raw --output -`, and
  `gitlab job trace --output -` stream the raw bytes to stdout (through an
  integrity-checked temp file), print no metadata on success, and never expose
  the presentation flags. Any other `--output` writes the file and prints the
  metadata JSON with an `output` file receipt.

## `credentials put` field model

`credentials put` and `admin credentials put` collect secret and non-secret
fields from explicit sources, validated against the chosen profile's
broker-owned input schema: a `basic_api_token` profile takes `username` and
`token`, a `bearer_token` profile `token`. Every field uses the `name=value`
form; there is no `--field-json` flag and no boolean/array shorthand.

Field sources:

- `--field name=value` — literal value (a value is required). Not allowed for
  secret fields.
- `--field-env name=ENV_VAR` — read the value from an environment variable.
- `--field-file name=PATH` — read the value from a file.
- `--field-stdin name` — read one field from stdin (only one stdin field source
  is allowed across the whole command).
- Convenience aliases: `--username`, `--username-env`, and
  `--username-file`, plus `--profile`, `--display-name`, `--expires-at`,
  `--verify`, `--verify-service`, and `--verify-repository`.

Rules:

- Secret fields cannot use the literal `--field`; they must come from
  env/file/stdin or an interactive prompt.
- Credential token secrets must use the generic schema-field forms, for
  example `--field-env token=JIRA_API_TOKEN`,
  `--field-file token=/secure/path`, or `--field-stdin token`.
- `--token-file` and `--token-env` are broker identity-token options only,
  including when they appear after `credentials put` or
  `admin credentials put`. They do not populate credential secret fields.
- A field provided more than once is an error.
- A field that is not in the profile schema errors with "not supported by profile".
- A missing required field is read interactively (hidden input for secret fields)
  only when both: stdin is a terminal, AND the field allows the prompt source.
- Otherwise a missing required field is an error.
- The CLI does not read stdin unless `--field-stdin` is passed.

All of the above are CLI-local input errors and exit `3`.

Imported connection schemas may declare `inputPolicy: "http_basic"`. For those
fields, literal and environment values are preserved exactly; file/stdin values
remove at most one terminal LF or CRLF and preserve all other spaces. Both
username and password/API token must be nonempty and contain no control
characters; usernames also reject colon and are limited to 256 UTF-8 bytes.
The secret remains the `token` field. Token-header and command-stdin profiles
retain their own input conventions; credential kind alone does not select Basic
validation.

## Rich-content write formats

- The six Jira rich-content mutations use exactly one of `--content STRING` or
  `--content-file PATH` plus the required `--content-format` value `adf`,
  `markdown`, or `plain_text`. The CLI parses `adf` as JSON and reads Markdown
  and plain text as literal UTF-8. It does not infer format from a filename,
  extension, environment variable, or client default. Inline content may be
  visible in shell history and process listings; prefer `--content-file` for
  long or sensitive values. `--content-file` reads are incrementally bounded
  by a 512 MiB CLI safety cap; provider and server limits may be lower and
  remain authoritative. Exceeding the CLI cap is a local input error (exit
  `3`), and `-` is treated as a literal path rather than stdin.
- `issue.create`, `issue.child.create`, and `issue.update` map content to the
  Jira description; `comment.add`, `comment.reply`, and `comment.update` map it
  to the Jira comment body. Description content is optional, while comment
  content is required. `--content` and `--content-file` are mutually exclusive,
  and `--content-format` cannot be supplied without a source.
- The twenty Confluence rich-content mutations use the same exactly-one source
  and explicit-format rules. Current page create/update accept
  `storage|atlas_doc_format|markdown|plain_text`; the other eighteen accept
  `storage|markdown|plain_text`. The CLI parses `atlas_doc_format` as JSON and
  treats storage, Markdown, and plain text as literal UTF-8. All twenty require
  content. File reads use the same 512 MiB CLI safety ceiling; the lower Broker
  and provider caps remain authoritative.
- Confluence read commands and read response bodies may use provider-native
  `bodyFormat`; that is distinct from write `contentFormat`.
- `--content-format` describes write input only. `--read-content-format`
  controls the shipped, action-scoped embedded read companion, while
  `--output-format markdown` controls the independent whole-result presentation.
- The sixteen GitLab issue/MR description, note, discussion, draft, and summary
  mutations use
  the same source rules with required explicit `--content-format
  markdown|plain_text`. Markdown is preserved as GitLab's native representation;
  plain text is escaped so Markdown punctuation, HTML, mentions, references,
  and autolinks stay literal. Issue/MR descriptions are optional; note and
  discussion content is required and non-whitespace.
  Command-like GitLab quick-action lines outside fenced code and suggestion
  blocks are rejected before a write to prevent hidden side effects or body
  stripping; fenced examples remain literal content. See the provider contract
  for the exact allow/reject grammar.
- No rich-content format is inferred from a filename, configuration,
  environment variable, or default for any provider. Inspect the exact
  caller-filtered action catalog's `contentFormat.enum` to detect support.

## Commands that reject literal or alternate token sources

The `credentials`, `tokens`, `audit`, and `admin` command groups call
`reject_literal_identity_token_for_management` before doing anything else. If
`--token-value` is set, the CLI exits `3` with:

```text
management commands do not accept --token-value; use --token-env, --token-file, config, or AGENT_ACCESS_TOKEN
```

The local `auth token` command group rejects `--token-value`, `--token-file`,
and `--token-env`; it manages the configured token file only. `auth
git-credential` instead uses normal effective token resolution, including
`--token-file` and `--token-env` global overrides, but rejects `--token-value`
so helper token material is not supplied in process arguments.

The `jira`, `confluence`, `invoke`, `services`, `actions`, and remote
`auth status` commands do not enforce this and accept `--token-value`.

## Config, env, and default precedence

For each setting the precedence is:

> CLI flag > config-file value (only when the config file exists) > environment variable > built-in default.

Config-key presence is determined from parsed TOML rather than raw text, so an
explicitly configured default still occupies the config tier.

| Setting | Flag | Config key | Env var | Default |
| --- | --- | --- | --- | --- |
| Broker URL | `--url` | `service.url` | `AGENT_ACCESS_URL` | `http://127.0.0.1:8787` |
| Identity header | `--identity-header` | `identity.header` | `AGENT_ACCESS_IDENTITY_HEADER` | `X-Agent-Access-Identity-Token` |
| Identity scheme | `--identity-scheme` | `identity.scheme` | `AGENT_ACCESS_IDENTITY_SCHEME` | `raw` |
| Token disabled | `--no-token` | `identity.disabled` | `AGENT_ACCESS_NO_TOKEN` (case-insensitive `true`) | not disabled |
| Insecure HTTP override | `--allow-insecure-broker-http` | (none) | `AGENT_ACCESS_ALLOW_INSECURE_BROKER_HTTP` (case-insensitive `true`) | off |
| HTTPS certificate verification | (none) | `service.tls.verify_certificates` | (none) | `true` |
| Additional HTTPS CA files | (none) | `service.tls.additional_ca_cert_files` | (none) | `[]` |
| Embedded read content | per-command `--read-content-format` | `defaults.read_content_format` | `AGENT_ACCESS_READ_CONTENT_FORMAT` | `native` |
| Complete result | per-command `--output-format` | `defaults.output_format` | `AGENT_ACCESS_OUTPUT_FORMAT` | `json` |

Format config and environment values are validated even when a command cannot
use them. A valid non-default ambient value is included only when that action
advertises the capability. When a non-default format is in effect, typed
commands and generic invoke both read the action's advertised formats from the
caller-filtered runtime catalog; at the defaults they send no catalog request.
An ambient value is omitted when the catalog omits the selected action; the
same condition for an explicit flag is a local input error. The CLI checks
returned `renderedBody` companions only at the action's catalog
`renderedBodyOwners`: each owner must be present and an object, and a companion
must carry the requested format and a string value. A catalog that advertises
`readContentFormats` without owners is a malformed Broker response and exits 5
before the request is sent.
An explicit `--output-format markdown` suppresses an ambient non-native
`read_content_format` because the two representations are mutually exclusive.

The token is disabled when `--no-token` is set, OR the config file exists and
`identity.disabled` is true, OR `AGENT_ACCESS_NO_TOKEN` equals `true`
(case-insensitive).

The insecure-HTTP override has no config key; it comes only from the flag or the
environment variable.

### Token resolution order

If the token is not disabled, the CLI resolves it from the first source present,
in this order:

1. `--token-value`
2. `--token-file`
3. `--token-env`
4. config `identity.token_file` (only when the config file exists)
5. config `identity.token_env` (only when the config file exists)
6. `AGENT_ACCESS_TOKEN`
7. `AGENT_ACCESS_TOKEN_FILE`
8. `AGENT_ACCESS_TOKEN_ENV`
9. none

Strict sources fail with a CLI input/config error when configured but unusable:
`--token-value` must be non-empty after trimming but is otherwise sent verbatim;
`--token-file`, `--token-env`, and `AGENT_ACCESS_TOKEN_FILE` must resolve to
non-empty token material. Token files are trimmed before use.

Identity token-file sources support current-user home expansion for a leading
`~` or `~/`, including `--token-file`, config `identity.token_file`, and
`AGENT_ACCESS_TOKEN_FILE`. `~user` is not expanded, and unrelated file arguments
such as request/body files remain literal.

Lenient fallback sources treat empty values as absent and continue resolving:
missing or empty config `identity.token_file`, config `identity.token_env`,
`AGENT_ACCESS_TOKEN`, and `AGENT_ACCESS_TOKEN_ENV` targets do not produce an
identity token. An unreadable configured `identity.token_file` is still an
error. If a configured `identity.token_file` requires `~` expansion but the
current user's home directory is unavailable, resolution fails with CLI-local
input exit code `3`. If no source yields a token, broker calls send no identity
header.

For a command that performs multiple broker requests, such as
`credentials put --verify`, the CLI resolves this effective config and identity
token once before command dispatch and reuses those settings for every request
in that process.

Use `agent-access auth token status` to distinguish a missing, empty, present,
or unreadable configured token file from the effective token source selected by
the normal precedence rules.

`agent-access auth git-credential get` uses this same resolver and precedence,
including token normalization, identity-disabled behavior, configuration
discovery, and the existing token-source handling. It does not maintain a
second Git credential file. Its one exception to the general precedence table
is that `--token-value` is rejected; use a file or environment source instead.

### Config file path

The config file path is resolved as:

1. `--config <PATH>` if given.
2. Otherwise `AGENT_ACCESS_CONFIG` if set.
3. Otherwise `$XDG_CONFIG_HOME/agent-access/config.toml` if `XDG_CONFIG_HOME` is set.
4. Otherwise `$HOME/.config/agent-access/config.toml` if `HOME` is set.
5. Otherwise `agent-access.toml` in the current directory.

For broker calls, an explicit `--config` path that does not exist is a hard
error (exit `3`), while a default path that does not exist falls back to
built-in defaults. `agent-access config validate` is different: it validates the
resolved file itself, so a missing explicit or default config file is a load
error and exits `3`. When HTTPS verification is enabled, `config validate` also
parses existing files listed in `service.tls.additional_ca_cert_files`; missing
entries are ignored. When `service.tls.verify_certificates = false`, validation
still rejects empty certificate-path entries but skips path expansion, file
existence checks, and PEM parsing.

## Exit codes

The CLI maps the broker's HTTP status to a process exit code via
`cli_exit_code_for_http_status`:

| HTTP status | Exit code |
| --- | --- |
| `200` | `0` |
| `400` | `3` |
| `401` | `6` |
| `403`, `409`, `413`, `415` | `2` |
| `424`, `502`, `504` | `4` |
| `429` | `7` |
| `503` | `5` |
| any other `>= 500` | `5` |
| any other `>= 400` | `3` |
| everything else | `1` |

HTTP 429 covers the Broker's own `rate_limited`, the upstream service's
`upstream_rate_limited`, and `concurrency_limited`. Exit `7` reports throttling;
inspect retry guidance and mutation outcomes before retrying. It is separate
from `5`, which reports 503 and network failures.

For `rate_limited` and `upstream_rate_limited`, the CLI also writes the Broker's
message to stderr as one line prefixed `rate limited: `, for example:

```text
rate limited: jira is rate limiting requests. Retry after 30s (at 2026-09-25T14:03:30Z).
```

The message names the service and the wait, or ends `Retry later.` when the
wait is unknown. The line collapses whitespace and control characters to single
spaces and strips Unicode format characters (general category Cf, such as
bidirectional overrides and isolates and zero-width characters). Stdout is
unchanged: commands that print the JSON envelope
still print it, including downloads and `--output` commands, which leave the
destination untouched. Broker admission limits use the reserved
`broker/request.admit` envelope without `result`; its correlated tuple proves
nonapplication. The error message reports the wait. Upstream failures may carry
`result.retryAfterSeconds` and `result.retryAt` when known. The CLI never
retries automatically; wait before running the command again, and do not retry
in a loop. Optional Broker waiting holds the original request open; do not
resubmit pending calls. Retry guidance accounts for this principal/service's
accepted FIFO queue. `concurrency_limited` prints no extra line and has no
`Retry-After`: waiting calls can occupy existing slots across services, so wait
for capacity without duplicating them.

In addition to HTTP-derived codes:

- Local response or metadata saving failures exit `1`. When an operation already
  ran, stderr contains a structured object with `operationStatus` and the failed
  output status. Exit `1` is also used for other local errors and does not, by
  itself, prove whether a request was sent. Check the structured outcome and
  request identifiers; neither `succeeded` nor `applied_unverified` permits
  repeating the operation simply to retry saving its response.
- Clap syntax and typed value-parser errors exit `2`, including unsupported Jira
  or Confluence `--content-format` values. CLI-local errors detected after
  argument parsing exit `3` (`exit_cli_input_error` / `require_cli_input`),
  including malformed native JSON, content-file read failures, schema
  mismatches, and a non-existent explicit `--config` path.
- Network errors, request timeouts, malformed broker responses, unexpected JSON
  shapes, and output-formatting failures exit `5` (`exit_network_error`,
  `exit_malformed_broker_response`, response-shape validation, and
  `print_value` formatting).

## Transport security

Broker HTTP redirects are rejected for ordinary requests, multipart uploads, and
streaming downloads, including redirects to the same origin. The CLI exits `5`
with the redirect status without printing the destination or sending the identity
token there. Configure the final broker URL directly.

For `https` broker URLs, the CLI uses reqwest/rustls default certificate-chain
and hostname verification unless `service.tls.verify_certificates = false` is
set in the CLI config. `service.tls.additional_ca_cert_files` may list
PEM-encoded CA certificates or self-signed broker certificates to add to the
default trust store; there is no custom-only trust mode. Each file may contain
one or more `CERTIFICATE` PEM blocks. Missing paths are ignored, but existing
directories, unreadable files, empty files, malformed certificates,
non-`CERTIFICATE` PEM blocks, or non-whitespace text outside PEM blocks are
CLI-local config errors. Paths are trimmed before use; empty or whitespace-only
entries are rejected in both verification modes.

Additional certificate paths support current-user `~` and `~/...` expansion.
`~user/...` is treated literally. Relative paths are resolved relative to the
current working directory. If `~` expansion is needed while certificate files
are loaded and the current user's home directory is unavailable, the CLI exits
with local input code `3`.

With `service.tls.verify_certificates = false`, the CLI disables both
certificate-chain and hostname verification for broker HTTPS requests. Any
configured `additional_ca_cert_files` are not expanded, read, or parsed in that
mode, but non-empty path syntax is still required.

`validate_transport` runs before every broker call. The insecure-transport gate
triggers only when **all** of the following hold:

- the URL scheme is `http`, AND
- the host is **not** one of `localhost`, `127.0.0.1`, or `::1`, AND
- a token is present.

When the gate triggers, there are three outcomes:

1. If `AGENT_ACCESS_ENVIRONMENT` equals `production`, the CLI errors with
   "insecure broker HTTP override is rejected in production" and exits `3`,
   regardless of the override flag/env.
2. Otherwise, if `allow_insecure_broker_http` is false, the CLI errors with
   "refusing to send identity material over non-local HTTP broker URL; use
   --allow-insecure-broker-http for development" and exits `3`.
3. Otherwise, the CLI prints a stderr warning and proceeds with the call.

With `--no-token` (no token present) the gate never trips, even against a remote
HTTP URL. An invalid broker URL exits `3`. Host matching is by hostname literal
only.

## Outbound request construction and timeouts

Set the client timeout to allow Broker rate waiting plus useful execution and
transfer time, within any proxy timeout. `services describe SERVICE` reports
configured `limits.invocations.maxWaitSeconds`; it is optional guidance, not a
required preflight. A shorter server operation/body deadline can still win.
Timeouts during invocation mean the Broker request may still be queued or
executing: detecting a closed connection can be delayed. Reconcile a mutation
through its response/audit or an authorized upstream read before resubmitting it.
The CLI never retries automatically.

A correlated HTTP 400 `body_malformed` result with `executionState:
"not_dispatched"`, `retrySafe: true` and `deadlineKind: "body"` proves the
initial admission deadline expired without dispatch. Queued expiry and infeasible
future FIFO turns still return 429. See [admission outcomes](http-api.md#rate-limits);
the status/reason alone proves nothing about application, and a later attempt
still needs current identity, configuration and authorization.

- Every request sets `X-Agent-Access-Request-Id` to a fresh UUID v4.
- If a token resolved, it is placed in the configured identity header as
  `Bearer <token>` when the scheme is exactly `Bearer`, otherwise as the raw
  token value.
- `[service].request_timeout_ms` sets the total JSON/upload HTTP timeout and
  defaults to `30000`. It must be positive and representable. It applies to CLI
  and local stdio MCP and has no flag or environment override.
- Streaming downloads use a client with no overall timeout; their send/header
  phase uses `request_timeout_ms`, while response-body reads retain the separate
  30-second idle timeout (a stalled stream aborts).
- The CLI validates the broker response JSON shape per the expected
  `ResponseShape`:
  - `Array` — a JSON array.
  - `Object` — a JSON object.
  - `Envelope` — an object containing `agentRequestId`, `brokerRequestId`, and
    `decision`.
  - `ManagementObject` — an object containing `requestId`, `brokerRequestId`, and
    `decision`.
  A shape mismatch exits `5`. For statuses `>= 400` the checks adjust to the
  error path: `Array` and `Envelope` require the `agentRequestId` envelope shape,
  `ManagementObject` requires the `requestId` envelope shape, and `Object` accepts
  an object matching either envelope shape.

## Recipes

These assume a broker reachable at `http://127.0.0.1:8787`.

### Validate the CLI config locally

```bash
agent-access --config agent-access.sample.toml config validate
```

### Discover services and actions

```bash
agent-access --url http://127.0.0.1:8787 --no-token services list
agent-access --url http://127.0.0.1:8787 --no-token services describe jira
```

### Generic invoke

```bash
agent-access --url http://127.0.0.1:8787 --no-token \
  invoke fake.echo --input-json '{"project":"TEST","message":"hello"}'

agent-access --url http://127.0.0.1:8787 --no-token \
  invoke fake.echo --input-file ./input.json
```

### Runtime specs and JSON send

```bash
agent-access --url http://127.0.0.1:8787 spec catalog
agent-access --url http://127.0.0.1:8787 spec openapi --auth omit
agent-access --url http://127.0.0.1:8787 spec send-schema
agent-access spec send-schema --offline
```

```bash
agent-access --url http://127.0.0.1:8787 \
  send --request-file ./agent-access-request.json
```

### Jira (typed)

Use `jira project list` for live projects allowed by the action’s effective
grants. Optional `--max-results` defaults to the configured limit (50; at most
100). Pass `--page-token` from `nextPageToken` with the same page size until
`scanStatus` is `exhausted`, including after empty `scan_budget` pages.
`--output-format markdown` renders the collection and its pagination state.
See [live project listing](providers-jira.md#live-project-listing).

Use `jira project view PROJ` to discover project details and searchable fields
before composing JQL. Use a field's stable `jqlReference`, such as `cf[12345]`,
with a returned operator; display names can be duplicated. Project view and
search require their own grants. For text fields, `~` is text matching rather
than strict whole-value equality. `--include fields,versions,components,issueTypes,statuses`
selects optional collections, and `--query external` narrows their names or IDs
before the 100-item cap. See [project details and searchable fields](providers-jira.md#project-details-and-searchable-fields).

```bash
agent-access jira project list
agent-access jira project view PROJ --output-format markdown
agent-access jira issue search --project PROJ --jql 'cf[12345] ~ "EXT-4812" AND fixVersion = "2.4"'
```

Use `jira issue-type list --project PROJ` before creation to discover names,
descriptions, decimal-string IDs, and subtask markers. Optional `--start-at`
and `--max-results` request one page (defaults `0` and `50`; maximum `100`).
Use `--output-format markdown` for a readable list. Follow `nextStartAt` until
`isLast` is true. The selected Jira execution credential needs Create issues
permission; broker grants still authorize reads and writes separately.
See [project issue types](providers-jira.md#project-issue-types).

```bash
agent-access --url http://127.0.0.1:8787 jira issue view PROJ-123
agent-access --url http://127.0.0.1:8787 jira issue view PROJ-123 --read-content-format markdown
agent-access --url http://127.0.0.1:8787 jira issue view PROJ-123 --output-format markdown
agent-access --url http://127.0.0.1:8787 jira issue view --issue-url https://example.atlassian.net/browse/PROJ-123
agent-access --url http://127.0.0.1:8787 jira issue create --project PROJ --issue-type-id 10001 --summary 'Document deployment rollout'
agent-access --url http://127.0.0.1:8787 jira issue create --project PROJ --issue-type-id 10001 --summary 'Document deployment rollout' --content-file description.md --content-format markdown
agent-access --url http://127.0.0.1:8787 jira issue update PROJ-123 --summary 'Clarify startup failure handling'
agent-access --url http://127.0.0.1:8787 jira issue child create --project PROJ --issue-type-id 10001 --summary 'Add rollout checklist' --parent PROJ-100 --content 'Follow the deployment checklist.' --content-format plain_text
agent-access --url http://127.0.0.1:8787 jira issue parent set PROJ-124 --parent PROJ-123
agent-access --url http://127.0.0.1:8787 jira issue dependency add --blocking PROJ-123 --blocked PROJ-124
agent-access --url http://127.0.0.1:8787 jira issue search --text 'deployment checklist' --max-results 10
agent-access --url http://127.0.0.1:8787 jira issue search --text 'deployment checklist' --max-results 10 --output-format markdown
agent-access --url http://127.0.0.1:8787 jira issue comment add --issue PROJ-123 --content-file comment.md --content-format markdown
agent-access --url http://127.0.0.1:8787 jira issue comment reply 10042 --issue PROJ-123 --content 'Acknowledged.' --content-format plain_text
agent-access --url http://127.0.0.1:8787 jira issue attach PROJ-123 ./design.md --content-type text/markdown
agent-access --url http://127.0.0.1:8787 jira issue verify PROJ-123 --expect-comment-id 10042 --expect-attachment-id 10055
```

For an Epic/child/dependency workflow, create the Epic with `jira issue create`,
create already-parented child issues with `jira issue child create`, then link
dependencies with `jira issue dependency add`. These are separate calls; the
broker does not roll back earlier Jira mutations if a later call fails. This
works only when the Epic and child issue types accept the narrow create fields;
issue types requiring additional custom fields are unsupported by these create
commands. Raw field passthrough is not available. To attach an existing issue to the
Epic instead of creating a new child, use `jira issue parent set <issue> --parent <epic>`.

See [providers-jira.md](providers-jira.md) for provider examples, canonical
`jira.<action>` invoke inputs, JSON `send` payloads, and lookup-backed
authorization behavior.

### Confluence (typed)

`agent-access confluence space list [--max-results N] [--page-token TOKEN]`
returns one live grant-filtered page; `--output-format markdown` is supported.
Continue `more` and `scan_budget` results even when empty. See
[space listing](providers-confluence.md#live-space-listing).

```bash
agent-access --url http://127.0.0.1:8787 confluence page view 123456
agent-access --url http://127.0.0.1:8787 confluence page view 123456 --read-content-format markdown
agent-access --url http://127.0.0.1:8787 confluence page view 123456 --output-format markdown
agent-access --url http://127.0.0.1:8787 confluence page view --page-url 'https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456'
agent-access --url http://127.0.0.1:8787 confluence page search --text 'runbook' --max-results 10
agent-access --url http://127.0.0.1:8787 confluence page search --text 'runbook' --max-results 10 --output-format markdown
agent-access --url http://127.0.0.1:8787 confluence page create --space ENG --title "Deploy Runbook" --content-file page.md --content-format markdown
agent-access --url http://127.0.0.1:8787 confluence page create --space ENG --title "Child Runbook" --parent 123456 --content-file child.storage.html --content-format storage
agent-access --url http://127.0.0.1:8787 confluence page update 123456 --base-version 7 --content-file page.adf.json --content-format atlas_doc_format
agent-access --url http://127.0.0.1:8787 confluence page move 234567 --position append --target 123456
agent-access --url http://127.0.0.1:8787 confluence page move 234567 --position after --target 345678
agent-access --url http://127.0.0.1:8787 confluence page attach 123456 ./diagram.png --content-type image/png
agent-access --url http://127.0.0.1:8787 confluence page footer-comment add 123456 --content "Deployment complete." --content-format plain_text
agent-access --url http://127.0.0.1:8787 confluence page footer-comment list 123456 --read-content-format text
agent-access --url http://127.0.0.1:8787 confluence blog view 222222
agent-access --url http://127.0.0.1:8787 confluence blog create --space ENG --title "Release Notes" --content-file release.md --content-format markdown
```

See [providers-confluence.md](providers-confluence.md) for provider examples,
canonical `confluence.<action>` invoke inputs, JSON `send` payloads, content-format
requirements, draft semantics, and lookup-backed
authorization behavior.

Page and page-draft creation accept `--parent <page-id>` or
`--parent-url <page-url>`; omitting both places the page under the space homepage.
Existing pages are reparented only through the separately granted
`confluence page move` command. Select the moved page by positional page ID or
`--page-url`, choose `--position before|after|append`, and select the target with
`--target` or `--target-url`. `append` places the page last under the target;
`before` and `after` place it adjacent to a sibling target. Moves are limited to
current pages in one space and do not expose parent clearing, cross-space moves,
or non-page targets.

### GitLab REST (typed)

Upload one project attachment with
`agent-access gitlab project upload team/project --file session.html --content-type text/html`.
Use `--project-url URL` instead of the project path when needed. MIME type is
inferred from the filename unless supplied. Canonical action `gitlab.project.upload`
returns `result.upload` with attachment paths and Markdown; see the
[upload contract](providers-gitlab-rest.md#project-uploads) for bounds and JSON send.

```bash
agent-access --url http://127.0.0.1:8787 gitlab project view team/project
agent-access --url http://127.0.0.1:8787 gitlab project view team/project --output-format markdown
agent-access --url http://127.0.0.1:8787 gitlab project view --project-url 'https://gitlab.example.com/team/project'
agent-access --url http://127.0.0.1:8787 gitlab issue view team/project 123
agent-access --url http://127.0.0.1:8787 gitlab issue view team/project 123 --read-content-format markdown
agent-access --url http://127.0.0.1:8787 gitlab issue view team/project 123 --output-format markdown
agent-access --url http://127.0.0.1:8787 gitlab issue search team/project --state opened --label bug --search 'deploy' --max-results 10
agent-access --url http://127.0.0.1:8787 gitlab issue search team/project --state opened --search 'deploy' --max-results 10 --output-format markdown
agent-access --url http://127.0.0.1:8787 gitlab issue search team/project --state opened --label bug --search 'deploy' --max-results 10 --page-token "$NEXT_PAGE_TOKEN"
agent-access --url http://127.0.0.1:8787 gitlab issue create team/project --title "Fix deploy docs" --content-file issue.md --content-format markdown --label docs --assignee-id 101
agent-access --url http://127.0.0.1:8787 gitlab issue comment team/project 123 --content-file comment.md --content-format markdown
agent-access --url http://127.0.0.1:8787 gitlab issue list-comments team/project 123 --projection summary
agent-access --url http://127.0.0.1:8787 gitlab issue view-comment team/project 123 NOTE_ID
agent-access --url http://127.0.0.1:8787 gitlab merge-request view team/project 45
agent-access --url http://127.0.0.1:8787 gitlab merge-request list-comments team/project 45 --projection summary
agent-access --url http://127.0.0.1:8787 gitlab merge-request view-comment team/project 45 NOTE_ID
agent-access --url http://127.0.0.1:8787 gitlab merge-request list-discussions team/project 45 --max-results 20 --projection summary --output-format markdown
agent-access --url http://127.0.0.1:8787 gitlab merge-request view-discussion team/project 45 DISCUSSION_ID --output-format markdown
agent-access --url http://127.0.0.1:8787 gitlab merge-request list-reviewers team/project 45
agent-access --url http://127.0.0.1:8787 gitlab merge-request list-commits team/project 45 --max-results 20
agent-access --url http://127.0.0.1:8787 gitlab merge-request list-pipelines team/project 45
agent-access --url http://127.0.0.1:8787 gitlab merge-request list-diffs team/project 45 --unidiff
agent-access --url http://127.0.0.1:8787 gitlab merge-request list-diff-versions team/project 45
agent-access --url http://127.0.0.1:8787 gitlab merge-request view-diff-version team/project 45 7 --unidiff
agent-access --url http://127.0.0.1:8787 gitlab merge-request diff-raw team/project 45 --output mr-45.diff
agent-access --url http://127.0.0.1:8787 gitlab merge-request create team/project --source-branch feature/rest --target-branch main --title "Update docs" --content-file mr.md --content-format markdown --reviewer-id 202
agent-access --url http://127.0.0.1:8787 gitlab merge-request comment team/project 45 --content-file review.md --content-format markdown
agent-access --url http://127.0.0.1:8787 gitlab merge-request discussion team/project 45 --content-file discussion.md --content-format markdown
agent-access --url http://127.0.0.1:8787 gitlab merge-request inline-discussion team/project 45 --expected-head-sha "$HEAD_SHA" --position-type text --old-path src/lib.rs --new-path src/lib.rs --new-line 42 --content-file inline.md --content-format markdown
agent-access --url http://127.0.0.1:8787 gitlab merge-request reply-discussion team/project 45 DISCUSSION_ID --content-file reply.md --content-format markdown
agent-access --url http://127.0.0.1:8787 gitlab merge-request list-draft-notes team/project 45 --max-results 20 --projection summary
agent-access --url http://127.0.0.1:8787 gitlab merge-request view-draft-note team/project 45 DRAFT_NOTE_ID
agent-access --url http://127.0.0.1:8787 gitlab merge-request add-draft-note team/project 45 --expected-head-sha "$HEAD_SHA" --position-file position.json --content-file draft.md --content-format markdown
agent-access --url http://127.0.0.1:8787 gitlab merge-request update-draft-note team/project 45 DRAFT_NOTE_ID --content-file revised.md --content-format markdown
agent-access --url http://127.0.0.1:8787 gitlab merge-request delete-draft-note team/project 45 DRAFT_NOTE_ID
agent-access --url http://127.0.0.1:8787 gitlab merge-request publish-draft-note team/project 45 DRAFT_NOTE_ID
agent-access --url http://127.0.0.1:8787 gitlab merge-request publish-all team/project 45 --content-file summary.md --content-format markdown
agent-access --url http://127.0.0.1:8787 gitlab merge-request submit-review team/project 45 --reviewer-state requested-changes --content-file summary.md --content-format markdown
agent-access --url http://127.0.0.1:8787 gitlab merge-request view-approval team/project 45
agent-access --url http://127.0.0.1:8787 gitlab merge-request view-approval-state team/project 45
agent-access --url http://127.0.0.1:8787 gitlab merge-request list-approval-rules team/project 45 --max-results 20
agent-access --url http://127.0.0.1:8787 gitlab merge-request view-approval-rule team/project 45 7
agent-access --url http://127.0.0.1:8787 gitlab merge-request approve team/project 45 --head-sha "$HEAD_SHA"
agent-access --url http://127.0.0.1:8787 gitlab merge-request unapprove team/project 45
agent-access --url http://127.0.0.1:8787 gitlab merge-request apply-suggestion team/project 45 DISCUSSION_ID NOTE_ID SUGGESTION_ID --expected-head-sha "$HEAD_SHA" --commit-message-file suggestion-message.txt
agent-access --url http://127.0.0.1:8787 gitlab merge-request apply-suggestions team/project 45 --suggestions-file suggestions.json --expected-head-sha "$HEAD_SHA"
agent-access --url http://127.0.0.1:8787 gitlab branch list team/project --search main
agent-access --url http://127.0.0.1:8787 gitlab file view team/project --path README.md --ref main
agent-access --url http://127.0.0.1:8787 gitlab file view team/project --path README.md --ref main --output-format markdown
agent-access --url http://127.0.0.1:8787 gitlab commit list team/project --ref-name main --first-parent true --max-results 10
agent-access --url http://127.0.0.1:8787 gitlab pipeline list team/project --ref work/docs --status success --max-results 10
agent-access --url http://127.0.0.1:8787 gitlab job list team/project --pipeline-id 12345 --scope failed --max-results 10
agent-access --url http://127.0.0.1:8787 gitlab job trace team/project 67890 --output job-trace.txt
```

#### GitLab repository discovery and native content search

```bash
agent-access gitlab project list --max-results 20
agent-access gitlab project search --search dispatch --include-namespaces true --archived false
agent-access gitlab project search --max-results 20
agent-access gitlab search issues --search 'credential rotation'
agent-access gitlab search merge-requests --search 'credential rotation'
agent-access gitlab search code --search verify_token --project team/project
agent-access gitlab search commits --search rotation --project team/project
agent-access gitlab search wiki --search onboarding --project team/project
agent-access gitlab search comments --search regression --project team/project
# Requires an operator-configured Zoekt tuple:
agent-access gitlab search code --search 'verify_.*' --engine zoekt --regex --project team/project
```

`gitlab project list` maps to the independently grantable `project.list` action
and lists live authorized projects, including archived projects. It accepts only
`--max-results`, `--page-token`, and response/output options. Its token cannot be
used with project search.

`gitlab project search` discovers upstream repositories within the caller's
grants; omit `--search` to browse. It maps to `project.search`. The six
`gitlab search` commands map to `search.issues`, `search.merge_requests`,
`search.code`, `search.commits`, `search.wiki`, and `search.comments`, and require
`--search`. They use native full-text search across authorized repositories or
the optional `--project`. `gitlab issue search PROJECT` and
`gitlab merge-request search PROJECT` list/filter within one required project
and retain their existing structured filters.

Content commands accept `--engine basic|advanced|zoekt`. Omit `--engine` to use
the service's configured default. Inspect the live action schema for configured
engine/scope support.
`--project` is required when the selected/default engine has no instance route;
with basic defaults this includes code, commits, wiki, and comments. `--regex`
exists only on code and requires Zoekt. Native syntax, index coverage, and
ranking depend on the engine. No fallback engine or project crawling is used.

All eight commands support `--max-results`, `--page-token`,
`--output-format json|markdown`, and local `--output` options. Repeat the original
query, filters, project, engine, regex choice, and page size when resuming.
`scanStatus=more` and `scan_budget` carry continuations without promising another
authorized match. An empty resumable page means “No matching authorized items in
this page; continue the search.” `exhausted` ends the selected stream;
`upstream_window` means incomplete coverage at a retrieval ceiling. A short page
does not imply completion. Confidential tokens expire 15 minutes after the
original search; invalid tokens require a fresh search. Previews and URLs are
untrusted content and do not grant access to other actions.

See [providers-gitlab-rest.md](providers-gitlab-rest.md) for provider examples,
canonical `gitlab.<action>` invoke inputs, JSON `send` payloads,
note/discussion terminology, repository mutation rules, and
lookup-backed authorization behavior.
The existing single-project issue/MR searches, issue/MR `list-comments`, the MR review-context list
commands, `list-draft-notes`, and `list-approval-rules` accept `--page-token`;
pass the previous response's `nextPageToken`
and reuse the same action, locators, filters, page size, and `--unidiff` choice;
the four projected collection commands also reuse `--projection`.

Issue/MR `list-comments`, MR `list-discussions`, and `list-draft-notes` accept
`--projection full|summary` and default to `full`; results echo the selected
projection. Summary retains identifiers, actor/state, timestamps, and full
normalized positions while omitting bodies, rendered bodies, suggestions, and
redundant target metadata. Discussion summaries include `noteCount` and every
nested note in order; draft summaries retain reply `discussionId` and
positioned `position`. Summary `--read-content-format` is a no-op. Summary
whole-result Markdown remains body- and suggestion-free.

Pagination tokens bind projection, so repeat it with `--page-token`; a full
token cannot continue a summary request. Draft tokens also bind the proven
upstream actor and fail if credential rotation selects a different GitLab user.
When a note ID is known, use `gitlab issue view-comment PROJECT IID NOTE_ID` or
`gitlab merge-request view-comment PROJECT IID NOTE_ID`. These separately
grantable commands return the exact full normalized note after proving its
parent, avoiding a collection scan.

An MR `list-comments` result contains ordinary Notes API comments. Those are
overview comments, not the complete review feed, and they do not carry file or
line association. Use `list-discussions` and `view-discussion` to inspect
threads. A diff note exposes its exact position, including paths, lines or line
range, and the reported base/start/head SHA association. `baseSha` is `null`
when GitLab reports no merge base, while `startSha` and `headSha` remain
present. Broker/API-created line-range endpoints use `type = old` for removed
or unchanged/context points and `type = new` for added points; GitLab
UI-created or otherwise returned positions may expose `null` for an
unchanged/context endpoint. Preserve the returned value. Positions are
version-bound: an old position is not
silently remapped after a push. Correlate it with
`list-diff-versions` and `view-diff-version` when reviewing history.
Before a positioned write, refresh `merge-request view` and structured diff
context. `inline-discussion` and positioned draft add/update require
`--expected-head-sha`; the broker's fresh MR context must also contain a
complete non-null base/start/head triplet, which callers do not pass. Supply a
closed position object with `--position-file`, or use `--position-type
text|file|image`, `--old-path`, `--new-path`, and category-specific flags. Text
positions use `--old-line`/`--new-line` or
`--range-start-old-line`/`--range-start-new-line` and
`--range-end-old-line`/`--range-end-new-line`; image
positions use `--position-width`, `--position-height`, `--position-x`, and
`--position-y`. The x/y flags require nonnegative integers. GitLab's REST prose
describes these values as floats, but its executable Grape parameter contract
rejects fractions; the Broker therefore rejects them before mutation. The
broker derives native line codes and multiline anchors.
Stale head or version data fails instead of being remapped. A multiline failure
uses safe input category `coordinates_unresolved` or `patch_unavailable`;
`overflow` and `without_files` diff versions use `patch_unavailable`.

`reply-discussion` targets the discussion ID, so it can reply to general,
current inline, or outdated threads. `add-draft-note` also supports a reply
draft with `--in-reply-to-discussion-id` and optional
`--resolve-discussion true|false`; it may instead create a general or positioned draft.
Drafts belong to the active GitLab credential: per-user mode isolates the
human's drafts, while service mode intentionally shares a bot-owned draft set
among all granted principals using that credential.
`list-draft-notes` uses the usual `--max-results`/`--page-token` interface, but
GitLab returns Draft Notes as one non-paginated array. The broker performs one
bounded upstream fetch per command and slices it locally with a signed offset
token. A continuation is not a snapshot; concurrent draft changes can repeat
or omit entries between pages.

Verified `publish-draft-note` success always prints
`mutationStatus = "applied"`, `retrySafe = false`, the input `draftNoteId`,
`published = true`, and required non-null `discussionId`/`noteId` for the
resulting GitLab note. Because GitLab's publish endpoint does not return that
note, the Broker uses bounded before/after discussion readback and requires one
exact actor/body/position match; it never guesses by timestamp or numeric ID.
If publication may have applied but the note cannot be proved uniquely, the
CLI exits `2` with the HTTP 409 `mutation_verification_failed` envelope,
`verificationStage = "published_note_readback"`,
`mutationStatus = "applied_unverified"`, `retrySafe = false`, and the original
draft ID under `safeLocators.draftNoteIds`. If the note IDs are proven but the
final draft-absence readback fails, stage `draft_absence_readback` also returns
the safe `discussionId` and `noteId`. Refresh by the safe locators; never retry
the publish automatically.

`publish-all` publishes the current credential owner's pending drafts and may
add an optional summary and `--internal`. `submit-review` requires GitLab 19.2
or newer, publishes that snapshot, accepts `--reviewer-state
reviewed|requested-changes`, and may add the same summary. It allows zero
drafts. `requested-changes` is reviewer workflow state, not formal approval;
the command rejects an existing formal approval or reviewer state `approved`
before writing. An unassigned acting reviewer returns `version_conflict` so the
caller refreshes reviewer assignment before trying again.
The recorded state alone does not prove the MR is merge-blocked: GitLab limits
that behavior to Premium/Ultimate and a project setting. Inspect current merge
status and applicable project policy before making a merge decision.

`view-approval` is the free-tier aggregate view. `view-approval-state` and the
approval-rule commands require GitLab Premium/Ultimate. Aggregate `approved`
has edition-dependent meaning; inspect `approvedBy` and `userHasApproved` for
the acting user's state. `approve --head-sha` fails closed until the current MR
has a matching collected diff version, a non-preparing/non-checking merge
status, and non-null patch ID. A null patch ID on an unchanged empty or legacy
diff may not become ready by retrying; refresh after a branch-changing push or
rebase. `unapprove` removes only the active credential owner's approval.
If a fresh actor-specific approval summary proves the actor is already approved
for `approve`, or has no approval for `unapprove`, the Broker returns
`version_conflict` (HTTP 409) before any GitLab approval POST.

`apply-suggestion` proves one exact discussion/note/suggestion. The batch
command reads a JSON array of 1 to 100 unique locator objects from
`--suggestions-file`. Both require the current expected head. Optional
`--commit-message` or `--commit-message-file` supplies GitLab commit-message
template text; GitLab expands `%{...}` placeholders, and a custom template
replaces the default message and its default `Co-authored-by` trailer. It does
not resolve the review thread. For a fork MR, one policy grant must cover both
the target and source repositories and the credential must be able to push the
source branch. Success reports verified applied suggestion IDs/state, not a
commit SHA. If readback cannot prove application, the applied-unverified 409
contract applies; refresh the returned locators and do not automatically retry.

Structured diff commands preserve GitLab's missing/collapsed/too-large state;
they never imply that an absent patch is complete. `collapsed` and `tooLarge`
appear only on GitLab 18.4 or newer. `diff-raw` requires GitLab 17.9 or newer
and streams only the current diff. Its metadata records the preflight head, but
GitLab cannot pin that stream to a SHA; use `view-diff-version` for a historical
snapshot.

GitLab read presentation uses the same provider-neutral controls as Jira and
Confluence. Embedded `--read-content-format markdown` preserves each native
issue/MR description or note/discussion body and adds `renderedBody` beside its
owner; because Markdown is GitLab-native, the embedded Markdown value is
byte-for-byte identical. `text` derives bounded readable text and suppresses
active raw HTML. Eligible result families include issue and merge-request
descriptions, notes, discussion notes, and draft notes.

`--output-format markdown` instead prints one semantic Markdown document for
the exact existing result. Eligible retrieval families include project, issue,
merge-request, note/discussion/draft, reviewer, current/historical structured diff,
branch, protected-branch, file, commit, pipeline, and job reads. Templates retain
meaningful present fields, collection order, pagination, file-view base64, and
literal commit messages; they do not dump arbitrary JSON, fetch related data,
decode file content, or follow pagination. Raw file/job-trace downloads and all
mutation results do not expose whole-result Markdown; raw MR diff is likewise a
stream and does not expose it.

Review mutations are not automatically retried. If GitLab may have applied a
write but its final state cannot be proven, the broker returns HTTP 409 with
`decision = error`, `reasonCode = mutation_verification_failed`, and
`result.retrySafe = false`; the CLI exits 2. Treat it as applied-but-unverified:
refresh with safe IDs from `result`, then decide whether another mutation is
needed. A direct or single-item mutation's upstream 5xx after the request uses
this same 409/error contract and is not a retry signal. After such an uncertain
failure, publish-all and review-submit re-read drafts and reviewer state and may
return an ordinary sanitized upstream failure only when they prove no change. A
definitive GitLab rejection (a redirect, a 4xx such as 403 or 409, or
throttling) keeps its ordinary error with no receipt. Broker attribution
applies to exactly five
review writes: direct inline add, reply add, draft add, publish-all summary, and
review-submit summary; it does not apply to draft update. Audit records never
contain review bodies, summaries, patches, native
line codes, or continuation tokens.

These read controls are independent from write `--content-format`. Do not
combine explicit non-native `--read-content-format` with whole-result Markdown.
Use command help or catalog capability arrays rather than inferring support from
an action name.

#### GitLab project webhooks

```bash
agent-access gitlab webhook list team/project --max-results 20
agent-access gitlab webhook view team/project 42
agent-access gitlab webhook create team/project \
  --destination-url https://hooks.example.com/gitlab/events \
  --event push --event merge_requests \
  --secret-token-env GITLAB_HOOK_TOKEN
agent-access gitlab webhook update team/project 42 \
  --event push --event notes --clear-description
agent-access gitlab webhook delete team/project 42
agent-access gitlab webhook test team/project 42 --event merge_requests
agent-access gitlab webhook event list team/project 42 \
  --status server_failure --max-results 20
agent-access gitlab webhook event resend team/project 42 9001
agent-access gitlab webhook custom-header set team/project 42 Authorization \
  --value-file /run/secrets/gitlab-hook-authorization
agent-access gitlab webhook custom-header delete team/project 42 Authorization
```

`--destination-url` is deliberately distinct from the global `--url`, which
selects the Broker endpoint.

Typed event and status values use the same canonical underscores
(`merge_requests`, `server_failure`) as action inputs. Create's repeatable
`--event` is the complete desired set. On update, one or more
`--event` values completely replace the set, while `--clear-events` selects an
empty set. Optional strings use explicit `--clear-name`,
`--clear-description`, and `--clear-custom-webhook-template` flags.

Webhook secrets have no literal typed flags. Use exactly one source for each
value:

```text
--secret-token-env NAME | --secret-token-file PATH | --secret-token-stdin
--signing-token-env NAME | --signing-token-file PATH | --signing-token-stdin
--value-env NAME | --value-file PATH | --value-stdin
```

Only one field may consume stdin. Values are exact UTF-8 and secret-file input
is not trimmed. Avoid shell tracing and never print the source variable.

The operator's TOML destination allowlist applies only to create and actual URL
change. Existing hooks remain listable, editable without URL change, testable,
inspectable, resendable, and deletable when the corresponding action is
granted. A URL change requires either a replacement token source or
`--clear-token`; when preflight reports affected custom-header or URL-variable
names, inspect them and repeat with `--confirm-destination-reset`. HTTP requires
an explicit operator-configured `http://` pattern. Disabling HTTPS verification
requires the operator setting described in
[configuration.md](configuration.md#providersgitlab).

`test` and `event resend` cause delivery and are never safe to retry blindly.
If a result reports `applied_unverified`, use list/view/event list to reconcile
state before deciding whether to act again. Delivery event list is a separately
grantable content read: request/response bodies are bounded, sensitive headers
are redacted, and per-field truncation is marked.

### Self-service token and credential management

Management commands carry the management broker token through `--token-env`,
`--token-file`, config, or `AGENT_ACCESS_TOKEN` — never `--token-value`.

```bash
# Issue an admin-provisioned management token (admin token required)
agent-access --url http://127.0.0.1:8787 --token-env ADMIN_TOKEN \
  admin tokens issue alice@example.com --name alice-setup --token-class user_manage --ttl 2h

# Create a noninteractive workload identity. Service accounts accept only
# administrator-issued agent_invoke tokens, never setup/admin tokens or login.
agent-access --url http://127.0.0.1:8787 --token-env ADMIN_TOKEN \
  admin principals create nightly-reporter --kind service_account \
  --display-name "Nightly Reporter"

# Store one Atlassian account email and API token for the atlassian
# connection that Jira and Confluence share (user_manage token)
agent-access --url http://127.0.0.1:8787 --token-env USER_MANAGE_TOKEN \
  credentials put atlassian \
  --username-env ATLASSIAN_ALICE_USERNAME \
  --field-env token=ATLASSIAN_ALICE_API_TOKEN \
  --verify

# Store one GitLab token for the gitlab connection that GitLab REST and the
# GitLab Git gateway share, and verify it through GitLab REST
agent-access --url http://127.0.0.1:8787 --token-env USER_MANAGE_TOKEN \
  credentials put gitlab --field-env token=GITLAB_TOKEN --verify

# Verify the same token through the Git gateway against one repository. The
# gateway presents it as its upstream_token_auth selects; GitLab Git HTTP needs
# { scheme = "basic", username = "oauth2" }.
agent-access --url http://127.0.0.1:8787 --token-env USER_MANAGE_TOKEN \
  credentials verify gitlab --service gitlab_git --repository team/project

# Provision a service account's token (admin token required)
agent-access --url http://127.0.0.1:8787 --token-env ADMIN_TOKEN \
  admin credentials put nightly-reporter atlassian \
  --username-env ATLASSIAN_REPORTER_USERNAME \
  --field-env token=ATLASSIAN_REPORTER_API_TOKEN --verify

# Use normal Git against the gateway listener. Configure the native helper as
# described below so Git obtains the agent_invoke broker token from this CLI.
# The repository URL may include or omit the trailing .git.
git clone https://git.example.com/team/project

# Issue a self-service token that follows current policy in two contexts
agent-access --url http://127.0.0.1:8787 --token-env USER_MANAGE_TOKEN \
  tokens issue --name codex-workstation \
  --execution-context workstation --execution-context internal --ttl 30d
```

Configure the CLI's credential helper for each brokered Git host:

```bash
agent-access auth token set --token-stdin
git config --global --replace-all \
  credential.https://<brokered-git-host>.helper ""
git config --global --add \
  credential.https://<brokered-git-host>.helper \
  "!agent-access auth git-credential"
```

Replace `<brokered-git-host>` with the exact gateway hostname before running
these commands.

This produces the following URL-scoped Git configuration:

```gitconfig
[credential "https://<brokered-git-host>"]
	helper =
	helper = "!agent-access auth git-credential"
```

The empty entry clears inherited helpers for that URL. The next entry runs the
CLI, which supplies the fixed username `agent-access` and the effective broker
token as the password. The Agent Access token remains authoritative: Git stores
no second copy, and updating it with `auth token set --token-stdin` affects the
next Git operation. The gateway must therefore use its default
`basic_broker_token_username = "agent-access"`. Git `store` and `erase` calls
intentionally do not change the token; use `auth token clear` explicitly when
needed.

Do not configure this helper globally under `[credential]`. The CLI is
deliberately host-agnostic, so only Git's URL-specific configuration prevents a
broker token from being offered to an unrelated HTTPS host. The gateway
listener is separate from the public `/v1` API URL, so Git remotes point at the
configured gateway host, not at `agent-access --url`. See
[git-http-gateway.md](git-http-gateway.md) for gateway request classification,
policy scopes, push validation, and audit behavior.

## Testing

Deterministic test commands, offline smoke harnesses, ignored live-backend smoke
recipes, and Confluence CQL conformance smoke instructions live in
`docs/testing.md`. Keep this CLI reference focused on command behavior and use
the testing guide for repository test workflows.

## See also

- HTTP routes, request-id rule, response envelopes, reason codes, and raw
  download negotiation: `docs/http-api.md`.
- Broker and CLI config shapes (including `service.url`, `identity.*`, and secret
  refs): `docs/configuration.md`.
- Managed-store database, token, and encryption model: `docs/database.md`.
- Architecture, request lifecycle, and security posture: `docs/design.md`.
- Provider and gateway overview plus links to detailed contracts:
  `docs/providers.md`.
- Detailed provider contracts: `docs/providers-jira.md`,
  `docs/providers-confluence.md`, `docs/providers-gitlab-rest.md`,
  and `docs/git-http-gateway.md`.
- Deterministic tests, live smokes, and conformance smokes: `docs/testing.md`.

## GitLab bot provisioning

Use `gitlab project access-token` for list/view/create/rotate/revoke and
`gitlab service-account` for list/view/create/delete/member-set and token
list/create/rotate/revoke. Token create/rotate require `--expires-at`;
`--token-output PATH` writes the new secret to a new private file and keeps it
out of stdout. Without that option the JSON response includes the issued token.
See [the full workflow](gitlab-bot-provisioning.md).


## CloudBees CI

`cloudbees-ci job list CONTROLLER` enumerates one JSON page of current jobs and
containers within effective grants. Optional `--folder` selects a canonical root;
`--max-results` bounds the page. Pass `--page-token` from `nextPageToken` with
unchanged inputs for both `more` and `scan_budget`, including empty pages.
`exhausted` ends the observed stream; `upstream_window` means terminal incomplete
coverage. This read-only command requires its own `job.list` grant, never expands
job inspection/build access, and has no Markdown format. See
[live job listing](providers-cloudbees-ci.md#live-job-listing).

```sh
agent-access cloudbees-ci job list team-ci --folder payments --max-results 50
agent-access cloudbees-ci job list team-ci --folder payments --max-results 50 --page-token TOKEN
```

Other `cloudbees-ci` typed commands locate a job by `CONTROLLER JOB` positionals or
by `--job-url URL`. `CONTROLLER` is a configured controller alias, the first
segment of a `cloudbees_ci_job` resource value; `JOB` is the Jenkins full name
below it, such as `payments/build-api`. Take both from a
`resource-access describe` registered reference or
coverage `inputs`. `--job-url` accepts a Jenkins job or build URL on a configured
controller and is sent as the `url` input (`--url` remains the broker URL).
Build commands take a `BUILD_NUMBER` positional or `--build-selector
PERMALINK` (`lastBuild`, `lastCompletedBuild`, `lastFailedBuild`,
`lastSuccessfulBuild`, `lastStableBuild`, `lastUnstableBuild`,
`lastUnsuccessfulBuild`), sent as `buildNumber` or `buildSelector`. With
`--job-url`, omit the positionals and give the build in the URL or with
`--build-selector`. Pipeline node IDs, artifact paths, and queue IDs are
`--node-id`, `--artifact-path`, and `--queue-id`. These wrappers invoke
`cloudbees_ci` catalog actions. Artifact, console log, and test report
downloads transfer raw bytes; the other actions return JSON:

```bash
agent-access cloudbees-ci build log-download team-ci payments/build-api 42 --output ./build-42.log
agent-access cloudbees-ci build pipeline view team-ci payments/build-api 42
agent-access cloudbees-ci build pipeline node team-ci payments/build-api 42 --node-id 7
agent-access cloudbees-ci build pipeline log team-ci payments/build-api 42 --node-id 7
agent-access cloudbees-ci build pending-inputs team-ci payments/build-api 42
agent-access cloudbees-ci build tests-details team-ci payments/build-api 42 --max-results 50
agent-access cloudbees-ci build tests-download team-ci payments/build-api 42 --output ./tests-42.json
agent-access cloudbees-ci job view team-ci payments/build-api
agent-access cloudbees-ci job view --job-url https://ci.example.com/team-ci/job/payments/job/build-api/
agent-access cloudbees-ci build list team-ci payments/build-api --max-results 10
agent-access cloudbees-ci build view team-ci payments/build-api 42
agent-access cloudbees-ci build view team-ci payments/build-api --build-selector lastFailedBuild
agent-access cloudbees-ci build view --job-url https://ci.example.com/team-ci/job/payments/job/build-api/42/
agent-access cloudbees-ci build log --job-url https://ci.example.com/team-ci/job/payments/job/build-api/ --build-selector lastFailedBuild --mode search --query ERROR
agent-access cloudbees-ci build log team-ci payments/build-api 42 --mode head --max-bytes 8192
agent-access cloudbees-ci build log team-ci payments/build-api 42 --mode tail
agent-access cloudbees-ci build log team-ci payments/build-api 42 --mode search --query ERROR --max-matches 20
agent-access cloudbees-ci build tests team-ci payments/build-api 42
agent-access cloudbees-ci build artifact list team-ci payments/build-api 42
agent-access cloudbees-ci build artifact download team-ci payments/build-api 42 --artifact-path reports/results.zip --output ./results.zip
agent-access cloudbees-ci build trigger team-ci payments/build-api
agent-access cloudbees-ci queue view team-ci payments/build-api --queue-id 51
```

A log `--cursor` continues the numeric build: pass the returned build number,
not `--build-selector`. Do not repeat a `build trigger` whose result reports
`retrySafe: false`; check `job view` or `build list` first.

Use `--output -` to write a completed download to stdout. JSON `send` can also request
the raw download with an output sink; direct HTTP and local stdio MCP expose
the raw bytes. HTTP MCP advertises JSON reads and omits raw downloads.
See [the CloudBees CI provider contract](providers-cloudbees-ci.md) for
authorization, result bounds, and trigger semantics.

## OAuth test records

When the Broker configures the development `oauth_stub` backend, the CLI provides
`oauth-stub record list --collection alpha`,
`oauth-stub record view alice-alpha-1 --collection alpha`, and `oauth-stub account`.
They invoke the canonical `oauth_stub.record.list`, `record.view`, and
`account.view` actions using the caller’s existing Broker token. Connect the
upstream account in the browser first; see [oauth.md](oauth.md).

## Teams notifications

For Teams notifications, use `teams notification send DESTINATION --text TEXT`
with optional `--title TITLE`, or `--content-file PATH` for a native Microsoft
Adaptive Card envelope or MessageCard. These wrap `teams.notification.send`.
The two input forms are exclusive. A successful receipt means Workflow endpoint
acceptance, not completed delivery. There is no automatic retry. CLI `--output`
and local MCP `outputPath` can save the acceptance response; a local save failure
does not imply the notification failed and must not trigger another send. See [Teams notifications](providers-teams.md).

## Gmail commands

`gmail account`, `gmail labels`, `gmail message search/view/archive/trash/restore`,
and `gmail thread view/archive/trash/restore` wrap the canonical Gmail actions.
Search accepts `--query`, `--max-results` (1–50), `--page-token`, and
`--include-spam-trash`. Other message/thread commands take one positional ID.
See [Gmail examples and semantics](providers-gmail.md).


## Imported actions

Base administrators use `admin imports list/get/create/update/discover/preview/accept`,
`admin imports upload-document`, `admin imports status/action-status`, and
`admin imports credentials put/delete`.
Complex writes use `--request-file`; versioned writes require `--expected-version`
and `--expected-catalog-revision`. Token writes use `--secret-file`, `--secret-env`,
or `--secret-stdin`, plus `--username` when the selected slot's `credentialInputs`
requires it, including Basic. Before reading secret material, the CLI checks the
current descriptor and requires its service and catalog revisions to equal the
explicit expected flags. It does not replace those flags or retry a stale write.
Basic environment values are exact; file/stdin removes at most one final LF or
CRLF, preserving spaces. Use `--confirm` for retirement and when re-enabling a service
or action with retained grants. See the [import management command workflow](imported-services.md#cli-and-http-management)
for exact request shapes, discovery timeouts and credential ownership.

For an uploaded Swagger/OpenAPI source, use `admin imports upload-document
SERVICE --document-file PATH --expected-version N --expected-catalog-revision N`.
Generic `send` cannot represent this exact-byte upload and rejects its route.
The CLI reads at most 4 MiB of UTF-8 JSON, sends the exact bytes and the file's
basename, and allows 75 seconds for validation and preview creation. The Broker
separately requires the entire body within the smaller of
`limits.request_body_timeout_ms` and 15 seconds; the CLI timeout does not extend
that receive deadline. The Broker rejects duplicate JSON members. A successful upload retains the source and
creates a preview; review and acceptance remain separate. A rejected replacement
preserves the previously retained source and accepted generation. See
[uploaded document workflow](imported-openapi.md#uploading-and-replacing-a-document).

Use the caller-filtered catalog for the service/action names and accepted schemas of
imported MCP tools. These are action-only grants without resource scopes. Results
preserve MCP content as JSON under `result.upstreamMcp`; images/audio remain bounded
JSON and resource links are not fetched. The entire opaque payload is catalog-marked
sensitive, including reads, so output markers cover private data as well as secret
exports. Writes are reported as applied but unverified on upstream success; failures
after dispatch may be uncertain and are never automatically replayed. Saving a local
response is separate from operation success. See the imported-services guide in
`docs/imported-services.md` for administrative setup and supported protocol limits.

Swagger 2.0 and OpenAPI 3.1 JSON imports use the same generic `invoke` and `send`
commands. Their accepted inputs separate `path`, `query`, `headers` and `body`.
For a URL-encoded operation, provide the declared scalar fields as a JSON `body`
object; the Broker encodes it for the upstream. Results are bounded JSON under
`result.upstreamHttp`. There are no generated per-import CLI subcommands. See
[OpenAPI and Swagger imports](imported-openapi.md).
