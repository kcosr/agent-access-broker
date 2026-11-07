# Connect an HTTP API through a gateway

An OpenAPI HTTP gateway lets ordinary HTTP clients use reviewed API operations
through the Broker. The Broker authenticates the caller, checks grants and
execution context, applies invocation and transfer limits, supplies the selected
upstream credential, and audits the transfer. Clients receive the upstream HTTP
response and raw bytes, including downloads.

The application does not need to publish an API specification. Its owner can
write a Swagger 2.0 or OpenAPI 3.1 JSON document and upload it. The document must
accurately describe the paths, methods, parameters and authentication that the
application actually supports. YAML and other OpenAPI versions are not supported.

Gateway actions authorize whole operations. A grant for `GET /items/{id}` allows
every `id` accepted by the request profile and upstream credential. It does not
limit access to particular projects, packages or records. Path parameters are not
Broker resource scopes. Use a custom gateway module when access must be scoped
by protocol-specific resources or constrained body fields.

## Reserve the gateway

The operator configures the gateway listener and a binding for a reserved service
identity. All gateways share that listener and are selected by HTTP host. Adding
a binding does not allocate a new listener or port. Provision DNS, the external
TLS endpoint and routing to the gateway listener as part of deployment; the main
Broker API listener remains separate.

For example, reserve `inventory` for an API whose base path is `/api`:

```toml
[imports]
enabled = true
allowed_kinds = ["openapi_http", "openapi_gateway"]
allowed_endpoints = ["https://inventory.example.com/api"]

[imports.gateway_bindings.inventory]
broker_hosts = ["inventory.gateway.example.com"]
endpoint = "https://inventory.example.com/api"
auth_modes = ["bearer_broker_token"]
allow_forwarded_identity = false
```

The binding reserves the service ID, host and exact upstream API destination.
The destination must also pass `imports.allowed_endpoints`. For a document
fetched from a URL, allow its document destination separately. Uploaded documents
need no document URL or discovery credential. Enable the managed store and import
management as described in [imported services](imported-services.md).

In the portal, the administrator selects the unused approved binding instead of
typing a new service ID or API endpoint. Once created, the import keeps that
identity, exposure and endpoint. A disabled or retired import does not free its
identity. Removing its binding makes the import unavailable while retaining its
definitions, credentials, guards and grants. Configure a new identity for a
different upstream routing contract.

## Write the document

The following uploadable example describes an anonymous upstream inventory API.
Broker ingress is still authenticated. Save the complete JSON as
`inventory-gateway.json`; the example hosts are placeholders for your approved
deployment.

<!-- gateway-setup-document:start -->
```json
{
  "openapi": "3.1.1",
  "info": { "title": "Inventory gateway", "version": "1" },
  "servers": [{ "url": "https://inventory.example.com/api" }],
  "security": [],
  "paths": {
    "/items/{id}": {
      "parameters": [
        { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
      ],
      "get": {
        "operationId": "get_item",
        "summary": "Read an item",
        "parameters": [
          { "name": "view", "in": "query", "schema": { "type": "string", "enum": ["summary", "detail"] } }
        ],
        "responses": {
          "200": { "description": "Item", "content": { "application/json": { "schema": { "type": "object" } } } }
        }
      },
      "put": {
        "operationId": "update_item",
        "summary": "Replace an item",
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "type": "object", "properties": { "name": { "type": "string" } }, "required": ["name"] } } }
        },
        "responses": { "204": { "description": "Updated" } }
      }
    },
    "/items/admin": {
      "get": {
        "operationId": "admin_items",
        "summary": "Administrative inventory route; leave unaccepted",
        "responses": { "200": { "description": "Administrative data" } }
      }
    },
    "/artifacts/{id}": {
      "parameters": [
        { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
      ],
      "get": {
        "operationId": "download_artifact",
        "summary": "Download an artifact",
        "responses": {
          "200": {
            "description": "Artifact bytes",
            "headers": { "X-Api-Version": { "schema": { "type": "string", "maxLength": 32 } } },
            "content": { "application/octet-stream": { "schema": { "type": "string", "format": "binary" } } }
          }
        }
      },
      "head": {
        "operationId": "artifact_metadata",
        "summary": "Read artifact metadata",
        "responses": {
          "200": {
            "description": "Artifact headers",
            "headers": { "X-Api-Version": { "schema": { "type": "string", "maxLength": 32 } } }
          }
        }
      }
    }
  }
}
```
<!-- gateway-setup-document:end -->

Declare every concrete path that takes precedence over an accepted template,
including paths you do not intend to accept. In this example, leaving
`admin_items` unaccepted makes `/items/admin` a denial target; it cannot fall
through to the accepted `/items/{id}` action. The Broker derives guards from the
document. It cannot discover a backend `/items/admin` route omitted by the
author. Do not create a reduced document by deleting shadowing routes.

Templates bind complete individual segments. Concrete paths take precedence;
equivalent templates with renamed variables and ambiguous overlapping templates
are rejected. Methods are exact: declare HEAD and OPTIONS explicitly. Missing,
unsupported and unaccepted operations do not fall through to another template.
Removed paths remain historical denial guards. A refresh never removes a guard
to make room; exceeding the guard limits rejects the refresh and retains the
previous complete generation.

Declared path, query and ordinary header parameters use the supported primitive
schema and serialization profile. Unknown query parameters and duplicate scalar
parameters are rejected. The preview reports unsupported features. The Broker
preserves the approved upstream base path: a client request for `/items/widget`
in this example goes to the upstream `/api/items/widget`.

**Body schema not validated by gateway.** The `update_item` schema documents the
application's expected `name` field; the Broker does not enforce that field or
restrict additional body fields. It checks whether a body is present or required,
declared media type, framing and bounded transfer. An empty payload is absent.
JSON, URL-encoded forms and declared `application/octet-stream` bodies are sent
as raw bytes. GET, HEAD and OPTIONS request bodies, multipart bodies and arbitrary
content encodings are unsupported. Response schemas are documentation, not runtime
validators. These semantics differ from [Actions/tools imports](imported-openapi.md).

## Import, review and grant access

1. Open **Admin > Catalog > Import service**, select **OpenAPI / Swagger**, then
   **HTTP gateway**. Select the approved `inventory` binding and a display name.
2. Choose **Upload file** and select the JSON file, or **From URL** and configure
   the approved document URL. Private document authentication uses a separate
   discovery credential. It never supplies API execution authority.
3. Choose **Anonymous upstream** for this example, create the draft and load or
   review the document. Anonymous mode requires the operation's effective
   security declaration to permit anonymous access. It stores no fake token.
4. Review methods, paths, parameter constraints, raw-body behavior and response
   headers. Accept `get_item`, `download_artifact` and `artifact_metadata` if they
   are appropriate, explicitly marking them reviewed read-only. Leave
   `admin_items` unaccepted. Accept `update_item` only when write access is
   intended; HTTP method alone does not determine the reviewed effect class.
5. Enable the service and use the existing grant screens to select actions,
   callers and execution contexts. Anonymous upstream access uses service-mode
   grants. Issued Broker token restrictions and read-only ceilings still apply.
6. Give the native client the externally reachable gateway address and Broker
   authentication configuration. Gateways are absent from ordinary agent service
   and action discovery, MCP tools, typed actions and `/v1/invoke`.

If creation succeeds but uploading the document fails, the portal retains the
created draft. Open it, inspect its current document and preview, and explicitly
retry the upload if needed. Do not create another service as an automatic retry.

For a static upstream credential, choose **Static credential** instead. Load the
document, select its supported Basic, Bearer or header API-key scheme, save the
configuration, refresh the document, and set the credential through the existing
encrypted credential controls. Grants can select configured shared or personal
credentials; a missing personal credential never falls back to a shared one or
anonymous access. The selected authenticated alternative always sends that
credential, even if the document also allows anonymous requests.

Broker ingress authentication is configured by the operator binding, independently
of the document's upstream scheme. A Broker Bearer token can authenticate a request
whose backend uses Basic. Broker authorization and trusted-identity carriers are
consumed locally and never forwarded as ordinary backend headers. OpenAPI gateway
imports have no delegated OAuth support and no active Verify probe. This does not
disable Git's existing OAuth Connect, token setup or repository verification.
Mixed credential connections retain verification through eligible consumers.

The management definition uses `adapterKind: "openapi_gateway"` and the binding's
exact `service` and `endpoint`. Its string-valued `connectionSettings` include
`executionAuthentication: "anonymous"` or `"static"`, plus the existing document
source settings. Anonymous mode requires `executionBindings: []` and omits
`securityScheme`. Static mode uses the selected scheme and existing static binding
delivery. Authentication can be chosen in an empty draft; accepted connection
settings are immutable. Draft settings changes follow the ordinary credential
cleanup and fresh-preview requirements.

## Use the gateway

For the example Bearer ingress binding, an HTTP client can request an item or
save an artifact using its normal output controls:

```bash
curl --fail-with-body \
  --header "Authorization: Bearer ${BROKER_TOKEN:?Set a Broker token}" \
  'https://inventory.gateway.example.com/items/widget?view=summary'

curl --fail-with-body \
  --header "Authorization: Bearer ${BROKER_TOKEN:?Set a Broker token}" \
  --output ./artifact.bin \
  'https://inventory.gateway.example.com/artifacts/build-123'
```

These commands are deployment templates, not live qualification. Confirm the
external scheme, hostname, port and token handling with the operator. Native
applications use their own equivalent remote URL and authentication settings.
No client installation or application-specific compatibility claim is implied.

The HTTP profile supports common content, conditional and single-range headers,
plus permitted declared request and response headers. The example declares
`X-Api-Version`; document custom response headers that clients require. Cookies,
upstream authentication challenges and routing override headers are not forwarded.
Redirects are refused, and absolute URLs embedded in response bodies are not
rewritten. Applications requiring those behaviors need separate qualification
and may need a custom module. Responses retain the Broker's private/no-store
policy; no shared cache is introduced.

Every classified gateway operation, including GET and HEAD, uses the existing
personal and aggregate service admission limits. Managed personal rates can be
edited in the import configuration; shared caps, waiting policy and transfer
budgets are operator-owned. Separate action and gateway imports of one upstream
have separate service limits. Streaming holds request capacity until delivery or
bounded disposal completes. A timeout or disconnect after bytes were sent does
not prove a write was unapplied; do not automatically repeat an uncertain write.

## Refresh and operate

Refresh or replace the source document from **Discovery and review**. New
operations remain unaccepted; changed or removed accepted operations require
review, with affected-grant confirmation when restoring changed authority.
Route guards, accepted plans and action status are published together. Failed
discovery leaves the previous complete generation active. Startup uses the
retained plans and guards without fetching a document.

Check the import's availability, gateway binding, selected credential, grants and
audit events when a client cannot connect. Unmatched and inactive operations
return the same generic not-found outcome. Administrator views retain the policy
identities needed for troubleshooting, and explicit resource-access inspection
for a known service remains available to authorized callers. Ordinary agent
discovery does not reveal the gateway.

Back up the managed database, configuration and encryption keys before upgrades.
Follow the schema and coordinated restore requirements in [database](database.md)
and the [operator guide](operator-guide.md). An older binary does not accept an
unknown migration ledger; rollback requires the matching pre-upgrade state and
software rather than dropping the gateway table.
