# Trusted callers

Trusted callers authenticate an attesting service, which supplies an approved
execution context and, when configured, a managed human identity. The caller
credential alone never authenticates a human, adds grants, or grants management
access. Broker applies the resolved principal's current invocation permissions.

## Configuration

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
allowed_execution_contexts = ["external", "internal", "workstation"]
allow_forwarded_identity = true

[identity.trusted_callers.job_runner]
credential_ref = "file:/run/secrets/job-runner-attestation"
context_mode = "fixed"
execution_context = "internal"
```

Caller names are operator-selected audit labels. The credential selects an entry;
there is no client-supplied caller name or namespace. Each entry accepts exactly
one `credential_transport`: `caller_authorization` (the default) or
`authorization_user`. Distinct entries can attest the same namespace but must use
distinct credentials. A direct caller credential must not collide with a static
principal credential or begin with the reserved managed-token prefix `aab_`.

Credentials use secret references and contain at least 16 visible ASCII bytes.
Username-capable callers require 16–8192 bytes, excluding whitespace and commas.
Secrets are loaded with the runtime snapshot: replace the secret file and reload
Broker to rotate one. Keep them outside agent workloads, editable client settings,
provider inputs, logs and audit. The managed launcher must control both its
credential and the asserted username; hiding only the credential does not prevent
impersonation if the user can choose the name sent with it.

`context_mode` is required. `fixed` requires `execution_context` and forbids
`allowed_execution_contexts`; `asserted` requires a nonempty unique
`allowed_execution_contexts` list and forbids `execution_context`. Values come
from the global execution-context vocabulary.

`username_namespace` enables username assertions and uses the safe configuration
identifier grammar. It requires managed identity authority and a managed store.
`authorization_user` also requires a namespace and fixed context, and cannot
set `allow_forwarded_identity = true`. The latter flag enables only fingerprint
forwarding and defaults to false; it requires managed identity/store/encryption.
A dedicated-carrier caller may enable usernames, fingerprints, or both, but a
request may assert only one representation. A context-only caller still needs an
ordinary principal credential.

## Admission

### Trusted usernames on HTTP MCP

Direct callers use this pair on `/mcp` or `/mcp/{service}`:

```http
Authorization: Bearer <managed-client caller credential>
X-Agent-Access-User: alice
```

Relayed callers use a separately configured credential in the dedicated carrier:

```http
X-Agent-Access-Caller-Authorization: Bearer <ingress caller credential>
X-Agent-Access-User: alice
X-Agent-Access-Context: workstation
```

The context line is required for asserted callers and forbidden for fixed callers.
Direct username callers always use their fixed context and omit that header.
The username is 1–128 ASCII bytes from `[A-Za-z0-9._@+-]`, case sensitive and
exact. Numeric-looking names remain names. Broker does not trim, case-fold,
percent-decode, normalize Unicode, split commas, or look up OS users, emails or
principal IDs. The configured namespace and exact name must have an enabled
[managed binding](managed-identity.md#username-bindings) to an active human with
unpaused identity access. Username access does not require an identity token.

Presence of `X-Agent-Access-User` selects username authentication before ordinary
token authentication. Duplicate, empty, malformed, comma-combined or overlong
values fail. Exactly one supported bearer carrier is required; both carriers,
a fingerprint, or an alternate configured principal credential is a conflict.
The bearer scheme is case insensitive; its single token is bounded to 8192 bytes
and may not contain whitespace or commas. A wrong credential, ordinary principal
token, wrong transport or missing capability never falls back to another method.
Even an administrator token cannot override the username assertion.

The user header is rejected on every other route, including health, browser,
management, REST invocation and Git. No URL, query parameter, tool input, cookie
or session ID selects a username. MCP rejects queries, including an empty `?`.
Repeat the credential and username on every MCP request, including initialization,
notifications, discovery, calls, cancellation and DELETE. Sessions cannot change
identity; see [MCP identity lifetime](mcp.md#trusted-identity-and-session-lifetime).

### Ordinary tokens and forwarded fingerprints

Without the user header, callers use:

```http
X-Agent-Access-Caller-Authorization: Bearer <caller credential>
```

Every supplied caller credential is checked, even alongside valid principal
credentials or on browser, management and public routes. Matching is always
transport-aware: a direct-only credential in the dedicated carrier is invalid.
A direct caller secret without a user assertion is not a principal bearer.
`X-Agent-Access-Context` and `X-AW-Identity-Token-SHA256` require an authorized
caller even when no callers are configured.

Asserted callers send one approved context on governed operations; they cannot
inherit the direct-client default. Fixed callers omit the context header even
when it would match. Ordinary clients without caller assertions use the configured
direct default, or built-in `default` when the execution-context section is absent.

A fingerprint requires `allow_forwarded_identity = true`. It has exactly the form
`sha256:` plus 64 lowercase hexadecimal digits. Forbidden or malformed forwarding
fails even beside a valid principal token. An explicit principal credential
remains authoritative; an invalid one never falls back to the fingerprint.
Fingerprint identity grants invocation access only. Git also requires its gateway
`allow_forwarded_identity = true` to accept token-free fingerprint identity;
all gateways enforce supplied caller authentication regardless of that opt-in.
Explicit invalid Basic credentials never fall back to forwarding.

### Protected fields and audit

Broker rejects protected fields nominated by `Connection` and protected names in
trailer declarations before admission. The protected set includes `Authorization`,
configured principal credential carriers, `X-Agent-Access-User`,
`X-Agent-Access-Caller-Authorization`, `X-AW-Identity-Token-SHA256`, and
`X-Agent-Access-Context`. MCP rejects all trailer declarations and actual trailer
frames, including undeclared ones, and consumes the complete bounded request body
before dispatch. No trailer becomes identity. The user header is reserved from
identity-source and browser CSRF header configuration.

Caller ID is recorded separately from principal identity source. Username identity
uses source name/kind `trusted_user`, header `x-agent-access-user`, scheme
`asserted`, class `agent_invoke`, and no token ID. Successful access records include
the namespace and opaque binding ID. Ordinary tokens retain their token provenance.
Caller trust does not confer client-address trust; `network.trusted_proxies` is
independent. Logs and denial bodies do not expose caller secrets, fingerprints,
raw failed usernames or private session proofs.

## Integration requirements

Broker has no build dependency on an ingress product. An attester must implement
the selected credential transport, exact subject contract, context mode and
approved-destination restrictions. A basic reverse proxy does not establish
identity merely by forwarding requests. Its ordinary Broker-token and browser
traffic can remain independent of identity attestation.

For username mode, the trusted launcher derives and controls the user assertion.
For fingerprint mode, ingress verifies possession of the registered identity
bearer and forwards its fingerprint; the fingerprint alone is not proof of
possession. Keep the raw bearer outside workloads. See
[managed identity](managed-identity.md) for inventory and rotation.

Authenticate the transport with verified HTTPS or an equivalent trusted local
transport. Remove untrusted protected assertions before generating verified ones;
verify duplicate and trailer handling in the selected ingress implementation.
Never forward the protected pair to arbitrary destinations or replay it across
redirects. Broker's validation does not establish those upstream protections.
Configure both aggregate and service MCP destinations explicitly where needed.

## HTTP failures before provider dispatch

Broker reserves service ID `broker` against provider, imported-service and Git
registration. Designated admission responses prove that provider dispatch did not
occur. The JSON envelope has the valid `agentRequestId`, a UUID v4
`brokerRequestId`, `service: "broker"`, empty `resourceScopes`, an error, and no
result. The reserved combinations are:

| Action | Reason | HTTP | Decision | Retry |
| --- | --- | --- | --- | --- |
| `identity.authenticate` | `identity_assertion_invalid`, `identity_assertion_unsupported` | 400 | `deny` | No |
| `caller.authenticate` | `caller_authentication_required`, `caller_authentication_invalid` | 401 | `deny` | No |
| `caller.authenticate` | `caller_user_assertion_denied`, `caller_identity_forwarding_denied`, `execution_context_required`, `execution_context_invalid`, `execution_context_denied` | 403 | `deny` | No |
| `identity.authenticate` | `identity_assertion_denied` | 403 | `deny` | No |
| `identity.authenticate` | `identity_required`, `identity_invalid`, `broker_token_not_found`, `broker_token_expired`, `broker_token_paused`, `broker_token_revoked` | 401 | `deny` | No |
| `identity.authenticate` | `principal_required`, `principal_disabled` | 403 | `deny` | No |
| `context.authorize` | `execution_context_denied`, `broker_token_class_denied` | 403 | `deny` | No |
| `request.admit` | `rate_limited`, `concurrency_limited` | 429 | `error` | Yes |
| `request.admit` | `identity_unavailable`, `audit_unavailable` | 503 | `error` | Yes |

Username denials deliberately conceal whether the binding, human or pause gate
caused rejection. Fingerprint failures retain their existing 401 `identity_invalid`
behavior; principal-disabled behavior retains its existing tuple. Mandatory audit
failure may supersede the original denial.

Before MCP protocol dispatch, username failures use this JSON envelope at the
outer HTTP status, `Cache-Control: no-store`, and a 401 Bearer challenge with realm
`agent-access-broker`. No JSON-RPC ID is invented. A tool request rejected at final
admission returns the same envelope inside an HTTP 200 MCP error tool result,
using negotiated JSON/SSE framing. Discovery/control failures use the outer status.
A valid identity with a mismatched session owner retains the invalid-session
response; authenticated GET remains 405. Git uses its reason headers and protocol
body instead of JSON.

Consumers must check the entire combination and correlation. Provider outcomes
and post-execution audit failures never gain a nonapplication guarantee from these
tuples. Terminal admission denials are not automatically retryable. A later denied
attempt cannot resolve an earlier uncertain write.
