# Temporary secret references

The Broker can retain newly issued provider secrets and return references that
can be used without exposing plaintext to an agent. The provider SDK declares
which outputs are transferable secrets; ordinary sensitive payloads are not
captured automatically. GitLab project access-token and service-account token
creation and rotation use this contract.

## Delivery and lifetime

`[secret_outputs] mode = "reference"` is the default. A designated output such
as `result.issuedToken` contains:

```json
{
  "secretRef": "sr_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
  "expiresAt": "2026-01-01T16:00:00Z"
}
```

The reference is sensitive. Keep it out of logs and unrelated messages. HTTP
responses use `Cache-Control: no-store`; CLI output receipts continue to mask
sensitive fields. Reference mode applies to HTTP, native HTTP MCP, stdio MCP,
`invoke`, `send`, and typed CLI commands. A caller cannot request plaintext.
Storage or encryption failures never fall back to raw output.

Operators may set `mode = "raw"` for scripts that intentionally receive the new
secret. The same output is then a string. Discovery advertises the configured
`secretOutputMode`, `secretOutputs`, and `secretInputPointers` beside the existing
sensitivity markers. OpenAPI, send schema, and MCP metadata carry the equivalent
extensions. Execution credentials already held by the Broker are never exported. Switching
to raw output mode does not invalidate unexpired references created earlier;
authorized consumers may still resolve them until their stored deadline.

References expire four hours after reservation by default. For an asynchronous
administrator handoff, operators can configure up to 24 hours; plan installation
within the displayed deadline rather than relying on an overnight renewal. The deadline is fixed;
reads, imports, reconnects, and unrelated activity do not extend it. A reference
cannot be used after its originating identity or Broker token loses validity.
Expiration removes the temporary encrypted copy. It does not revoke the upstream
token or remove credentials already installed in a connection.

Store a newly issued token in its destination connection before doing unrelated
work. Do not issue or rotate another token merely because a reference expired.
GitLab returns the new plaintext only once; use the original safe token metadata
to inspect and reconcile its upstream state.

## Install into a credential connection

Retrieve the project member's username separately using the token response's
`accessToken.userId`:

```bash
agent-access gitlab project member view team/project 12345
```

`project.member.view` reads a direct member of that project and needs its own
repository-scoped read grant. A failed username read does not repeat token
issuance. It may be retried independently.

An administrator can install a held reference into an explicitly named
principal's configured connection:

```bash
agent-access admin credentials put review-service gitlab \
  --field-ref token=sr_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG \
  --field username=project_42_bot_example
```

For a bearer-token connection, omit the username. Personal self-service uses
`agent-access credentials put <connection> --field-ref token=...` and requires
the existing credential-management authority. It can import only references
owned by that same principal. Administrator import requires full administrator
credential-write authority; auditors and service policy managers cannot use it.
The reference alone grants no management authority. Canonical Broker handles
are rejected in literal credential fields and metadata, including when embedded
in longer text; use `--field-ref` or the structured object below.

The existing connection credential PUT endpoints accept the same field:

```json
{
  "secret": {
    "username": "project_42_bot_example",
    "token": {
      "secretRef": "sr_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
    }
  }
}
```

The entire output reference object may be copied, including `expiresAt`. That
field is informational; the Broker always checks its stored expiry. Unknown
reference-object fields are rejected. Only the token field accepts a reference;
usernames and metadata do not. Profile selection, owner status, and management
permissions remain enforced. A concurrent configuration or policy publication can
return HTTP 409 `version_conflict` before installation. Retry the credential PUT
against the current configuration while the reference remains valid; do not repeat
the upstream issuance. This publication check also applies to literal token PUTs.

Resolution and credential installation occur in one managed-store transaction.
The CLI never receives the resolved token. A successful import does not consume
the reference: an authorized administrator can install the same value into more
than one destination before expiry. Audit records identify the actor, origin,
destination, and non-capability receipt, without recording the token or reference.

`--token-output` on typed GitLab issuance commands requires advertised raw mode.
In reference mode it refuses before issuing. If a configuration reload changes
mode after that check, the CLI preserves the returned reference and metadata;
it does not repeat the operation.

## Ordinary action inputs and ownership

Native providers can designate string payload fields as reference-capable. Those
fields accept their ordinary literal value or a reference object in the same
position. The runtime authorizes the consuming action and resources before
resolution, then validates the resolved string against the original field schema.
Invocation audit records carry host-owned `providerAudit.secretInputs` entries
containing only the declared `pointer` and `kind` (`reference`, `literal`, or
`absent`). The Broker captures these categories before resolving references and
keeps them through denied and completed outcomes. Native and imported receivers
use the same metadata; it contains no handle, envelope, value length or fingerprint.
Secret fields cannot determine resource scope. Objects containing a Broker-shaped
`secretRef` capability are rejected in undeclared positions. Ordinary upstream
fields such as Kubernetes `secretRef: {name: "db"}` remain valid. A Broker
capability (`sr_` followed by the canonical base64url encoding of 32 bytes) is
rejected anywhere in action inputs, including object keys, nested objects,
arrays and undeclared payload fields. This also rejects a capability embedded
in text such as `Bearer sr_...` or `TOKEN=sr_...`. Pass it only as the `secretRef`
member of a strict reference object at a declared secret input, so it cannot be
forwarded upstream as a literal string. Recognition requires boundaries outside
the base64url alphabet on both sides, preserving ordinary continuation tokens,
JWTs, and longer encoded values that happen to contain the same character pattern.

Ordinary invocation use requires the same principal, original Broker token or
exact trusted-human identity binding, trusted caller contract, and execution
context. Another token for the same principal is insufficient. A new MCP session
can use the reference when those bindings still match. Managed `agent_invoke`
tokens and trusted username/fingerprint identities are supported origins;
anonymous and static configuration tokens cannot issue references and do not see
secret-producing actions in reference-mode caller discovery. The administrative
catalog still describes configured actions.

Current origin validity is checked on each use. Token revocation, pause or expiry,
principal disable, and identity-binding changes deny access. Trusted caller
contract generations persist across restarts. An observed rotation or removal
followed by restoration cannot revive earlier references. Caller generations change only when a validated runtime is activated; a rejected
reload preserves the active runtime and its references.

The administrator/personal credential import described above is a narrow handoff
exception to ordinary credential and context matching. It still checks the
origin's current validity. It is not a general secret-reveal API.

## Storage and failures

Reference-capable actions require a managed SQLite store and credential encryption.
GitLab declares its issuance actions even when provisioning is disabled, so any
configured GitLab service needs this storage or explicit `mode = "raw"`.
Capacity for declared maximum output bytes and reference counts is reserved
before dispatch. Configuration defaults are:

```toml
[secret_outputs]
mode = "reference"
ttl_seconds = 14400
max_refs_per_principal = 100
max_refs_total = 10000
max_bytes_per_principal = 1048576
max_bytes_total = 67108864
receipt_retention_seconds = 604800
max_receipts_total = 100000
```

TTL must be positive, no greater than 24 hours, and in reference mode strictly
longer than both `limits.request_timeout_ms` and `mcp.operation_timeout_ms`.
This keeps the configured producer budget shorter than the reservation lifetime.
Receipt retention is bounded to
30 days. Per-principal limits cannot exceed global limits. Each principal can also retain
at most ten times `max_refs_per_principal` outcome receipts (1,000 by default),
bounded by the global receipt limit. Failed or expired operations still occupy
receipt capacity until their retention deadline. This can refuse new issuance
even when no active references remain. Reference admission
fails before dispatch when capacity, identity, encryption, or storage checks fail.

Actions declaring secret outputs use `mcp.operation_timeout_ms` as a total
producer budget on every transport, in both reference and raw modes.
The budget starts at governed invocation entry and includes audit admission,
scope and credential preparation, and all sequential provider calls. An earlier
incoming deadline takes precedence; later invocation phases do not reset it.

Capture runs after a provider outcome is available and before output formatting.
Protected capture and durable outcome finalization, including completion audit,
run outside producer cancellation, preserving an already completed outcome at
its deadline.
A capture failure after issuance preserves safe outcome metadata and reports
`retrySafe: false`; it never returns the plaintext. A timeout or interruption can
leave the upstream outcome unknown. Request IDs are correlation values, not
idempotency keys. Never automatically repeat issuance after these failures.

The store retains bounded non-secret outcome receipts after temporary material
expires. Receipts contain allowlisted completion flags and provider-declared safe
object identifiers, not arbitrary result or audit payloads. At the store boundary,
invalid optional receipt metadata is replaced with
`executionState: "completed"`, `retrySafe: false` and `metadataOmitted: true`,
while valid secret capture still commits and returns references. This applies to
non-object metadata, metadata exceeding 16 KiB of serialized JSON, and metadata
containing a Broker capability or captured secret. Invalid output contracts and
storage, encryption or expiry failures still fail capture.

A lost response can still lose its usable reference; retained metadata
does not recreate an upstream one-time secret. Database failure can also prevent
recording completion, and the Broker cannot atomically commit a local row and a
remote GitLab mutation.

At cold startup, abandoned reservations become unknown outcomes with
`retrySafe: false`, releasing their count and byte reservations. Reload preserves
in-flight reservations. Cleanup also runs periodically. Every use checks expiry independently
of cleanup timing. Retained ciphertext participates in key readiness, used-key
inventory, and credential rewrap. Backups contain encrypted temporary material
and should receive the same protection as other managed credentials. The public
`sr_` reference is distinct from private managed `sqlite:` storage pointers and
configuration `env:`/`file:` references.

See [provider SDK](provider-sdk.md) for declaration and sidecar contracts,
[GitLab provisioning](gitlab-bot-provisioning.md) for upstream behavior, and
[database operations](database.md) for migration and key handling.

## Delegated local handoffs

[Broker administration](broker-management.md) adds a reference-only
`credential.install` sink. The caller must own the reference under its exact
invocation authentication, caller and context. Full principal/connection
authorization precedes reference lookup. Origin validation and absent-slot
installation share one transaction; no plaintext reaches an SDK provider.

Its `token.create` action commits the child invocation-token row, encrypted
reference and capture receipt together. Delivery is always by reference and
creation is unavailable when global output mode is raw. Existing references can
still be installed in raw mode. A token's own expiry is independent of reference
expiry; losing the reference cannot be repaired by reading token metadata.
