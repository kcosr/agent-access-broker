# Managed workspace identity

A named [trusted caller](trusted-callers.md) can attest a managed human without
issuing that human a Broker invocation token. Broker supports exact username
bindings on HTTP MCP and registered identity fingerprints on the existing HTTP,
MCP and Git invocation surfaces. Both apply the human's current grants, groups,
credentials, execution context and principal quotas. Neither grants browser login,
personal management or administration, even when the mapped human is an admin.

The caller credential authenticates the attester, not the human. The attester must
control the asserted identity and protect its credential from workload access or
redirection. These contracts are independent of any particular ingress product.
Ordinary Broker-token and browser access remain separate.

## Username bindings

A username caller selects one operator-configured namespace. An administrator
binds the exact `(namespace, username)` pair to an existing human principal.
There is no automatic provisioning, principal-ID shortcut, email or OS lookup.
Names are case-sensitive 1–128 ASCII bytes from `[A-Za-z0-9._@+-]`; numeric-looking
values are names. `Alice` and `alice` are distinct. A human may have several
bindings; every alias shares that principal's quotas and policy.

Bindings have immutable server-assigned IDs, names and namespaces. Disable one
to suspend it while reserving the name. Rename or reassign by deleting and
creating a binding; the new record receives a new ID. Removing a namespace from
caller configuration preserves its bindings as unavailable. Creation accepts only
currently configured namespaces. Users cannot enroll themselves.

The administrator's principal view separates **Identity access**, username
bindings and **Identity token** inventory. Auditors can inspect metadata;
administrators can change it. Management uses a normal admin credential or browser
session, with CSRF on cookie-authenticated writes. For example:

```sh
agent-access admin principals identity-bindings list alice
agent-access admin principals identity-bindings create alice --namespace managed_workspace --username alice
agent-access admin principals identity-bindings disable alice BINDING_ID --expected-version 1
agent-access admin principals identity-bindings enable alice BINDING_ID --expected-version 2
agent-access admin principals identity-bindings delete alice BINDING_ID --expected-version 3
```

Use the ID and version returned by the last read or write. Duplicate names and
stale versions return distinguishable conflict errors; refresh state before
making a new administrative decision. Metadata includes whether each namespace
is available and the configured namespace/credential-transport choices, never
caller credentials. See [management API](http-api.md#administrator-identity-access-and-bindings).

## Shared identity access

Every managed human has one identity-access gate with a unique incarnation,
positive version and pause state. **Pause identity access** blocks both trusted
username and fingerprint access without disabling sign-in or independently issued
Broker tokens. **Resume identity access** requires a new MCP initialization;
old sessions do not regain authority. Principal disable blocks the principal's
identity methods. A pause does not cancel operations already admitted.

```sh
agent-access admin principals identity-access inspect alice
agent-access admin principals identity-access pause alice --expected-version 1
agent-access admin principals identity-access resume alice --expected-version 2
```

| Administrative action | Username access | Fingerprint access | Issued Broker tokens | Browser sign-in |
| --- | --- | --- | --- | --- |
| Pause identity access | Denied | Denied | Unchanged | Unchanged |
| Disable one username binding | That binding denied | Unchanged | Unchanged | Unchanged |
| Remove identity-token inventory | Unchanged | Denied | Unchanged | Unchanged |
| Pause/revoke one issued token | Unchanged | Unchanged | That token denied | Unchanged |
| Disable principal | Denied | Denied | Denied | Disabled-user behavior |

Identity inventory changes preserve the gate and bindings. Username access works
without inventory. Broker identity-access pause affects Broker admission only;
other services that authorize the person independently need their own controls.

## Identity-token inventory

Broker-generated identity tokens are random lowercase hyphenated UUID v4 values.
Administrators can import existing bearers of 32–4096 ASCII HTTP token characters.
Input is exact: no whitespace or trailing newline is stripped. Broker stores the
recoverable value encrypted and a unique SHA-256 fingerprint for lookup. Ingress
verifies possession of the original bearer and forwards only its fingerprint;
a fingerprint alone is not proof of possession. The raw identity bearer is not a
normal Broker access token.

The **Identity token** section supports inspect, reveal/copy, import/replace,
generate and remove. Only explicit reveal returns plaintext; ordinary reads and
generation return metadata. Users cannot manage their own inventory through
personal routes. New human users receive generated inventory at creation when
encryption is configured, including manual, bootstrap and OIDC provisioning.
Existing users need explicit import or generation, and login never recreates
removed inventory. A configured managed store requires credential encryption.

```sh
agent-access admin principals identity-token inspect alice
agent-access admin principals identity-token set alice --identity-token-file /secure/identity-token
agent-access admin principals identity-token set alice --identity-token-stdin < /secure/identity-token
agent-access admin principals identity-token reveal alice
agent-access admin principals identity-token generate alice
agent-access admin principals identity-token remove alice
```

There is no literal secret argument for import. Global `--token-file` separately
authenticates the administrator. Inventory revision advances on every set,
generation or removal. Removing/replacing inventory invalidates the old fingerprint
and its MCP sessions; it leaves username sessions and shared pause unchanged.

Broker access tokens use the `aab_ai_`, `aab_um_` or `aab_ad_` prefixes and are
separate credentials. Without `X-Agent-Access-User`, an explicit Broker token
retains precedence over fingerprint identity, including failure for an invalid
token. With the user header, username mode is selected and competing principal
credentials are rejected. Privileges from two identities are never combined.

## Trusted caller setup

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
allowed_execution_contexts = ["workstation"]
allow_forwarded_identity = true
```

Direct username clients send `Authorization: Bearer <caller credential>` and
`X-Agent-Access-User: alice` on every `/mcp` or `/mcp/{service}` request. They omit
context because Broker fixes it. Relayed username requests send the dedicated
`X-Agent-Access-Caller-Authorization` instead, with the same user field and the
approved context for an asserted caller. The namespace is never requester-chosen.
Only HTTP MCP accepts username identity; REST, local stdio's REST transport, Git,
management, browser and health routes reject the user header.

Fingerprint requests use the dedicated caller header and
`X-AW-Identity-Token-SHA256: sha256:<64 lowercase hexadecimal digits>`, with context
only for an asserted caller. `allow_forwarded_identity` is the fingerprint
capability; namespace presence is the separate username capability. Each request
uses only one assertion representation. Git additionally requires its gateway's
`allow_forwarded_identity = true` for token-free fingerprint admission.

Protect the transport with verified HTTPS or an equivalent trusted local channel.
The attester must derive identity from its trusted source, replace untrusted
assertions, constrain destinations, and protect credentials from workload access.
Broker rejects protected `Connection` nominations and trailer declarations; HTTP
MCP rejects every declaration and actual trailer frame before provider dispatch.
See [trusted callers](trusted-callers.md) for parsing, contexts and failure framing.

## Deployment and rotation

Provision bindings explicitly before enabling username clients. For fingerprint
identity, coordinate the inventory bearer with the infrastructure that provisions
and verifies it. Inventory changes do not distribute secrets, update ingress
records or restart workloads. Verify new identities are admitted and retired
ones are denied using the selected invocation surface.

Caller rotation requires replacing its loaded secret and reloading Broker, then
updating the attester. Changes to caller security contracts invalidate attested
MCP sessions, even if a later reload restores an earlier credential. An unchanged
reload preserves them. Database binding/gate changes take effect at final
admission without reload. See [session lifetime](mcp.md#trusted-identity-and-session-lifetime).

Client-address forwarding remains separately controlled by
`network.trusted_proxies`. Ordinary clients without trusted assertions retain the
configured direct default context and normal authentication.

CLI/local stdio clients behind fingerprint-aware ingress can omit Broker-token
configuration. Use `--no-token` or `AGENT_ACCESS_NO_TOKEN=true` to suppress inherited
tokens. These options do not configure username authentication. Git likewise uses
no dummy token for fingerprint identity; an empty URL-scoped `credential.helper`
can suppress unrelated inherited credentials. Ordinary Broker-token Git helpers
remain supported.

Follow the [upgrade and rollback runbook](operator-guide.md#upgrade-and-rollback)
for the managed-store migration. It preserves existing pauses, creates no username
bindings, and requires a pre-upgrade backup for rollback.
