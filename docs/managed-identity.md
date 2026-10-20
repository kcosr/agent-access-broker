# Managed workspace identity

A named [trusted caller](trusted-callers.md) can attest a managed human without
issuing that human a Broker invocation token. Broker supports exact username
bindings on HTTP MCP and registered identity fingerprints on the existing HTTP,
MCP and Git invocation surfaces. Both apply the human's current grants, groups,
credentials, execution context and principal quotas. Neither grants browser login,
personal management or administration, even when the mapped human is an admin.
Administrators can disable each path or make it read-only independently; see
[access path controls](#access-path-controls).

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

Bindings have immutable server-assigned IDs, names and namespaces. Each binding
has its own **Enabled** and **Read-only** settings. Disable one to suspend it
while reserving the name; a disabled binding is denied like an unknown name.
Rename or reassign by deleting and creating a binding; the new record receives a
new ID. Removing a namespace from caller configuration preserves its bindings as
unavailable. Creation accepts only currently configured namespaces and creates an
enabled binding, read-only only when requested. Users cannot enroll themselves.

The administrator's principal view separates **Identity access**, the **Access
paths** table and **Identity token** secret management. Auditors can inspect
metadata; administrators can change it. Management uses a normal admin credential
or browser session, with CSRF on cookie-authenticated writes. For example:

```sh
agent-access admin principals identity-bindings list alice
agent-access admin principals identity-bindings create alice --namespace managed_workspace --username alice
agent-access admin principals identity-bindings create alice --namespace managed_workspace --username alice-review --read-only
agent-access admin principals identity-bindings update alice BINDING_ID --read-only true --expected-version 1
agent-access admin principals identity-bindings update alice BINDING_ID --enabled false --expected-version 2
agent-access admin principals identity-bindings delete alice BINDING_ID --expected-version 3
```

`update` takes at least one of `--enabled BOOL` and `--read-only BOOL`. Use the
ID and version returned by the last read or write. Duplicate names and stale
versions return distinguishable conflict errors; refresh state before making a
new administrative decision. Metadata includes whether each namespace is
available and the configured namespace/credential-transport choices, never
caller credentials. See [management API](http-api.md#administrator-identity-access-and-bindings).

## Access path controls

A human can reach Broker without a Broker token through two trusted-identity
paths: the identity token (one per human, usable on HTTP, MCP and Git) and each
username binding (any number, HTTP MCP only). Each path has its own controls:

| Level | Control | Effect |
| --- | --- | --- |
| Person | **Pause identity access** | Stops every trusted-identity path of the person |
| Each username binding | **Enabled** | A disabled binding is denied like an unknown name and keeps the name reserved |
| Each username binding | **Read-only** | That binding can use only actions classified as reads |
| Identity token | **Enabled** | A disabled token is denied like an unknown fingerprint and keeps its secret |
| Identity token | **Read-only** | Fingerprint access can use only actions classified as reads |

New paths are enabled and not read-only until an administrator changes them.
Upgrading keeps each existing binding's Enabled setting, enables existing
identity tokens and leaves every path not read-only. There is no person-level
read-only setting and no write-only mode.

### Read-only paths

A request admitted through a read-only path may use an action only when its
existing grants, caveats, execution context, resources and credentials permit it
**and** the action's current runtime catalog descriptor has `readOnly: true`. An
action without a descriptor, or one whose I/O this host does not serve, counts as
a write. Read-only is a ceiling checked on every request against the current
classification, not a stored list of actions:

- **Grants still decide.** The check runs per action before grant selection and
  removes no grant. A permitted read selects the same grant, credential mode and
  resource clauses as on a full-access path, so a higher-precedence grant that
  also covers writes still wins for the read.
- **Classification is reviewed.** Backend actions are writes unless the backend
  explicitly classifies them as reads. Imported MCP, OpenAPI and command actions
  are writes until an administrator selects Read-only during import review;
  upstream hints never count. Unreviewed imported actions are therefore hidden
  from read-only paths. Reclassifying an action takes effect on every read-only
  path for requests admitted after the change is published; see
  [classification review](imported-services.md#classification-and-read-only-identity-access).
- **Discovery shows only reads.** HTTP MCP `tools/list` (aggregate and
  `/mcp/{service}`), the five discovery helpers, `/v1/spec/catalog`, OpenAPI, the
  send schema, `/v1/services*`, `/v1/capabilities`, `/v1/me` service limits and
  resource discovery omit write actions. A service with no remaining actions
  disappears, and its `/mcp/{service}` view returns 404. The five fixed MCP
  discovery helpers remain and report only the filtered catalog. Aggregate
  tool-name conflicts are checked among the caller's visible actions, so a read
  tool omitted for a conflict with a write can appear on a read-only path.
- **Writes are refused before any upstream work.** REST invoke, JSON send,
  multipart uploads and downloads return 403 `service_action_denied` with reason
  `identity access is read-only`, before credential lookup, OAuth leasing, scope
  resolution or provider dispatch. An HTTP MCP call to a hidden write tool fails
  as an unknown or unavailable tool (`invalid_params`). Git fetch works; push is
  refused at receive-pack discovery and at the receive-pack POST before its body
  is read. Every resumed continuation names an action and passes the same check.
- **Local output is unaffected.** Read-only governs upstream effects only. CLI
  and stdio MCP local output destinations keep their ordinary behavior.

Agents can tell that a connection is read-only. HTTP MCP `initialize` and
`server/discover` append "This connection is read-only: only actions classified
as reads are listed or executable." to the server instructions, on aggregate and
service-specific endpoints. `GET /v1/me`, `/v1/capabilities` and the caller
catalog's identity report `readOnlyAccess` for an attested identity; only the
fingerprint path can use those REST routes. Invocation audit records
`identitySource.readOnlyAccess` for attested identities, and a read-only denial
records `{"identityAccess":{"readOnly":true,"requestedService":…,"requestedAction":…}}`
with no fingerprint, username, token ID, grant or credential mode. Git denials
keep the classified repository scope; invoke denials record no resource scopes.

### Paths, not people

The controls limit an access path, not the person. Browser sign-in and issued
Broker tokens keep the person's full grants, whatever their paths' settings.
Without `X-Agent-Access-User`, an explicit Broker token sent alongside a
fingerprint keeps precedence, so the token's authority applies rather than the
identity token's settings. With the user header, competing credentials are
rejected as usual. Pause is the only person-level control.

### Changing a setting

Changing **Enabled** or **Read-only** advances that binding's version or the
identity token's revision once and ends the path's open MCP sessions at their
next request; clients initialize a new session. An update that changes nothing
stores nothing, advances nothing and ends no session; it is still audited, with
the same settings before and after. Restoring an earlier value
does not revive old sessions. Identity-token changes leave username sessions
intact, and binding changes leave fingerprint sessions intact. Resource discovery
cursors bind the read-only setting, so a cursor issued under the other setting is
rejected; repeat the listing without it. A change takes effect for requests
admitted after it commits; it does not cancel operations already admitted.

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
| Make one username binding read-only | That binding reads only | Unchanged | Unchanged | Unchanged |
| Disable identity token | Unchanged | Denied, secret kept | Unchanged | Unchanged |
| Make identity token read-only | Unchanged | Reads only | Unchanged | Unchanged |
| Remove identity-token inventory | Unchanged | Denied | Unchanged | Unchanged |
| Pause/revoke one issued token | Unchanged | Unchanged | That token denied | Unchanged |
| Disable principal | Denied | Denied | Denied | Disabled-user behavior |

Identity inventory changes preserve the gate and bindings. Username access works
without inventory. Pause leaves each path's Enabled and Read-only settings in
place, so resuming restores them as they were. Broker identity-access pause
affects Broker admission only; other services that authorize the person
independently need their own controls.

## Identity-token inventory

Broker-generated identity tokens are random lowercase hyphenated UUID v4 values.
Administrators can import existing bearers of 32–4096 ASCII HTTP token characters.
Input is exact: no whitespace or trailing newline is stripped. Broker stores the
recoverable value encrypted and a unique SHA-256 fingerprint for lookup. Ingress
verifies possession of the original bearer and forwards only its fingerprint;
a fingerprint alone is not proof of possession. The raw identity bearer is not a
normal Broker access token.

Every human has exactly one identity-token record, created with the principal in
the same transaction. A record without a secret is not configured. Its metadata
is `{principalId, configured, enabled, readOnly, revision, updatedAt}`; the
fingerprint, ciphertext and plaintext never appear in ordinary reads.

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
agent-access admin principals identity-token update alice --read-only true --expected-revision 3
agent-access admin principals identity-token update alice --enabled false --expected-revision 4
```

There is no literal secret argument for import. Global `--token-file` separately
authenticates the administrator. Inventory revision advances on every set,
generation, removal or settings change. `update` takes at least one of
`--enabled BOOL` and `--read-only BOOL` and the revision from the last read; a
stale revision is a version conflict. Setting, generating, replacing and removing
the secret keep the Enabled and Read-only settings. A disabled token keeps its
secret: reveal, replace, generate and remove still work, and enabling it again
restores access with the same secret. Removing/replacing inventory or changing a
setting invalidates the fingerprint's MCP sessions; it leaves username sessions
and shared pause unchanged.

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
reload preserves them. Database binding, identity-token and gate changes take
effect at final admission without reload. See [session lifetime](mcp.md#trusted-identity-and-session-lifetime).

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
for the managed-store migrations. They preserve existing pauses, create no
username bindings, keep each binding's Enabled setting, enable identity tokens,
leave every path not read-only, add a
not-configured identity-token record for each human without one, and require a
pre-upgrade backup for rollback.
