# Delegated Broker administration

`broker_management` exposes narrow local administration actions through ordinary
Broker invocation: HTTP, MCP, `agent-access invoke`, and JSON `send`. It is always
registered by core, has no upstream endpoint or execution credential, and starts
with no grants. It requires managed identity and managed policy. An administrator
authors its grants; service policy managers cannot delegate Broker administration.

The actions operate on service accounts, identity-group membership, direct grant
subjects, encrypted credential slots, and bounded invocation tokens. They do not
provide a directory, arbitrary grant editing, credential reveal, token revocation,
role changes, or an administrative-session substitute. The existing management
API and portal retain their own role, token-class, self-service and CSRF checks.

## Actions and exact targets

| Actions | Required scopes | Inputs beyond the target IDs |
| --- | --- | --- |
| `principal.create` | `principal` | Optional `displayName` |
| `principal.view` | `principal` | None |
| `group.view` | `group` | None |
| `group.member.view`, `.add`, `.remove` | `group`, `principal` | None |
| `grant.view` | `grant` | None |
| `grant.subject.view` | `grant`, `principal` | None |
| `grant.subject.add`, `.remove` | `grant`, `principal` | `expectedVersion` |
| `credential.view` | `principal`, `connection` | None |
| `credential.install` | `principal`, `connection` | `token` reference envelope |
| `token.create` | `principal`, `grant` | `expectedVersion`, `tokenId`, `name`, `allowedExecutionContexts`, `ttlSeconds` |
| `token.view` | `principal` | `tokenId` |

Target fields are `principalId`, `groupId`, `grantId`, and `connectionId`.
The corresponding resource types are `broker_principal`, `broker_group`,
`broker_grant`, and `broker_connection`. All four accept only exact selectors.
Resource entry IDs are catalog names; selector values are the actual target IDs.
An exact principal resource can select an absent ID before `principal.create`.
It does not assert existence or reserve that ID.

One grant must cover **every target in every required scope**. Two partial grants
cannot combine into permission for an edge change. A more specific partial grant
does not hide a complete lower-priority grant. Token restrictions independently
cover the same complete tuple. Existing group exclusions, disabled resources,
execution contexts and grant precedence still apply. See [resources](resources.md)
for correlated effective-access clauses and complete-target discovery.

For example, a grant permitting `group.member.add` with exact resources selecting
`review-workers` and `review-worker` authorizes only that group/account pair.
The operation's inputs are:

```json
{"groupId":"review-workers","principalId":"review-worker"}
```

The seven view actions are read-only. Creation, installation, and every edge
change are writes. Inputs reject unknown fields. Results contain fixed safe
metadata, never raw credentials, token hashes, reference ownership proofs, or
full group/grant subject inventories. Reads require their own action permission;
write permission does not imply a reconciliation read.

## Destination restrictions

`principal.create` creates an absent service-account ID with the ordinary user
role and self-service disabled. Existing IDs conflict. Writes cannot target the
invoking principal. Existing account writes require an active service account;
reads can inspect an authorized disabled service account.

Group membership changes cannot target protected groups that confer Broker
administration. Grant-subject changes cannot target Broker-management grants or
inactive grants, and cannot remove an active grant's final subject. Grant edits
use `expectedVersion`; re-read an authorized grant after a version conflict.
Group and grant selection delegates their live authority: later administrator
changes to those objects can change the recipient's effective permissions.
Review a delegation against the combined authority of its selected groups and
grants, including execution contexts and resource selections, for every selected
principal ID, including accounts that have not yet been created.

A direct assignment read distinguishes the direct edge from effective membership.
Repeated group changes report whether they changed the edge. Duplicate or missing
direct grant-subject changes return an input error. `grant.view` returns the grant
contract without its subjects.

## Credential installation

`credential.install` accepts only an envelope such as:

```json
{
  "principalId":"review-worker",
  "connectionId":"gitlab-main",
  "token":{"secretRef":"sr_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
}
```

The example handle is synthetic. Literal token strings are rejected. Optional
`expiresAt` is informational; the stored deadline is authoritative. The originating
invocation identity, authentication, trusted caller and execution context must
still own the reference. The Broker authorizes the complete principal/connection
tuple before checking or decrypting it, then checks origin validity and installs
the encrypted credential in the same transaction.

References produced by `broker_management`, including `token.create`, are rejected
as connection credentials. Their authenticated producer receipt enforces this
boundary. They remain usable by approved secret-input receivers. Successful
installation records safe origin, producer, output pointer and receipt metadata
in `secretReferences` audit evidence, without the bearer or reference handle.

The destination must select the GitLab `gitlab-access-token` bearer-token profile
for service accounts. The slot must be absent; a disabled existing row also
conflicts. Installation does not verify the upstream account or grant permission
to invoke GitLab. All configured consumers of the credential connection can use
it subject to their own grants. Use `credential.view` to reconcile a lost response;
it returns safe slot metadata, not the installed value.

A still-valid reference remains installable after switching output mode to `raw`.
Creating a new reference for this flow requires reference output mode. Expired
references never become usable again.

## Child invocation tokens

`token.create` issues an `agent_invoke` token to an active service account that
currently matches the selected active non-Broker grant, directly or through an
identity group. Select the canonical lowercase UUIDv4 `tokenId` before sending the
request. Existing UUIDs conflict even for revoked tokens or other owners.

The request requires the selected grant's current `expectedVersion`, explicit
allowed execution contexts, and a positive `ttlSeconds` from configured finite
`broker_tokens.admin_agent_invoke_ttl_options`. Absolute expiration, never-expiring
options, and implicit lifetimes are not accepted. The action's discovery schema
lists the configured finite choices.

The token captures the selected service, explicit actions and requested contexts.
Scoped actions retain live selected resource IDs/groups. An empty resource
selection can mint only unscoped actions; it cannot borrow resource authority from
another grant. The token does not pin a grant ID or a credential mode. Every later
invocation still evaluates current policy, resource definitions, grant precedence
and credentials. Later resource/group changes may alter authority inside the
captured service/action/context restrictions.

The token row, encrypted output reference and safe capture receipt commit in one
transaction. The result includes `issuedToken` as a reference envelope and a
separate token `expiresAt`. Token expiry and temporary-reference expiry are
independent. This action is reference-only and unavailable in raw output mode;
metadata continues to advertise reference delivery while unavailable.

`token.view` returns safe metadata for any invocation token owned by the selected
service account, including paused/revoked/expired state. Wrong owner or token class
returns the same not-found result. It cannot redeliver the reference or bearer.
If the reference response is lost, reconcile with `token.view`, revoke through
existing authorized administration, and intentionally issue under a new UUID.
Do not automatically repeat issuance.

## Availability and completion

Discovery checks local prerequisites without contacting upstream systems or
reading target inventories. Availability requirements have a `kind` tag:
`credential` entries include `credentialMode`; `local_runtime` entries do not.
Local reasons are:

| Reason | Resolution |
| --- | --- |
| `managed_identity_required` | Administrator |
| `managed_policy_required` | Administrator |
| `credential_encryption_unavailable` | Administrator |
| `reference_identity_unsupported` | Caller: use supported invocation authentication |
| `token_hashing_unavailable` | Administrator |
| `finite_token_ttl_required` | Administrator |
| `reference_output_required` | Administrator |

All actions need managed identity/policy. Install and token creation additionally
need encrypted managed storage and a reference-capable invocation identity.
Only token creation needs the hashing key, finite TTL choices, and reference
output mode. Missing prerequisites hide affected invocable actions; authorized
management catalog views retain the definitions and explain prerequisites.

The host owns the operation through transaction settlement, policy publication
and completion audit. Cancellation or a stale runtime before the commit gate
prevents dispatch. After that gate, disconnect, timeout and shutdown do not cancel
a transaction whose result is still being established. The final transaction
rechecks the original identity/authentication, current group membership, matched
grant, token restrictions and admitted policy/resource generation.

Write receipts distinguish `not_dispatched`, `not_committed` (verified rollback),
`completed` (known commit), and `unknown`. All carry `retrySafe:false`. MCP delivery
failure uses its existing `execution.completion` vocabulary: a settled rollback
is `completed` with `dispatched:true`, not a successful mutation. Inspect the
operation decision and result. Audit or delivery failure never turns a known
commit into a retryable no-op. Managed state and the audit store are separate;
completion audit is cancellation-safe, not crash-atomic with the database.

Unauthorized tuples uniformly return `service_action_denied` before object
existence/eligibility checks. Authorized missing targets return `resource_not_found`;
occupied destinations use `access_management_target_exists`; ineligible targets
use `access_management_target_ineligible`; stale versions use `version_conflict`.
Reference failures use `access_management_reference_denied` without explaining
which origin check failed. Local prerequisite/storage failures before commit use
`access_management_unavailable`. Fixed messages do not echo secret inputs.

See [secret references](secret-references.md), [GitLab provisioning](gitlab-bot-provisioning.md),
[HTTP](http-api.md), and [MCP](mcp.md) for transport and upstream contracts.
