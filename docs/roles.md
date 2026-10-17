# Account roles and self-service

Each managed account has exactly one `role`: `user`, `auditor`,
`service_policy_manager`, or `admin`. The independent boolean
`selfServiceEnabled` controls personal management. Human accounts default to
`user` with self-service enabled. Roles do not grant service invocation access;
invocation grants, token restrictions, and upstream credentials still apply.

| Role | Administrative reads | Administrative changes |
| --- | --- | --- |
| `user` | None | None |
| `auditor` | All administration metadata, policy, configuration status, and global audit | None |
| `service_policy_manager` | Policy and audit for directly assigned services | Grants for those services |
| `admin` | All | All |

Auditors can inspect safe policy previews, effective access, import previews,
and policy exports. Secret reveals, identity-token reveals, credential
verification, import discovery, and every administrative mutation require an
administrator. Metadata never includes stored plaintext secrets. Read access
and write access use distinct authorization scopes throughout the control plane.

Self-service permits personal token, credential, connection, and activity
operations under their individual authorization rules. Personal OAuth
connect/reconnect requires a credential connection with OAuth and a matching
active `per_user` action grant on a service that uses it, for the user or their
current groups; separate credential rights
are not used. The owner can inspect and disconnect an existing bound connection
after grant loss. See [OAuth setup](administrator-guide.md#enable-personal-oauth-connections). Disabling it
hides the entire **My access** space, its tabs, shortcuts, and background queries,
and rejects direct personal API requests with HTTP 403 `self_service_disabled`.
Login, logout, password management, and essential **Account** settings remain.
A plain user without self-service lands on Account. Administrative views of
other accounts, or an administrator's own account, remain governed by the role.
Existing invocation tokens, stored credentials, and OAuth refresh continue to
work for authorized invocation. Disabling self-service does not revoke them.

## Assign service policy managers

Set the account's role to `service_policy_manager`, then assign one or more
configured services directly to that account. Groups have no manager attribute
and cannot hold policy-management assignments. Ordinary group membership and
group invocation grants are unchanged.

```bash
agent-access admin principals access set alice --role service_policy_manager
agent-access admin policy managers grant --service jira --principal alice
agent-access admin policy managers grant --service gitlab --principal alice
```

Assignments allow managing all grants for each assigned service, including
grants for the manager themselves, but do not grant invocation or credential
access. Changing away from this role atomically removes the assignments.
Disabling the account preserves them for re-enablement. Assignments to services
removed from configuration remain dormant. A manager with no active services
has an empty management view.

## Change account access

Use the account's access controls in the portal, or:

```bash
agent-access admin principals access set reviewer --role auditor
agent-access admin principals access set reviewer --self-service-enabled false
```

The corresponding endpoint is
`PATCH /v1/admin/principals/{principal}/access`. Its JSON body accepts `role`
and/or `selfServiceEnabled`. At least one field is required; null and unknown
fields are rejected. Omitted fields stay unchanged. Principal and browser
session responses always expose singular `role` and `selfServiceEnabled`.

A real role change revokes all of the account's `admin` tokens, including a token
used for the change itself. This prevents a previously issued auditor token from
acquiring write authority after promotion. An unchanged patch or a flag-only
change does not revoke those tokens. The last active human administrator cannot
be demoted or disabled. Audit completion records previous and new access,
removed service assignments, and revoked admin-token IDs. Admission uses current
authority on each request; a write already admitted before a role change may
finish.

## Credential classes

Browser sessions use the account role for administration and the flag for
self-service. An `admin` bearer may be issued to a human administrator or auditor;
the holder's current role limits its powers and it cannot call personal routes.
A `user_manage` bearer supports personal routes when self-service is enabled,
global policy/audit reads for admins and auditors, and scoped policy reads/writes
for managers. It does not open general administrator metadata or mutation
routes, the global policy export, manager-assignment listing, or
`visibility=all` runtime specs; use an authorized `admin` bearer or browser
session for those administrative reads. Admins may also write policy with a
`user_manage` bearer.
`agent_invoke` tokens and forwarded identities cannot manage the broker.
Configured classless operator/recovery identities retain their existing explicit
configuration boundaries.

Human accounts may hold any role. `system` principals support `user` or
`service_policy_manager`, with self-service enabled by default, but cannot use
browser login or global administrative roles. A `service_account` is always
`user` with self-service disabled and cannot receive management tokens.

For authorized administrators and auditors, runtime specs with `visibility=all`
include provider and personal route documentation. Administrative write routes
remain filtered by actual write authority. This option grants no execution
permission.

## Database operations

For supported schema upgrades, assignment preconditions, and preservation of
account data, see [database account authority](database.md#admin-roles-and-browser-login-state).
Back up the managed database and encryption keys before upgrading; see
[backup and recovery](database.md#backup-and-recovery).

## Delegating narrow Broker operations

Only an administrator can author grants for `broker_management`. Service policy
manager assignment cannot select that service, and service policy managers cannot
edit its grants. A caller's ordinary invocation grant authorizes only its selected
complete principal/group/grant/connection tuples. It does not confer portal or
management-API authority. See [delegated administration](broker-management.md).
