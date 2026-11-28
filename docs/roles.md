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

Administrators and auditors can inspect a person's OAuth connection status and
nonsecret upstream account metadata, including its display name or email when
the provider supplies one. Only administrators can disconnect it, including when
the person's self-service is disabled. Connecting or reconnecting requires the
person's own consent. Disconnect ends the connection without changing grants or
preventing a later permitted connection. See [administrative OAuth management](oauth.md#administrator-management-api).

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

## Connecting applications

Approving a [registered application](applications.md) is its own permission.
Any enabled human account can approve one whose level is not `none`, with
self-service on or off and whatever its agent-token issuance policy: the
application, not the person, receives the tokens. The person's own list of
connected applications and its removal are likewise not gated by self-service.
Administrators set an access's Enabled and Read-only settings and remove it;
auditors read it; service policy managers have no access to it. An
application's tokens act only within the person's invocation grants.

## Agent token issuance

`agentTokenIssuance` is an administrator-owned object for new personal
`agent_invoke` tokens. It contains a `mode` and an explicit
`allowedExecutionContexts` list. It does not change role, self-service,
invocation grants, or any existing token. New accounts default to
`{"mode":"inherit","allowedExecutionContexts":[]}`; new managed groups default
to `{"mode":"disabled","allowedExecutionContexts":[]}`. An administrator must
permit personal issuance, including for administrator accounts.

| Account mode | Context list | Effect on new personal tokens |
| --- | --- | --- |
| `inherit` (Inherit from groups) | Empty | Resolve active effective group permission separately in each context |
| `disabled` (Disabled) | Empty | Refuse personal issuance regardless of groups |
| `read_only` (Read-only) | Nonempty configured contexts | Require `readOnly: true` in every listed context; all other contexts are disabled |
| `write_capable` (Write-capable) | Nonempty configured contexts | Permit either Boolean in every listed context; all other contexts are disabled |

Groups accept the three modes without `inherit`. Within each context, only groups
that list that context contribute. Their modes combine as Disabled < Read-only <
Write-capable; Disabled does not veto another group's permission. An explicit
account setting replaces group permission completely, including outside its
selected contexts. Disabled groups and expired Microsoft membership evidence do
not contribute; a current local membership can still contribute. Under TOML
identity authority, managed groups contribute nothing and `inherit` resolves to
Disabled. Explicit account overrides still work under either identity or policy
authority; there is no TOML group issuance setting.

For example, a member of an internal Write-capable group and an external Read-only
group can issue a write-capable token for `internal`. A token selecting both
`internal` and `external` must be read-only. Selecting any context without
permission rejects the entire request; Broker never trims or splits it.

```bash
agent-access admin groups create external-readers --agent-token-issuance read_only --agent-token-issuance-context external
agent-access admin groups create internal-writers --agent-token-issuance write_capable --agent-token-issuance-context internal
agent-access admin principals groups add alice external-readers
agent-access admin principals groups add alice internal-writers
agent-access admin principals access set alice --agent-token-issuance inherit
agent-access admin principals access set bob --agent-token-issuance write_capable --agent-token-issuance-context internal
```

These examples require `internal` and `external` in the configured registry.
Repeat `--agent-token-issuance-context` to select more contexts. Enabled modes
require at least one selection; Inherit and Disabled require an empty list.
New registry values never expand saved issuance policies automatically. Context
names are unique, use `[a-z][a-z0-9_-]{0,63}`, and have a maximum of 64 selections.
Saved sets serialize in lexical order; the portal shows choices in configuration
order. Reordering the same set does not change a policy.

Active-account, self-service, personal-management authority, grant, context,
lifetime and resource-reference checks still apply. Eligible `system` principals
use the same rule; service accounts cannot self-issue. An administrator using
`POST /v1/tokens` follows this personal rule. Administrative issuance through
`/v1/admin/principals/{principal}/agent-tokens` or the generic `/tokens` route
uses administrator write authority independently of the owner's issuance mode,
context list, read-only requirement, or self-service flag. Target grants, active
owner, configured contexts, expiry and token-boundary checks still apply. Auditors
and service policy managers cannot use that bypass or change issuance settings.

A read-only token may **Follow current grants**: later reads become usable while
writes remain blocked. `readOnly: false` removes only that extra ceiling; it
creates no grant. Restrictions are immutable; issue a replacement to change them.
Disabling issuance keeps token lists, inspection, previews, pause, resume and
revocation available under their existing permissions. Other personal management
is unaffected. See [token creation](end-user-guide.md#issue-a-token-for-the-agent).

## Access key types

`accessKeyTypes` is an administrator-owned object that decides, separately
for each configured [access key type](configuration.md#access-key-types), whether an
account may hold access keys of that type. It does not change role,
self-service, agent-token issuance or invocation grants. A configured
access key type is on for nobody until an administrator allows it.

| Owner | Object | Meaning |
| --- | --- | --- |
| Account | `{"allow":[...],"deny":[...]}` | A type in `deny` is refused and a type in `allow` is permitted, whatever the account's groups allow. A type in neither list follows the groups. A type cannot be in both lists. |
| Managed group | `{"allow":[...]}` | The types the group lets its members hold. A group cannot deny a type. |

New accounts have both lists empty and new groups allow nothing. For each
account and each type the Broker decides in this order:

1. the account's `deny` names the type: no;
2. the account's `allow` names the type: yes;
3. otherwise yes when at least one active managed group, which the account
   belongs to by current local membership, allows the type.

Membership that comes only from Microsoft group evidence does not count, and
a disabled group allows nothing while it is disabled. Access key types require
managed identity authority, so the groups are always managed groups.

The setting applies to people and to service accounts alike, and is read
every time a key is evaluated as well as when one is created. Withdrawing a
type stops the account's existing keys of that type without revoking them:
a key with no permitted type left is not active, and the same key works
again when the type is restored, subject to its own expiry, if any, the
type's current maximum and revocation. The [type configuration](configuration.md#access-key-types)
defines the offered lifetimes and whether a key can have no expiry. An
administrator who issues a key for a person or a service account needs
that account's access to allow every requested type. The access key type's
`self_service` key is a separate question: whether a person may create a
key of a type they may hold. It does not apply to an administrator's
issuance, so a type with `self_service = false` is one that only an
administrator hands out, to people as well as to service accounts.

A person's own access key routes (`/v1/access-keys`) take a signed-in
browser session with the CSRF header, never a bearer token, and are not
gated by the account's self-service flag, by agent-token issuance or by any
service grant: this setting, the access key type's `self_service` and a usable
[username](configuration.md#usernames) decide. Administrators issue for
people and service accounts, administer usernames and list and revoke any
access key; auditors read; the service policy manager role gives no access to
those administrative routes. See
[the routes](http-api.md#usernames-and-access-keys).

```bash
agent-access admin groups create platform --access-key-types --access-key-type-allow inference --access-key-type-allow packages
agent-access admin principals groups add alice platform
agent-access admin principals access set alice --access-key-types --access-key-type-deny packages
agent-access admin principals access set build-agent --access-key-types --access-key-type-allow inference
agent-access admin principals access set alice --access-key-types
```

`--access-key-types` replaces the whole setting with the
`--access-key-type-allow` and, for an account, `--access-key-type-deny`
access key types given with it. Alone it empties the lists: an account then
follows its groups for every type, and a group allows nothing. In this
example Alice first holds `inference` through `platform` and is denied
`packages`; the last command lets her follow the group for both.

Each list names configured access key types, each once, at most 256, and is saved
in lexical order. A supplied object replaces the whole setting; omission
leaves it unchanged. API and CLI writes are last-writer-wins without a
version precondition, so reread the current object before replacing it. An
access key type added to the configuration later is never added to a saved
setting, and the Broker refuses to start or reload while a saved setting
names an access key type the configuration does not define, naming the type
and the settings; see
[retiring an access key type](administrator-guide.md#retire-an-access-key-type).

Principal detail reports the configured `accessKeyTypes` and the resolved
`accessKeyTypePolicy`: one row for every configured access key type, in ID
order, with `accessKeyType`, `allowed`, `source` and `groupIds`. `source` is
`account` when the account's own list decides, `groups` when the account
follows its groups and at least one allows the type, and `none` when it
follows them and none does. `groupIds` lists the allowing groups, sorted, for
`groups` and is empty otherwise. Every group route reports the group's
`accessKeyTypes`. Audit completion records the setting before and after
each change.

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
`PATCH /v1/admin/principals/{principal}/access`. Its JSON body accepts `role`,
`selfServiceEnabled`, `agentTokenIssuance`, and/or
[`accessKeyTypes`](#access-key-types). Any one field satisfies the
minimum, including issuance alone. At least one field is required; null and unknown
fields are rejected. Omitted fields stay unchanged. Principal and browser
session responses always expose singular `role` and `selfServiceEnabled`.
Principal records include configured `agentTokenIssuance`; principal detail and
token options also include the resolved `agentTokenIssuancePolicy`. Creating an
existing principal again is refused with HTTP 409 and changes no settings.
Internal onboarding upserts also preserve existing issuance overrides; only
this access PATCH changes them. An unchanged issuance
setting is a no-op, and a policy-only edit never revokes tokens or removes
service-manager assignments. A supplied `agentTokenIssuance` must include both
fields and replaces the whole object atomically; nested partial updates are not
supported. Omission preserves both fields. API and CLI writes are last-writer-wins
without a version precondition, so reread the current object before replacing it.

`agentTokenIssuancePolicy` reports `source` (`user`, `groups`, or `default`) and
`contexts`: enabled rows with `executionContext`, `mode`, and winning `groupIds`.
Missing contexts are disabled. Only groups tied at each context's winning mode
appear in its sorted unique `groupIds`; account overrides have no group IDs.
Explicit Disabled reports source `user` with no rows; inheritance without any
permission reports source `default` with no rows. The rows follow registry order
and can include assigned issuance contexts without current invocation grants.

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
self-service. Only a request the portal sign-in cookie authenticated is a browser
session; an issued `user_manage` bearer is never one. An `admin` bearer may be
issued to a human administrator or auditor; the holder's current role limits its
powers and it cannot call personal routes.
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
