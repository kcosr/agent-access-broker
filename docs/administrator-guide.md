# Administrator guide

For portal walkthroughs with screenshots, start with
[users and groups](portal-guide/admin-users-groups.md),
[resources and grants](portal-guide/admin-grants.md), or
[maintenance and offboarding](portal-guide/admin-maintenance.md).

Use this guide to set up administrators, onboard users and workloads, grant
access, and review it later. Deployment owners should first follow the
[operator guide](operator-guide.md). Users can follow the separate
[end-user guide](end-user-guide.md) after their account and grants are ready.

This workflow assumes `identity.authority = "managed"`,
`policy.authority = "managed"`, management enabled, browser login enabled, and
the built portal available at `/ui`. Start from the
[managed production sample](../agent-access-broker.production.sample.toml).
TOML-authority deployments can inspect their policy in the portal, but must edit
configuration and reload to change it. Do not mix TOML grants with managed policy.

## First administrator

1. Start one broker with an empty managed store and
   `[management.initial_admin].mode = "create_if_empty"` and a unique generated
   initial password. Replace the sample placeholder before validation. Keep ingress
   restricted to the operator until this step is complete.
2. Open `https://<broker-host>/ui`, sign in as the configured `principal_id`, and
   change the configured initial password. Until then, only the password-change
   account screen is available.
3. Confirm that **Admin** is available and that **System** reports the intended
   runtime configuration. Create another human administrator with a working
   local sign-in method so recovery does not depend on one person or Microsoft
   availability.
4. Remove the initial bootstrap password from the deployed config by changing
   initial-admin mode to `disabled` and removing both `principal_id` and
   `initial_password`, then validate and reload. Disabled mode rejects those
   fields. Bootstrap applies only to an empty store; it is never a password reset or role-repair mechanism.
5. Record the administrator owners and recovery procedure. Keep the operator
   keys and database backups in the platform's protected storage.

The broker protects the last active human administrator from demotion or disable
and protects its local login method. For controlled static-token recovery, use
[management bootstrap](operator-guide.md#management-bootstrap); it deliberately
opens a temporary operator authority path that must be closed afterward.

The portal's **Admin** space contains **Policies**, **Principals**, **Catalog**,
**Audit**, and the **System** gear. **My access** contains personal **Access**,
**Tokens**, **Credentials**, and **Activity**; **Account** is in the account menu.
Select a table row for details or use Ctrl+K/⌘K to find an account, user group,
resource group, resource, grant, service, or service action. Search also links
directly to nested lists such as **Resource groups**, includes imported-service
drafts, and can open **Audit** with your search text. Results follow the viewer's
role and service scope. See [portal search](portal-guide/index.md#search-and-jump-with-ctrlk--k)
for matching, result expansion, and retry behavior. Filters and selected items
remain in page URLs for bookmarks.

## Configure an integration

Providers and ingress destinations are operator-controlled configuration. Choose
the relevant [provider guide](providers.md), add the provider settings and
credential sources, validate, and reload before creating grants.

Choose the credential mode deliberately:

| Mode | What it means | Administrator responsibility |
| --- | --- | --- |
| `per_user` | Calls use the principal's own upstream identity | Configure a credential connection for the service, have people store their token or connect OAuth, and provision service accounts' tokens |
| `service` | Calls use a configured shared upstream identity | Provision the service credential, review its upstream privileges, and grant its use explicitly |

Use per-user mode for personal ownership, such as GitLab review drafts. Service
mode makes every granted principal act as the same upstream account. A credential
alone authorizes no action. Jira, Confluence, and GitLab lookup-backed service
mode also requires the configured shared metadata-lookup credential; per-user-only
lookup uses the user's credential. Provider guides document those requirements.

Token-only actions, such as GitLab's project and service-account token creation
and rotation, run only with a token, never with delegated OAuth access. Under a
`per_user` grant they work for principals whose connection selects a stored
token, and are hidden and denied for people whose connection uses OAuth,
without falling back to a lower-priority grant. Where people connect through
OAuth, grant them in `service` mode or only to principals with tokens.

Per-user credentials come from **credential connections**. A connection is one
credential slot per principal that one or more services consume. For example,
Jira and Confluence on one Atlassian site can let each principal store one
Atlassian account email and API token for both with:

```toml
[credentials.connections.atlassian]
display_name = "Atlassian"
token_profile = "atlassian-api-token"

[credentials.per_user.jira]
type = "connection"
connection = "atlassian"

[credentials.per_user.confluence]
type = "connection"
connection = "atlassian"
```

This is an addition to the production baseline, not a complete broker config.
Configure the Jira and Confluence provider URLs and other required provider
settings as described in [Jira setup](providers-jira.md) and
[Confluence setup](providers-confluence.md) before reloading.

Services that reach the same upstream account can share one connection, as Jira
and Confluence do above. GitLab REST and a GitLab Git gateway can both name a
`gitlab` connection, so each principal stores one GitLab token, or connects one
GitLab account through [OAuth](oauth.md#gitlab), for both; see the
[Git gateway](git-http-gateway.md#credentials-limits-and-audit). Grants stay
per service, so a principal with only GitLab REST grants still cannot fetch
through the gateway, and one with only Jira grants cannot read Confluence. A
deployment that routes Atlassian through its API gateway gives service accounts
scoped bearer tokens instead, usually with one connection per product; see the
[token profiles](configuration.md#connection-token-profiles).

You decide each connection's method; principals never choose, and the Broker
never falls back from one method to the other:

| Principal | Connection with `oauth` | Connection with only `token_profile` |
| --- | --- | --- |
| Human user | Connects their account through OAuth | Stores their own token |
| Service account | Uses the token you provision, if the connection sets `token_profile` | Uses the token you provision |
| `system` principal | Stores its own token, if the connection sets `token_profile` | Stores its own token |

OAuth is available for services that accept delegated credentials: Gmail,
GitLab REST and GitLab Git gateways, which share one GitLab OAuth connection
per instance ([GitLab setup](oauth.md#gitlab)), and imported MCP OAuth
services. An import with a personal binding publishes its own connection under
its service ID. See
[credential connections](configuration.md#credential-connections) for every
rule.

Teams uses managed encrypted destination resources with service-mode grants and
no dummy credential. Imported MCP/OpenAPI services require administrator discovery,
review, and acceptance before grant creation. Imports have no project or folder
resource boundary. See [Teams](providers-teams.md),
[imported MCP](imported-services.md), [imported OpenAPI](imported-openapi.md), and
[imported OAuth](imported-oauth.md).

## Onboard a human user

In **Admin > Principals > Users**, create the user with a stable principal ID and
clear display name. Select a role and self-service setting:

| Role | Administrative authority |
| --- | --- |
| User | Personal management only when self-service is enabled |
| Auditor | Read all administrative metadata and audit; no administrative writes or secret reveal |
| Service policy manager | Read audit and manage grants for directly assigned services |
| Admin | Full broker administration |

Roles do not grant invocation. Self-service independently controls personal
credentials, connections, tokens, and activity; turning it off preserves existing
invocation tokens and credentials. See [roles](roles.md).

Create a group before adding members. For local login, enable a temporary password
in the user's **Overview > Sign-in methods**, deliver it securely, and require
its first-use change. A user can instead sign in through configured Microsoft
OIDC. Group mapping/JIT/linking details and expiry behavior are in
[Microsoft onboarding](#microsoft-onboarding).

For CLI administration, issue a short-lived `admin` management token from your
administrator account's **Tokens > Management tokens**. Save it in an
administrator-only file. Use it explicitly so it cannot be confused with an agent
token:

```bash
agent-access --url https://broker.example \
  --identity-header Authorization --identity-scheme Bearer \
  --token-file /secure/operator-admin.token auth status
```

The following examples assume your administrator CLI config selects that HTTPS
URL, Authorization Bearer identity, and token file. Management commands reject
literal `--token-value`; use a file or environment source.

```bash
agent-access admin principals create alice \
  --kind user --display-name "Alice Example" --email alice@example.com
agent-access admin groups create agent-users --display-name "Agent users"
agent-access admin principals groups add alice agent-users
agent-access admin principals password enable alice \
  --acknowledge-separate-sign-in --password-stdin
```

`--password-stdin` reads the new password from standard input. Supply it through
a protected source; do not put it in command arguments or shell history. Enabling
local sign-in is an independent login method, including on a Microsoft-linked
account. Reset only applies to an already active local method.

For users who need CLI self-service without a browser, issue a finite setup token
and deliver its returned secret through an approved secure channel:

```bash
agent-access admin tokens issue alice \
  --name alice-setup --token-class user_manage --ttl 2h
```

A `user_manage` token can manage the owner's personal credentials and invocation
tokens; an `agent_invoke` token cannot. Raw tokens are shown once. Do not send an
administrator token to a user or put a setup token in an agent's environment.

## Configure trusted human identity

For managed HTTP MCP clients, open the human's **Identity access** section and
create an exact username binding in a namespace configured by the operator.
The caller's credential selects the namespace; the user cannot select it in a
request. Several names can map to one human and share its permissions and quotas.
Disabled bindings reserve their names; rename or reassign with delete/create.
Unavailable namespaces remain visible for review. Auditors can inspect metadata;
only administrators can mutate it.

**Pause identity access** blocks trusted usernames and fingerprints together while
leaving browser sign-in and separately issued Broker tokens available. **Identity
token** inventory is separate: removing or replacing it affects fingerprint access,
not username bindings or the pause gate. Principal disable blocks all principal
identity methods. Pause and binding changes take effect at final admission and
do not cancel already admitted operations. Reinitialize MCP after an identity
transition. Use [managed identity](managed-identity.md) for exact CLI commands,
version checks and caller setup.

## Enable personal OAuth connections

For Gmail, GitLab (GitLab REST and GitLab Git gateways on one connection; see
[GitLab setup](oauth.md#gitlab)) and imported MCP OAuth, enable the human
owner's self-service setting, configure a credential connection whose `oauth`
names the registration and permission profile (imports publish theirs), and
assign a matching active action grant with `credentialMode = "per_user"` on a
service that uses the connection to the user or one of their current groups.
The same setup applies to an administrator connecting a personal account. A
signed-in browser session is required; a setup bearer alone cannot perform
consent. Use the registration's row in **My access > Credentials**.

Setup does not require a resource or execution context to be usable now, and the
matching grant need not win invocation precedence. A user can prepare an account
before its resources become available. Every invocation still evaluates its own
action, context, resource and credential requirements. Connecting an upstream
account adds no Broker invocation authority.

After grant removal, an existing owned connection stays visible and locally
disconnectable while self-service remains enabled and a service still binds its
registration. Connect/reconnect requires a current grant. Retired or blocked
imports still permit local cleanup. Imported administrator discovery has its own
bounded exception, including later discovery refreshes; see
[imported OAuth](imported-oauth.md).

## Grant personal credential rights

Explicit personal credential rights authorize deliberately enabled classless
static credential management. They do not authorize OAuth connection management;
OAuth uses the grant-based setup rules above. Ordinary managed browser sessions
and `user_manage` bearers also use configured per-user policy visibility for
connection tokens rather than these rights.

A credential right applies to one credential connection: its service bound is
the connection ID and its credential name is `default`. A right on any other
name, or on a service that no longer names a connection, has no effect. A
classless caller also needs its managed principal row, whose kind selects each
connection's method; rights cannot store a token for a connection that uses
OAuth for it.

| Right | Classless static credential operation |
| --- | --- |
| `credentials:self:read_metadata` | Read stored credential metadata |
| `credentials:self:write` | Save or replace a credential |
| `credentials:self:delete` | Remove a stored credential |
| `credentials:self:verify` | Run supported credential verification |

For a configured `jira` connection, grant the operations the principal
actually needs:

```bash
agent-access admin rights grant alice \
  --right credentials:self:read_metadata --service jira --credential-name default
agent-access admin rights grant alice \
  --right credentials:self:write --service jira --credential-name default
agent-access admin rights grant alice \
  --right credentials:self:verify --service jira --credential-name default
agent-access admin rights grant alice \
  --right credentials:self:delete --service jira --credential-name default
```

Always supply both `--service` and `--credential-name`; omission grants broader
rights. Rights belong directly to the principal, are independently revocable,
and may expire. Name the configured connection ID exactly. List and revoke
retained rights with:

```bash
agent-access admin rights list
agent-access admin rights revoke "<right-id>"
```

For ordinary connection tokens, a managed browser session or `user_manage`
bearer is admitted by its token class and the owner's policy-visible connection;
these routes do not additionally require the explicit rights above. Stored
tokens that the configuration no longer selects, such as tokens kept under a
former credential name or profile, stay listed for their owner, who can delete
them by ID.
OAuth owner cleanup after grant removal follows the separate rules above.
None of these management operations grants invocation access.

An administrator acting through **Admin > Principals > Credentials** or
`agent-access admin credentials ...` uses administrative authority to manage the
target's stored tokens. An administrator can store a token only for a
connection that selects a token for that principal: service accounts' and
`system` principals' tokens, and people's for connections without OAuth. That
does not grant the target personal rights or complete the user's OAuth consent. An `admin` bearer cannot call
personal routes. Imported OAuth administrator discovery has a separate authority
path described in [imported OAuth](imported-oauth.md).

## Create resources and grants

Create resources before referencing them in grants or token restrictions. In
**Admin > Catalog**, choose the resource type, exact/all/namespace selector,
execution contexts, and an identifiable label. Flat resource groups may include
and exclude entries; inspect their current members before reuse.

The example below grants the group read access to Jira project `ENG` from the
`default` context. It assumes Jira and its credential connection are
configured and `default` is a configured execution context. Direct token
clients must arrive in that context through the deployment's configured default
or approved ingress.

```bash
agent-access admin policy resources create \
  --id jira-eng --resource-type jira_project \
  --selector-kind exact --selector-value ENG \
  --execution-context default --display-name "Engineering Jira"

agent-access admin policy grants create \
  --grant-id jira-eng-readers --subject group:agent-users \
  --service jira --action issue.view --action search \
  --execution-context default --resource-id jira-eng \
  --credential-mode per_user --description "Engineering project reads"
```

In **Admin > Policies > Create grant**, choose subjects, service/actions,
execution contexts, resources, and credential mode. The editor shows effective
access and validation before save. Read-only and Write-capable action columns
help separate upstream reads from mutations; a mixed grant is Write-capable.
Saving selects explicit actions, so future provider actions are not added
implicitly. Start with the smallest useful action set and add writes separately.

A request must fit one grant's complete authorization alternative. Grants are not
combined to authorize one multi-resource operation. Exclusions win across groups
selected within the same grant or token restriction, including excluded entries
that are disabled or ineligible in the current context. An exclusion in one grant
is not a global deny against a different grant. See [resource rules](resources.md).

Exact entries cover one target. All and namespace entries can cover future
upstream objects. Token selections reference live resource definitions and group
membership, so later catalog edits can change access without reissuing tokens.
Use bounded exact resources where an enduring ceiling is required, and review
changes to broad entries and reused groups.

## Verify the user handoff

1. Open the user's **Access** tab. Confirm the intended actions/resources in every
   granted context, and check that unexpected writes or broad selectors are absent.
2. Verify self-service is enabled and the service's credential connection is
   configured for a current `per_user` grant. Have the user sign in, change any
   temporary password, and store/verify the credential through
   **My access > Credentials**. Connections with OAuth use the connect flow
   instead of pasting an API token; they need no separate credential rights. Check explicit rights only when
   deliberately using classless static credential management.
3. Have the user issue a finite `agent_invoke` token with only the required contexts.
   For dedicated automation, add explicit service/action/resource restrictions.
4. Verify a representative read with that token at the intended ingress. Check
   the response request IDs and Audit/Activity. A grant preview does not validate
   upstream permissions or guarantee a working credential.
5. Verify a disallowed action or target is denied before authorizing broader access.
   Use an agreed nonmutating probe; do not test denial by sending an uncontrolled write.
6. Revoke the setup token when it is no longer needed. Give the user the
   [end-user guide](end-user-guide.md) and support contact.

When an administrator opens another account's tabs, the administrator remains the
authenticated actor. The portal does not impersonate the target user; audit keeps
both actor and target metadata.

## Service accounts and delegation

Use **Admin > Principals > Service accounts** for workloads that must outlive a
human owner. These accounts have no password/Microsoft login, self-service, or
management tokens. Administrators manage their credentials, groups, grants, and
bounded `agent_invoke` tokens. A service account always uses a token you
provision for each credential connection that sets `token_profile`, even when
people connect that connection through OAuth; an OAuth-only connection gives it
no personal credential. Assign an operational owner and rotation schedule.

```bash
agent-access admin principals create build-agent \
  --kind service_account --display-name "Build automation"
```

For delegated policy ownership, set a human account's role to
`service_policy_manager`, then assign services directly:

```bash
agent-access admin principals access set alice --role service_policy_manager
agent-access admin policy managers grant --service jira --principal alice
```

This delegates the entire grant set for Jira, including the ability to grant access
to the manager themselves and use configured service credentials. It does not
allow principal/token/credential/config administration. Groups cannot hold these
assignments. A role change removes manager assignments and revokes admin tokens;
assign fresh administrative credentials after a promotion. See [roles](roles.md).

## Microsoft onboarding

The operator configures single-tenant Microsoft sign-in and a recovery local login
method first; see [OIDC operation](operator-guide.md#microsoft-entra-oidc-setup-and-operation).
Then map immutable Entra security-group Object IDs to existing broker groups. These
mappings never grant the admin role. JIT creates a new opaque broker principal only
when an eligible active group mapping exists.

```bash
agent-access admin groups external-group-bindings create agent-users \
  --external-group-id 11111111-1111-1111-1111-111111111111
agent-access admin principals login-methods oidc link alice \
  --user-object-id 22222222-2222-2222-2222-222222222222
```

Use real tenant Object IDs, not the example UUIDs, email addresses, or group names.
Link an existing principal before its first Microsoft login if that identity must
retain existing credentials/grants. The broker does not merge accounts by email.

Group evidence refreshes only on successful Microsoft login and expires at the
configured TTL. There is no background directory sync or Graph expansion; group
overage denies login. Local groups, roles, direct grants, and tokens are independent
of the directory account. Removing local membership may leave an active Microsoft
contribution. Broker logout does not end Microsoft SSO.

For immediate access removal, disable the Broker principal. Unlinking Microsoft
alone leaves nonbrowser tokens and local access intact and can permit later JIT
creation if Entra eligibility remains. Remove that eligibility when preventing
future admission.

## Access review and offboarding

Periodically review active administrators, auditors, service managers/assignments,
service accounts and their owners, credential rights and expiry, enabled grants,
resource-group membership, trusted username bindings and namespace availability,
shared identity-access pause state, nonexpiring tokens, unused credentials,
stored tokens the configuration no longer selects, and principal-specific limits. Review
retained grants/credentials/assignments before restoring a removed service name:
its dormant records can become effective again.

For a departing user or suspected compromise:

1. Disable the principal to deny its tokens immediately, then revoke affected
   tokens. Pause is temporary and preserves the disclosed token secret.
2. Remove directory/JIT eligibility when it could admit the identity again.
3. Revoke upstream credentials at the upstream service when they may be exposed;
   deleting the broker copy does not revoke the upstream secret.
4. Inspect **Admin > Audit** by principal, token, and request ID. Preserve the
   incident evidence under the deployment's retention rules.
5. Revoke obsolete personal credential rights and remove direct grants and
   memberships after reviewing other subjects
   that share grants. Keep database history/backups required by policy.

Disabling self-service only removes personal management; it does not stop
invocations. Disabling a principal preserves durable records, and re-enabling it
can restore unexpired tokens and retained policy. Reconcile those records before
re-enablement.

For operational failures, migrations, keys, and backups, return to the
[operator guide](operator-guide.md#common-failures). For command shapes and version
checks, use the current [CLI reference](cli.md) and authenticated runtime catalog.
