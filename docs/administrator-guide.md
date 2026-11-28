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
token_profiles = ["atlassian-api-token"]

[credentials.per_user.jira]
type = "connection"
connection = "atlassian"

[credentials.per_user.confluence]
type = "connection"
connection = "atlassian"
```

`token_profiles` names the token types the connection accepts. Jira and
Confluence with a `cloud_id` accept several, so the connection lists the one
it uses; without a `cloud_id`, the classic API token is the only possible type
and the line can be omitted.

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

Through the gateway, people can instead connect their Atlassian account with
[Atlassian OAuth](oauth.md#atlassian), once for both products when one
registration serves both. That registration's scopes are checked as a whole, so
it suits sites where everyone has both Jira and Confluence. Where some people
have only one product, register one Atlassian integration per product and give
each product connection its own registration; see
[one registration or one per product](oauth.md#one-registration-or-one-per-product).

You decide each connection's method and the token types (profiles) it accepts:
`token_profiles` for everyone who uses tokens, and optionally
`service_account_token_profiles` to give service accounts and `system`
principals other types. A connection without `oauth` whose services accept only
one type, such as GitLab's, needs neither: that type is implied. Principals
never choose between OAuth and a token, and the Broker never falls back from one
method to the other:

| Principal | Connection with `oauth` | Connection without `oauth` |
| --- | --- | --- |
| Human user | Connects their account through OAuth | Stores their own token of a `token_profiles` type, or of the implied type |
| Service account | Uses the token you provision, of a `token_profiles` type | Uses the token you provision, of a `service_account_token_profiles` type if set, otherwise as for people |
| `system` principal | Stores its own token, of a `token_profiles` type | Stores its own token, of the same types as a service account |

Beside `oauth`, a connection without `token_profiles` gives service accounts
and `system` principals no personal credential. With several types in a list, whoever stores the token picks one:
the portal's token form asks for a **Token type**, with none preselected for a
first save and the stored token's type for a replacement, and the CLI takes
`--profile`. With one, there is nothing to pick. The portal names each type by
the label its consuming services declare, or by its profile. A stored token
whose type the list no longer accepts is kept but not used, and listed as
**Not used** (retained) until it is deleted or the type is accepted again.

OAuth is available for services that accept delegated credentials: Gmail,
GitLab REST and GitLab Git gateways, which share one GitLab OAuth connection
per instance ([GitLab setup](oauth.md#gitlab)), Jira and Confluence, which can
share one Atlassian OAuth connection per site ([Atlassian setup](oauth.md#atlassian)),
and imported MCP OAuth services. An import with a personal binding publishes its own connection under
its service ID. See
[credential connections](configuration.md#credential-connections) for every
rule.

Teams uses managed encrypted destination resources with service-mode grants and
no dummy credential. Imported MCP/OpenAPI services require administrator discovery,
review, and acceptance before grant creation. Imports have no project or folder
resource boundary. See [Teams](providers-teams.md),
[imported MCP](imported-services.md), [imported OpenAPI](imported-openapi.md), and
[imported OAuth](imported-oauth.md).

Swagger 2.0 and OpenAPI 3.1 JSON use the same OpenAPI / Swagger import flow.
Choose a document URL or upload a JSON file, with a separate approved API base
URL in either case. The Broker retains an uploaded document for refresh after
restart; upload a replacement to review changes. If uploading fails after the
draft is created, correct and retry that draft. Existing accepted actions stay
unchanged after a failed replacement.
Basic credentials have Username and Password or API token fields; preserve their
spaces exactly. Document-fetch credentials are separate from execution
credentials. Review POST searches explicitly as read-only before accepting them;
an HTTP method or operation name never assigns that classification automatically.

## Onboard a human user

In **Admin > Principals > Users**, select **Create user**. Microsoft enrollment
is the default: enter the required **Microsoft email**, optionally enter a
**Display name**, and choose access settings. The Broker generates the stable
principal ID; there is no ID field in this form. The portal initially uses the
Microsoft email for profile email and enrollment, which remain independent after
creation. See [Microsoft onboarding](#microsoft-onboarding) for matching and
first-sign-in behavior.

For a local account, select **Create a local account instead**, enter its
**Username**, and acknowledge the separate local-password sign-in. The username
is the explicit principal ID; creation displays a temporary password once. This choice does not create Microsoft
enrollment. If Microsoft enrollment is unavailable, the form explains why and
requires an explicit local choice to proceed. Service accounts are created
separately under **Service accounts**, with an explicit principal ID.

Select a role, self-service setting, and **Agent token issuance** permission:

| Role | Administrative authority |
| --- | --- |
| User | Personal management only when self-service is enabled |
| Auditor | Read all administrative metadata and audit; no administrative writes or secret reveal |
| Service policy manager | Read audit and manage grants for directly assigned services |
| Admin | Full broker administration |

Roles do not grant invocation. Self-service independently controls personal
credentials, connections, tokens, and activity; turning it off preserves existing
invocation tokens and credentials. See [roles](roles.md).

In **Overview > Account access**, **Agent token issuance** defaults to **Inherit
from groups**. A managed group's **Token issuance** defaults to **Disabled**.
Select Read-only or Write-capable, then explicitly check at least one configured
execution context. The checklist follows the configured registry order; newly
added contexts are never selected automatically. Inherit and Disabled clear the
list. Account overrides remain editable under TOML identity or policy authority;
group writes require managed identity. If the context registry is loading or
unavailable, context-dependent saves remain disabled until it loads.

An account override replaces group permission completely. With Inherit, the most
permissive active effective group wins separately in each context. Review the
current saved context/mode summaries and contributing groups. Switching an
unsaved override to Inherit does not preview the inherited result; that appears
after save and refresh. Disabled groups and TOML identity groups do not contribute.
For example, internal Write-capable and external Read-only permission allows a
writable internal-only token, while a token covering both contexts must be read-only.

A context removed from configuration remains visible in an open draft as **No
longer configured** until you deselect it. A failed save preserves the draft.
If the saved value of an edited field changes, choose **Discard draft** to load
saved settings or **Keep my draft** to keep your edits against the new saved base.
Neither choice saves automatically. Unedited role/self-service fields adopt the
latest saved values; a contexts-only save does not resubmit an old role. The form
checks again before saving and sends only changed fields. API/CLI writes remain
last-writer-wins, so an edit after that final check can still replace the submitted
fields.

Read-only permission still allows **Follow current grants** tokens that inherit
future reads while blocking writes. Permission changes affect only new personal
tokens. Administrators can issue either token type from a principal's Tokens tab
regardless of the owner's personal mode or context limits; those forms use target
grants and start with Read-only checked. Missing owner-policy display data alone
does not block administrative issuance, but valid lifetime/permission metadata
and target options are required. Service accounts require this administrative
path. See [issuance rules](roles.md#agent-token-issuance).

Create a group before adding members. Deliver a local account's temporary
password securely and require its first-use change. To add local-password
sign-in to an existing account, use **Overview > Sign-in methods**. It is an
independent sign-in method, including when added to a Microsoft account. Group mapping,
JIT/linking details and expiry behavior are in
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
URL, Authorization Bearer identity, and token file, and that `default` is a
configured execution context. Management commands reject
literal `--token-value`; use a file or environment source. This example explicitly
creates a local account with username `alice`; Microsoft creation omits the
positional ID as shown under [Microsoft onboarding](#microsoft-onboarding).

```bash
agent-access admin principals create alice \
  --kind user --display-name "Alice Example" --email alice@example.com
agent-access admin groups create agent-users --display-name "Agent users" \
  --agent-token-issuance read_only --agent-token-issuance-context default
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
use its **Add username binding** form to create an exact username binding in a
namespace configured by the operator.
The caller's credential selects the namespace; the user cannot select it in a
request. Several names can map to one human and share its permissions and quotas.
Disabled bindings reserve their names; rename or reassign with delete/create.
Unavailable namespaces remain visible for review. Auditors can inspect metadata;
only administrators can mutate it.

The **Access paths** table lists the human's identity token first, then each
username binding, each with **Enabled** and **Read-only** settings. Disable a
path to stop it without affecting the others; disabling the identity token keeps
its secret. Make a path read-only when an agent connection should only read: it
can then list and call only actions classified as reads, within the person's
grants, and Git push through the identity token is refused. Browser sign-in and
issued Broker tokens do not inherit the path's setting; tokens retain their
own stored read-only and other restrictions. Imported actions stay writes
until you review them as reads, so they are hidden from read-only paths until
then.

**Pause identity access** blocks trusted usernames and fingerprints together while
leaving browser sign-in and separately issued Broker tokens available. **Identity
token** inventory is separate: removing or replacing it affects fingerprint access,
not username bindings or the pause gate, and keeps the token's settings. Principal
disable blocks all principal identity methods. Pause, binding and identity-token
changes take effect at final admission and do not cancel already admitted
operations. Changing a path's settings ends its open MCP sessions; reinitialize
MCP after an identity transition. Use [managed identity](managed-identity.md) for
exact CLI commands, version checks and caller setup.

## Review application access

When the operator has registered [applications](applications.md), a person can
approve one in their browser, and the application then obtains short-lived
agent tokens for that person. Approving needs neither self-service nor
permission to issue tokens, because the person never holds the tokens. The
operator sets each application's level for everyone (`none`, `read_only` or
`read_write`); you narrow or end one person's access. In the portal, open
**Admin > Principals > the person > Overview**: each application is a row of
the **Access paths** table under **Identity access**, with **Enabled**,
**Read-only** and **Remove**
([walkthrough](portal-guide/admin-maintenance.md#review-application-access)).
With the CLI:

```bash
agent-access admin principals application-access list alice
agent-access admin principals application-access update alice ACCESS_ID --read-only true --expected-version 1
agent-access admin principals application-access update alice ACCESS_ID --enabled false --expected-version 2
agent-access admin principals application-access delete alice ACCESS_ID --expected-version 3
```

- **Read-only** limits the application's tokens for this person to actions
  classified as reads, even when the application's level is `read_write`.
- **Enabled** off stops the application for this person: it can no longer
  refresh, and the person cannot connect it again until you enable it.
- **Remove** (`delete` in the CLI) removes the approval and its settings; the
  person may connect again later, unrestricted.

Every change ends the tokens the application currently holds for that person,
so it takes effect at once. A person can remove their own access under
**Account > Applications**, with or without self-service, and the application
can end it, but neither lifts your restriction: a disabled or read-only access
stays in this list as not connected, and approving again reuses it with the
same settings. A first approval is also listed as not connected until the
application finishes connecting. The list shows how many tokens are live; they
are not listed with the person's other tokens, and the count can be zero while
the application stays connected, for example after a reload ended them. An
access whose application is no longer registered is shown as unavailable,
without a level, and mints nothing. Auditors can read the list. An
application's tokens act within the person's grants, so review application
access together with those grants.

## Usernames and access keys

When the operator has configured [access key types](configuration.md#access-key-types),
a trusted caller with the resolution capability can ask the Broker whose
[access key](http-api.md#access-key-resolution) a value is. An access
key is for that service only: the Broker never accepts one as a credential. A
person is known there by the username on their account, a service
account by its principal ID. You administer names, decide who may hold each
access key type and issue access keys for people and service accounts with the
[management routes](http-api.md#usernames-and-access-keys) or the CLI
commands below; auditors can run the `list` and `inspect` commands.

When a stored key is inactive, the trusted resolving service receives its key
ID, the owner's current usable username or service-account ID (or null), and
the [inactive reason](http-api.md#access-key-resolution) for its own logs. A
renamed owner is identified by the current name; a missing, reserved or
unconfirmed name yields null. Unknown keys receive only `active: false`;
malformed HTTP requests are refused with 400.

### Size the resolution route

A resolving service asks about a key when it first sees it, and then asks
again on a schedule for as long as anything it admitted under the key is
live. The two kinds of request are bounded differently, by
[`[limits]`](configuration.md#limits):

- `max_concurrent_access_key_resolutions` is the pool every request to the
  route runs in, and the only bound on a lookup for a key the Broker holds.
  Make it at least the sum, over the resolving services, of the rechecks
  each may have in flight and the lookups of new keys each may have in
  flight. A request beyond the pool answers 429, which a resolving service
  treats as "unavailable": a pool that is too small delays rechecks and
  new-key lookups under load. The resolving service owns its recheck schedule
  and its handling of unavailable lookups.
- `max_concurrent_access_key_resolutions_per_caller` is the most of that
  pool one caller entry may hold at once, so that a caller whose requests
  stall cannot keep the others out. Make it at least what the busiest
  caller entry may have in flight, rechecks and lookups of new keys
  together, and make the pool larger than it by what the other callers
  need while that one is at its share. With the defaults one caller holds
  at most 24 of 32 slots. A Broker with a single resolving caller may set
  the two equal; once a second caller resolves, the share must be smaller
  than the pool. A request beyond the share answers 429 like one beyond
  the pool.
- `access_key_resolutions_per_caller_per_minute` counts, for each caller
  entry, only the requests the Broker cannot tie to a stored key: keys no
  store holds, malformed requests (among them a request abandoned while
  its body was being read) and failed lookups. It never refuses a
  stored key, so it need only cover what the services sharing the entry
  allow through for keys that turn out to be unknown, their own bound on
  lookups of new keys. Beyond it the Broker answers 429. Lower it to the
  services' bound rather than leaving headroom.

Resolution writes no audit records. It identifies a key and decides nothing
about a request; the resolving service logs every decision and refusal itself.
An unavailable audit store does not change a resolution answer. The coarse
last-used time remains, and issue, revoke, settings and username changes keep
their existing audits.

Give each resolving service its own caller entry when you want their
unknown-key budgets and shares of the pool kept apart.

### How people get their usernames

A person's name is decided in one of two ways, set per account:

- **From email**, the default. The name is the part of the profile email
  before the `@`, lower-cased, when the operator's
  [`[usernames]`](configuration.md#usernames) lists the email's domain.
  The name follows the email.
- **Set by hand.** You type it, and it stays until you change it. Leaving it
  empty means the person has no name.

The Broker keeps the stored name in step itself. A person is named when the
account is created; when you change their email or their mode; when they
sign in while they hold no name; and, for accounts that already existed,
shortly after the Broker starts or reloads with their domain listed. There
is no command to run for existing accounts.

```bash
agent-access admin usernames list
agent-access admin usernames inspect usr-3
agent-access admin principals inspect usr-3
```

Each account shows its `mode`, its `state` and, when it has no name, the
`reason`:

- `usable`: the name works.
- `awaiting_confirmation`: the name is on the operator's list of names that
  services already use for people. Equal spelling is not proof: the name
  works only after you confirm that this account is that person.
- `conflict` (`name_taken`): another account holds the name this person's
  email derives; `conflict` names the name and its holder. The first holder
  keeps a name. Give this person a name by hand, or change the holder's.
- `none`, with `no_email`, `email_unusable`, `domain_not_listed`,
  `name_invalid`, `name_reserved`, `not_set` (set by hand, and empty) or
  `not_yet_assigned` (the name is free and is allocated at the person's
  next sign-in or the next reload).

```bash
agent-access admin usernames confirm usr-1 alice
agent-access admin usernames set usr-3 a.smith
agent-access admin usernames clear usr-4
agent-access admin usernames mode usr-3 from_email
agent-access admin usernames mode usr-5 manual
agent-access admin principals update usr-6 --email new.name@example.com
```

- `confirm` names the name the account holds, so a confirmation never
  applies to a name allocated since you looked.
- `set` gives a person a name by hand and switches them to manual. A
  reserved name, or one another principal holds, is refused. A name on the
  operator's list still needs your confirmation afterwards.
- `clear` leaves the person without a name, in manual mode.
- `mode ... from_email` derives at once from the email when the person's
  name was set by hand. For a person already on **From email** it takes no
  name away: it fills in a missing name and otherwise changes nothing.
  `mode ... manual` keeps the name held now and stops following the email.
- Changing the email of a person on **From email** renames them in the
  same change, unless the new email gives the same name.

Every change of name ends the person's access keys: keys minted under
the earlier name no longer work. The username's `liveKeys` says how many
that would be before you change anything, and `fromEmail` what the saved
email gives, also for a person whose name is set by hand. The response to a
change of mode, name or email carries `accountUsernameChange`: the names
before and after, `renamed`, and in `endedKeys` how many live keys ended. A
name that stays the same, as when only the mode changes or a new email gives
the same name, ends nothing. A disabled person keeps their name until you
change it. A person without a usable name cannot create an access key and
is told why.

### Decide who may hold each type

The operator's configuration defines the access key types. You decide who may
hold each one, and a type is on for nobody until you allow it. Allow a type
to a group, to one account, or both:

```bash
agent-access admin groups create platform \
  --access-key-types --access-key-type-allow inference --access-key-type-allow packages
agent-access admin principals groups add alice platform
agent-access admin principals access set alice \
  --access-key-types --access-key-type-deny packages
agent-access admin principals access set build-agent \
  --access-key-types --access-key-type-allow inference
agent-access admin principals inspect alice
```

- A group's setting lists the types it lets its members hold. It counts for
  members you added to the group while the group is enabled; membership that
  comes only from Microsoft group evidence does not count.
- An account's setting can allow a type whatever its groups say, or deny a
  type although a group allows it. A type the account names in neither list
  follows its groups. Here Alice holds `inference` through `platform` and is
  denied `packages`.
- A service account has the same setting. You can issue any account a key
  only of types its access allows.
- `--access-key-types` replaces the whole setting with the lists given
  beside it, and alone it empties them. Reread the current setting first:
  the last write wins.

`inspect` shows the account's `accessKeyTypes` and, under
`accessKeyTypePolicy`, whether each configured type is allowed and
whether the account itself (`account`), its groups (`groups`, with their
IDs) or nothing (`none`) decides. Withdrawing a type takes effect at once
for keys that already exist, without revoking them: they work again if you
restore it. See [access key types](roles.md#access-key-types).

### Retire an access key type

A type is defined in the Broker's configuration, and the Broker refuses a
configuration that no longer defines a type while any account's or group's
setting still names it. A refused reload leaves the running configuration
in force; a Broker started on such a configuration does not start. The
refusal says which type it is, how many account settings and group
settings still name it, with up to ten of each, and how many unexpired
access keys carry it:

```text
access key type packages is not in [access_key_types] and is still named by
2 account settings (alice, build-agent) and 1 group setting (platform);
3 unexpired access keys carry it. Take it out of those settings, or keep its
table, then reload or start again
```

To retire a type:

1. **Decide about its keys.** Keys never block a retirement and are not
   revoked by it. Once the type is gone, a key that carries only that type
   stops working (`no_access_key_type`), and a key that carries others
   keeps working with the rest. `agent-access admin access-keys list` shows
   each key's `accessKeyTypes`. Tell the owners, and revoke the keys that
   must not work again if the type is ever put back.
2. **Take the type out of every setting, while it is still configured.**
   Replace each group's setting with the types that remain
   (`admin groups update <group> --access-key-types ...`; `admin groups
   list` shows every group's setting) and each account's with its remaining
   allow and deny entries (`admin principals access set <account>
   --access-key-types ...`; `admin principals inspect <account>` shows it).
   An entry in a deny list counts like one in an allow list, and so do the
   settings of disabled accounts and disabled groups.
3. **Remove the type's table from the configuration and reload.** If the
   reload is refused, its message names what is left: repeat step 2 for
   those and reload again.

If the Broker does not start because the configuration already lacks a type
that settings name, put the type's table back, start, and follow the steps
above. Settings are changed only through a running Broker: never edit
database rows.

A type put back later under the same ID is on for nobody until you allow it
again. Keys that carried it can work again for accounts allowed it, subject
to their own expiry, if any, and the type's current maximum lifetime.

### Issue a key for an account

A person creates their own access keys with their signed-in browser
session, through the
[personal routes](http-api.md#a-persons-own-access-keys), of the types
they may hold that the operator opened to self-service. You issue a key
for a workload's service account, and for a person when the type is not
one people create themselves or when you hand the key out:

```bash
agent-access admin access-key-types list
agent-access admin access-keys issue build-agent \
  --name "nightly build" --access-key-type inference --ttl 7d
agent-access admin access-keys issue alice \
  --name "batch access" --access-key-type batch --ttl 30d
```

`access-key-types list` shows each type's name, description, ordered
`lifetimeOptions`, `defaultLifetime` and whether people may create it
themselves. The account's access must allow every type
you request; the self-service setting does not matter for a key you issue,
so a type the operator closed to self-service is one only you hand out. The
key is printed once, in `result.key`; store it where the workload reads
it, or give it to the person. Supply `--ttl` with a duration offered by
every chosen type, or `never` only when every chosen type offers it. Durations
match by their effective length, so `24h` matches `1d`. The server never uses
a type's default for an omitted lifetime. Invalid syntax, zero and durations
over `3650d` are malformed input and return `input_invalid` without echoing
the supplied value. It refuses a well-formed but unoffered lifetime with
`lifetime_not_offered` and names the first type in request order that does
not offer it.

The portal uses the same common options, in the first chosen type's order.
It preserves a lifetime you chose manually while every selected type still
offers it. Otherwise, it preselects the shortest chosen-type default common
to every chosen type, or the shortest common option, treating **Never expires**
as unlimited when choosing the default. The displayed choices keep the configured order.
With no common option, issuing is disabled. A key issued with `never` lists
its expiry as **Never**, but still depends on the current type settings:
removing `never` from a type's options can end that type's use by the key,
counted from the key's original mint time.

The Broker does not issue a key that could not work. The account must be
one whose keys resolve: enabled, for a person with identity access that is
not paused, with a usable name (a person's username, and for a service
account an ID that is not a reserved or listed username), and in at most
64 local groups. Otherwise the command is refused with the reason, the
same code the account's page shows as its access key problem and every key
the account already holds lists as its status: `principal_disabled`,
`identity_access_paused`, `no_account_username`,
`account_username_awaiting_confirmation`, `account_username_reserved` or
`group_limit_exceeded`. Remove the cause and issue again; keys issued
before are not ended by it and work again once it is gone. A person's own
request is refused in the same states.

A key you issue for a person is theirs. It works as that person, they see
it among their own keys, marked as issued by an administrator, and can
revoke it, and it stops working by the same rules as one they created: a
changed name, withdrawn access, paused identity access or a disabled
account. The audit record names you as the actor and the person as the
owner.

### Review and revoke

```bash
agent-access admin access-keys list
agent-access admin access-keys list --principal build-agent --include-revoked --include-expired
agent-access admin access-keys revoke ak_0123456789abcdef0123456789abcdef
```

Each key's `status` is `active` or the reason it does not work now, such as
`expired`, `revoked`, `principal_disabled`, `identity_access_paused`,
`username_incarnation_changed` (its owner's name changed), `no_account_username` or
`no_access_key_type` (its types were removed, shortened or withdrawn from its
owner's access). `lastUsedAt` is updated at most every five minutes.
Revocation is final. Pausing a person's
[identity access](managed-identity.md), disabling the account or withdrawing
a type stops access keys without revoking them: they work again when you
resume, re-enable or restore, so revoke them when that is not what you want.

## Enable personal OAuth connections

For Gmail, GitLab (GitLab REST and GitLab Git gateways on one connection; see
[GitLab setup](oauth.md#gitlab)), Jira and Confluence (one Atlassian connection;
see [Atlassian setup](oauth.md#atlassian)) and imported MCP OAuth, enable the human
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
`system` principals' tokens, and people's for connections without OAuth, of a
type the principal's list accepts, chosen in **Token type** when it accepts
several. That
does not grant the target personal rights or complete the user's OAuth consent. The
tab lists each person's OAuth registration with its connection status and
nonsecret connected account metadata for administrators and auditors alike.
An administrator can disconnect it using the same confirmation as the personal
view, naming the person and affected services; an auditor cannot. This works
after grant loss and when the person's self-service is disabled. The drawer
also shows remote revocation, and the row flags a failed or unconfirmed one.
Only the person connects or reconnects. Disconnecting does not block future
consent while the person remains permitted to connect. See
[administrative OAuth management](oauth.md#administrator-management-api).
An `admin` bearer cannot call
personal routes. Imported OAuth administrator discovery has a separate authority
path described in [imported OAuth](imported-oauth.md).

## Create resources and grants

Create resources before referencing them in grants or token restrictions. In
**Admin > Catalog**, choose the resource type and one of its supported
exact/all/namespace/subtree selectors,
execution contexts, and an identifiable label. Flat resource groups may include
and exclude entries; inspect their current members before reuse.

For Confluence content, paste a page, blog or folder browser URL; service and
kind are inferred. New page location entries default to page-and-descendants;
select page-only if descendants should not be included. **Change location** starts
a new entry with the same default. Save normalizes and saves the entry, while
Cancel discards the whole edit. Whole spaces retain separate By space
key, From space URL and All spaces modes. A space URL shows the key to be saved;
use By space key if its browser segment is an alias. Normalization is offline and
reports `verification: "not_checked"`, without an administrator connection.
Content identities bind site, kind and ID and follow external cross-space moves;
subtrees cover current descendants. Existing resources can retain their identity
while changing name, contexts or enabled state. Existence and upstream permissions
are checked at invocation.
Space grants remain broad when a narrower resource is added. See
[content access](confluence-content-access.md) for supported URLs, exclusions,
overlap and token restrictions.

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
help separate upstream reads from mutations; a mixed grant is Write-capable. A
[read-only identity path](managed-identity.md#read-only-paths) can use only the
Read-only actions of the grants that reach it.
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
provision for each credential connection it uses: one without `oauth`, or one
with `oauth` that sets `token_profiles`, even though people connect that
connection through OAuth. With several types accepted, choose one in **Token
type** on its **Credentials** tab, or with `admin credentials put --profile`.
A connection with `oauth` and no `token_profiles` gives it no personal
credential. Assign an
operational owner and rotation schedule.

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
Prepare the normal human account with an explicit pending Microsoft email and
no positional principal ID:

```bash
agent-access admin principals create \
  --microsoft-enrollment-email morgan@example.test \
  --display-name "Morgan Demo User" --email morgan@example.test
```

The Broker generates a principal ID such as
`usr-7be9a51d-14d2-4f30-8c56-939c76cb602a` and returns it in `result.principalId`.
Use that returned ID for groups, grants and all later account operations; it is
independent of the email and display name. The CLI rejects a positional ID with
`--microsoft-enrollment-email`. Profile `--email` is optional and independent of
the enrollment option. Local and service-account creation require explicit IDs.
Existing principal IDs and enrollment attached to existing accounts stay unchanged.

Assign groups, grants and account settings using the existing operations.
Creating the account and enrollment is the approval; there is no further approval
step at login. They commit together, so invalid or duplicate enrollment leaves
no new account. Later group/grant setup failures retain the account for completion.
If the creation response is lost, inspect the principal list and pending enrollment
before trying again; loss of the response does not prove that creation failed.
This does not create a local password, attach upstream credentials, issue or
distribute Broker tokens, or configure trusted username access.

The first validated Microsoft sign-in with the reserved tenant and token `email`
binds the immutable tenant/Object ID to this same principal, consumes enrollment,
and preserves prepared access and identity inventory. The token's email can differ
from the sign-in name. Matching trims surrounding whitespace and lowercases ASCII
letters; it requires an email-shaped value with a dotted domain, no control
characters, and at most 320 UTF-8 bytes. There is no preferred-username, UPN or
alias fallback. Ordinary profile email never enrolls an account, and changing it
does not change the pending match email. A missing, unusable or different token
email leaves the prepared account pending and follows normal unmatched JIT rules.

In **Overview > Sign-in methods**, **Awaiting first Microsoft sign-in** shows the
pending email and tenant separately from profile email. Inspect, edit or cancel
it there, or use the following templates, replacing `PRINCIPAL_ID` with the
returned ID (or an existing account's unchanged ID) and the enrollment placeholders
with its current values:

```bash
agent-access admin principals login-methods oidc enrollment inspect PRINCIPAL_ID
agent-access admin principals login-methods oidc enrollment create PRINCIPAL_ID \
  --email morgan@example.test
agent-access admin principals login-methods oidc enrollment update PRINCIPAL_ID \
  --enrollment-id <enrollment-UUID> --expected-revision 1 --email morgan.new@example.test
agent-access admin principals login-methods oidc enrollment cancel PRINCIPAL_ID \
  --enrollment-id <enrollment-UUID> --expected-revision 2
```

Create is only for an account with neither pending enrollment nor a Microsoft
method. Use the current ID and revision returned by inspect for updates or
cancellation; stale requests conflict. The cancellation CLI sends those values
as the HTTP DELETE's required query parameters, without a JSON body.
A disabled account keeps its reservation and refuses matching login.
Cancellation releases the reservation and preserves
prepared access, but does not ban ordinary JIT sign-in. A paused reconciled
Microsoft provider permits preparation and pauses authentication. Pending rows,
Microsoft methods and external group mappings prevent changing the configured
tenant until explicitly removed.

Administrators can also link an existing account directly by Microsoft Object ID.
Cancel pending enrollment before linking; unlinking never restores email matching.
Existing immutable bindings always take precedence, even when their account or
method is disabled. Explicit email preparation and Object-ID linking permit
sign-in without JIT enablement or mapped-group admission. For unmatched users,
JIT creates a new opaque principal only when enabled and an eligible active
group mapping exists. Map immutable Entra security-group Object IDs to existing
Broker groups; these mappings never grant an account role.

```bash
agent-access admin groups external-group-bindings create agent-users \
  --external-group-id 11111111-1111-1111-1111-111111111111
agent-access admin principals login-methods oidc link alice \
  --user-object-id 22222222-2222-2222-2222-222222222222
```

Use real tenant Object IDs, not the example UUIDs, email addresses, or group names.
The Broker does not merge accounts. If a different token email created a separate
JIT account, inspect that account's Microsoft Object ID, disable the duplicate,
unlink its Microsoft method, cancel the prepared account's pending enrollment,
then Object-ID link the prepared account before retrying sign-in. This transfers
no account data or independently issued tokens.

Every successful Microsoft sign-in refreshes the display name from the first
usable sanitized `name`, `preferred_username`, or token `email`; with none it
keeps the current name. An administrator's name edit may be replaced at the next
sign-in. Profile email remains unchanged. Failed or superseded callbacks and
membership renewal do not refresh the name.

To give newly created Microsoft users a local baseline membership, enable
**Automatically add new Microsoft users** on each desired group's **Overview**
or when creating the group. Any number of groups can be selected. The CLI
equivalents are:

```bash
agent-access admin groups create baseline-users --display-name "Baseline users" \
  --auto-enroll-new-microsoft-users
agent-access admin groups update baseline-users --auto-enroll-new-microsoft-users true
```

This database setting takes effect without a configuration reload and does not
change sign-in eligibility. At the first successful Microsoft sign-in for a
principal created after migration `036_microsoft_enrollments`, Broker inserts
missing local memberships in every selected active group. Prepared, Object-ID-linked
and JIT-created accounts qualify, including an established local account's first
Microsoft sign-in. Existing memberships keep their attribution; new ones identify
Microsoft sign-in as their creator. Assignment and a durable processed marker
commit with the login, even when no groups qualify.

Accounts that existed at migration are marked processed without backfill.
Later sign-ins, unlink/relink and replacement enrollment never restore removed
memberships or add subsequently selected groups. Local login and membership
renewal do not trigger assignment. Disabling a group preserves its setting and
pauses assignment; re-enabling it affects accounts whose first Microsoft sign-in
is still ahead, without backfilling users who signed in during the pause. Turning
the setting off leaves existing memberships intact.

These local memberships persist after Microsoft evidence expires or the user
loses an Entra group. A group that is both mapped and selected for enrollment
initially reports `local_and_microsoft`; its local membership continues to
provide access when the Microsoft contribution ends. Review that consequence
when selecting groups. Membership grants no account role or service management
assignment. Successful login audit details include `jitCreated`, `enrollmentId`
and `tenantId` when a pending row was consumed, `displayNameUpdated` for an
existing name change,
and `autoEnrolledGroupIds` for actual inserts. No name or raw claim is recorded.
Enrollment changes and group setting changes have supplemental success records.

Group evidence comes from a successful Microsoft login and expires at the
configured TTL. When the operator enables
[membership renewal](operator-guide.md#microsoft-membership-renewal), the
Broker also renews it on demand while the person or their agents use the
Broker, from the refresh token stored at their last Microsoft sign-in. There is
no background directory sync or Graph expansion; group overage denies login.
Local groups, roles, direct grants, and tokens are independent of the directory
account. Removing local membership may leave an active Microsoft contribution.
Broker logout does not end Microsoft SSO, and does not stop renewal for the
person's agents.

The principal's **Overview**, under **Sign-in methods**, shows the Microsoft
method's renewal state, as does `oidc.membershipRenewal` in
`agent-access admin principals login-methods list <principal>`:

| Portal status | State | Meaning |
| --- | --- | --- |
| Groups renew automatically | `active` | Renewal works; the line names the last renewal. |
| Renewal retrying | `retrying` | Microsoft was unavailable or throttling; the Broker retries with backoff at the time shown. |
| Renewal blocked: *reason* | `blocked` | Microsoft rejected the client credentials or the request, reported an incomplete group list, or returned a response the Broker rejected. The next request that needs renewal retries it at least an hour after the failure, possibly later because of Microsoft's `Retry-After` or throttling, so a fix does not guarantee recovery within an hour; fix the cause (for example the client secret, or the person's group count). |
| Sign-in required to renew groups | `sign_in_required` | Microsoft no longer honours the refresh token. The person signs in with Microsoft again. |
| Not available: Microsoft returned no refresh token | `not_issued` | The last sign-in produced no usable refresh token. The person signs in again after their groups expire. |
| Sign-in required to renew groups: Microsoft returned a different identity | `identity_mismatch` | A renewal returned another identity and was refused. The person signs in again. |

No status appears when the method has no renewal record: renewal is off, or
the person has not signed in with Microsoft since it was enabled. Renewal ends
until the next Microsoft sign-in when Microsoft stops honouring the token
(about 90 days unused, a disabled account, revoked sessions, a password reset by
an administrator, removed consent). Unlinking the Microsoft method, disabling
the principal, and disabling Microsoft sign-in or renewal delete the stored
token; re-enabling a principal does not restore it. Failures never extend
evidence. Renewal outcomes are audited as `oidc.membership.renewed` or
`oidc.membership.renewal_failed` under the person's principal.

For immediate access removal, disable the Broker principal. Unlinking Microsoft
alone leaves nonbrowser tokens and local access intact and can permit later JIT
creation if Entra eligibility remains. Remove that eligibility when preventing
future admission. Deleting the Broker's stored refresh token does not revoke it
at Microsoft; when it may be exposed, use Entra **Revoke sessions** for the
person (see [revoking stored refresh tokens](operator-guide.md#revoking-stored-refresh-tokens)).

## Access review and offboarding

Periodically review active administrators, auditors, service managers/assignments,
service accounts and their owners, credential rights and expiry, enabled grants,
resource-group membership, connected applications and their per-person settings,
trusted username bindings and namespace availability,
shared identity-access pause state, each identity path's Enabled and Read-only
settings, read-only classifications of granted imported actions, nonexpiring
tokens, unused credentials,
stored tokens the configuration no longer selects, and principal-specific limits. Review
retained grants/credentials/assignments before restoring a removed service name:
its dormant records can become effective again.

For a departing user or suspected compromise:

1. Disable the principal to deny its tokens immediately, then revoke affected
   tokens. Pause is temporary and preserves the disclosed token secret.
   Disabling also ends, permanently, every token a connected application
   holds for the principal; the applications cannot obtain new ones while the
   principal stays disabled.
   Disabling also ends the principal's OAuth connections and, for GitLab,
   revokes their tokens in GitLab automatically. It deletes the stored
   Microsoft refresh token too, which Microsoft keeps honouring until its
   sessions are revoked in Entra.
   The principal's **Credentials** tab and
   `agent-access admin credentials list <principal>` report each OAuth
   connection's remote revocation (`remoteRevocation`), and keep listing a
   connection whose revocation is `pending`, `failed` or `unconfirmed` after its
   grants are removed: `failed` or `unconfirmed` needs the application's access
   revoked for that person in GitLab (see
   [remote revocation](oauth.md#remote-revocation)).
2. Remove directory/JIT eligibility when it could admit the identity again.
3. Revoke upstream credentials at the upstream service when they may be exposed;
   deleting the broker copy of a stored token does not revoke the upstream
   secret, and providers other than GitLab keep OAuth consent until revoked
   there.
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
