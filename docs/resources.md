# Resources and resource groups

Resources give grants and agent-token restrictions a shared vocabulary for
Confluence, Jira, GitLab REST, GitLab Git HTTP, CloudBees CI, and Teams. They describe
selectable scopes rather than a synchronized inventory of upstream objects. A
repository can be used by both GitLab surfaces without duplicating its catalog
entry.

## Resource entries

Each entry has a stable ID, a resource type, a selector, allowed execution
contexts, and an enabled state. The display name is optional. The UI derives a
label from the selector when no name is supplied and shows coverage alongside
custom labels. Resource and group IDs cannot be `.` or `..`, because each ID
must be addressable as an HTTP path segment.

Resource types are registered, not hard-coded in policy. Each registered type
defines its canonical target grammar, the selector forms it supports, and the
labels clients show; a service descriptor binds each of its resource scopes to
one registered type. The broker publishes the registry, in registration order,
at `GET /v1/resource-types` (any authenticated caller, no execution context) and
as `resourceTypes` in the runtime catalog (`/v1/spec/catalog`);
`agent-access admin policy resources types` prints it. This build registers:

- `git_repository` supports `exact`, `namespace`, and `all` selectors.
- `jira_project` supports `exact` and `all` selectors.
- `confluence_space` supports `exact` and `all` selectors.
- `cloudbees_ci_job` supports `exact`, `namespace`, and `all` selectors.
- `teams_notification_destination` supports `exact` and `all` selectors; an
  exact entry binds its alias to one encrypted Workflow URL in managed storage.
- `fake_project` supports `exact` and `all` selectors; it belongs to the
  development `fake` service.
- `oauth_collection` supports `exact` and `all` selectors; it belongs to the
  development `oauth_stub` service.

Command imports add the resource types their accepted manifests declare, after
the build's types, with `exact` and `all` selectors. Their selector grammar,
labels and private attributes come from the accepted declaration, which alone
validates attribute values; they stay registered while the import is disabled or
retired. Listings name the type's `importedService`. A type the command no
longer declares stays registered for its remaining resources, listed with
`removed: true`, but accepts no new ones, until a later acceptance drops it.
See [Imported resource types](imported-services.md#imported-resource-types).

A resource whose type is not registered, or whose selector form or value the
type rejects, fails TOML validation, managed mutations, and managed startup with
an error naming the resource and type. Removing a backend from a build therefore
requires deleting its resources (and their group memberships and grant
references) first.

An exact selector has the shape `{"kind":"exact","value":"engineering/payments"}`.
Repository names are canonical paths shared across integrations: at least two
segments, not all digits, used identically by GitLab REST authorization and Git
HTTP gateway classification. Jira project
and Confluence space selectors use their canonical keys. A Confluence personal
space is an ordinary exact selection, such as
`{"kind":"exact","value":"~alice"}`; keep the actual upstream key, including its
case and leading tilde. Its label implies no ownership or caller-relative home
behavior. See [personal-space setup](providers-confluence.md#personal-spaces).
Backend ID resolution belongs to the integration, not the resource catalog.

A repository namespace selector such as
`{"kind":"namespace","value":"engineering/platform"}` matches complete path
segments, including nested subgroups. It covers `engineering/platform/api`, but
not `engineering/platform-tools/api`. CloudBees CI job namespaces work the
same way: `team-ci/payments` covers `team-ci/payments/build-api`, and `team-ci`
covers all jobs on that controller. A namespace does not match its own path:
`team-ci/payments` does not grant the folder item at that exact value. An
`exact` CloudBees CI job requires the alias and at least one job segment;
`team-ci` alone is valid only as a `namespace`. Arbitrary globs are not
supported.

An all selector is `{"kind":"all"}` with no value. It deliberately covers
matching upstream objects that have never been individually registered,
including objects created later. An administrator can therefore provide broad
internal access without entering every project, space, or repository. For
Confluence this includes personal spaces, subject to upstream permissions and
the effective grant and token restrictions. Review existing Confluence `all`
resources in grants, groups, and token restrictions before upgrading, especially
service-mode grants using shared credentials. Use exact team-space resources
when access must remain limited to team spaces. Exact personal-space exclusions
cover only the listed keys; future personal spaces remain within `all` coverage.

Teams destinations additionally require configured exact entries. An all selector
can authorize those entries but cannot invent an endpoint for an unknown alias.

There is one entry per resource type and selector, regardless of label,
contexts, or enabled state. Overlapping selectors are valid: an exact repository,
its namespace, and all repositories can each have a catalog entry.
When a managed create or edit would duplicate a selector, the error identifies
the existing entry and the portal offers **Open existing resource**. Edit that
entry's contexts or enabled state and reuse it in groups and grants.

Jira issues and Confluence pages remain ordinary operation targets. Their
containing project or space is the authorization boundary; neither has a
separate resource type or fine-grained grant/token scope.

### Catalog change history

Resource and resource-group create, edit, and delete operations require a
successful audit preflight before changing the managed store. A preflight is
evidence of an attempt. A separate success record describes the committed
change using safe names, before/after state, and included/excluded member changes
captured in the transaction. No-op edits do not invent membership changes.

The portal shows those recorded names and changes in Audit and Activity. If a
resource has no configured display name, the recorded name stays null and the
portal derives its label from the recorded selector. Names remain as recorded
after subsequent renames or deletion. Links available to
administrators and auditors open the current object at that ID; a deleted ID
can be reused, so the link does not establish historical object identity.
Older records cannot supply details never recorded. A missing completion does
not prove failure: see [audit operations](operator-guide.md#audit-operations)
for investigation and [management audit](http-api.md#resource-and-resource-group-change-records)
for the record contract and separate-store durability limits.

## Private resource attributes

Registered types may declare private string attributes on exact managed entries.
The type metadata supplies labels, requiredness, and sensitivity to the resource
editor. Teams requires `webhookUrl`; admins enter it on creation and can explicitly
reveal, copy, or replace it later. Normal reads expose configured attribute names
only. The editor keeps revealed values out of shared caches and clears them when
the target changes, the value is hidden/replaced, or the view closes.

The URL is encrypted with the existing credential key ring and participates in
readiness and rewrap, even while the resource is disabled. Writes use the resource's
expected version and commit metadata and encrypted attributes together. Omitting
an attribute on PATCH preserves it; blank/null replacements fail. A populated
resource cannot change type or selector kind. Delete/recreate requires the ordinary
reference checks; aliases may be renamed on the same resource.

For `teams.notification.send`, callers pass only a destination alias and message
content. The broker first authorizes the alias, then resolves the configured exact
binding and rechecks it at dispatch. That entry must remain enabled and eligible
for the execution context, even when permission comes from an all/group grant.
This is endpoint availability, separate from the ordinary selector rules below.
Groups grant access and do not send to multiple destinations. See
[Teams setup and payloads](providers-teams.md) and
[the attribute management API](http-api.md#admin-policy-management).

## Caller discovery

`agent-access resources list --service SERVICE` and MCP `resources_list` show
only exact registered entries that are enabled, eligible in the caller's
execution context, and covered by at least one effective action clause. When a
service authorizes more than one resource type, discovery requires a
`resourceType` (`--resource-type`) so rows and resource-filtered action checks
never mix types; a service with one type uses it implicitly. Rows
contain IDs, types, values, optional configured names, and, when the resource
type defines them, the action `inputs` that address the value (for example,
CloudBees CI `{"controller":"team-ci","job":"payments/build-api"}`). Rows have
no action lists and never query upstream inventory.

The first page (no `cursor`) also reports the caller's broad access as
`coverage`, omitted when empty:

```json
{"service":"cloudbees_ci","resources":[],"coverage":[{"type":"cloudbees_ci_job","selector":{"kind":"namespace","value":"team-ci"},"inputs":{"controller":"team-ci"},"restricted":true}],"nextCursor":null}
```

- Each entry is a `namespace` or `all` selector from the caller's own
  effective clauses (grants and groups after exclusions, credential precedence,
  token restrictions, execution context, and local credential availability), across the type's actions. An
  entry is listed when the clause it comes from reaches some resource inside
  it. Resources inside are not enumerated; use `actions list` with a concrete
  value to check a particular action.
- A type whose provider declares roots, such as CloudBees CI controller aliases,
  reports an `all` selector as one `namespace` entry per root that clause
  reaches. A root its clause excludes or withholds is omitted even when a
  narrower grant reaches inside it; that grant is reported as its own entry.
  Namespace entries outside every root are dropped. Other types report
  `{"kind":"all"}`.
- Entries contained by another entry are dropped. `inputs` are the type's action
  inputs for the selector, when it defines any.
- `restricted: true` means an action whose clause includes the whole entry can
  reach only part of it because of exclusions, token restrictions, or
  precedence conflicts. Withheld values are never named.
- `prefix` keeps entries whose value starts with the prefix or whose namespace
  contains it; `all` entries are kept.

An empty `resources` list with `coverage` means broad access, not no access.
Check a known value with `actions list` before concluding it is not accessible.
Teams execution always requires a configured exact destination; its listing never
reveals the URL.

Use the returned `value` with `actions list --service SERVICE --resource VALUE`
or MCP `actions_list` to check action names for one target. A known unregistered
value is also valid. This uses existing grant precedence, group exclusions,
credential-mode conflict handling, and token restrictions. It is not a
full-request authorization or upstream existence check: multiple request targets
must still fit one effective clause at execution time. A disabled catalog row
is omitted metadata, not a new global deny over a separate broad grant.

Resource pages default to 50 and cap at 100. Repeat the original service,
prefix, and limit with `nextCursor`; continuation pages omit `coverage`.
Changed identity, context, policy, effective credential availability, resource labels or filters require
restarting. See [CLI discovery](cli.md#resources)
and [HTTP discovery](http-api.md#resource-and-action-discovery).

## Groups and exclusions

A resource group has a stable ID, name, included resources, and excluded
resources. A group can mix types. It has no execution contexts or disabled state
and cannot contain other groups. Grants and tokens can select several groups
for reuse. Resource groups are separate from principal groups used as grant
subjects. A newly created empty group remains visible to delegated policy
managers and can be selected before its members are added.

For example, an `External collaboration` group can include all repositories and
exclude the `private` namespace. A grant selecting this group and an
`Engineering` group combines all their positive selections, then subtracts all
their exclusions. Duplicated membership has no additional effect. An exclusion
from any selected group wins within that grant, even over a direct resource
selection. A separate eligible grant can still authorize the repository; these
are not global deny rules. An entry may appear in both membership lists; its
exclusion wins, including when that leaves the selection empty.

An exclusion uses its resource's selector even when that entry is disabled or
does not allow the request context. Disabling an entry must not accidentally
expose an excluded repository through a wildcard. Remove the exclusion from the
group to stop applying it.

Confluence personal-space exclusions must use the key exactly as Confluence
reports it, including case. Excluding `~Alice` does not exclude `~alice`. Copy
the key from a Broker content result's `space` field and confirm the exclusion
with a page-ID read, such as `agent-access confluence page view 123456`, as well
as search.

## Contexts and grants

Trusted ingress establishes the execution context. Resource entries and grants
both carry nonempty context lists. Contexts on a resource entry describe where
that entry contributes positive permission; they are not a universal
classification of the upstream object. An internal-only exact entry cannot
restrict a separate all-spaces entry that permits external access.

A grant references resources, groups, or both:

```json
{
  "resources": {
    "resourceIds": ["payments"],
    "resourceGroupIds": ["external-collaboration"]
  }
}
```

Within an otherwise eligible grant, the broker keeps enabled inclusions of the
applicable resource type that permit the attested context, then subtracts the
selected groups' exclusions. The service's actions and credential mode remain
independent grant decisions. A Confluence grant referencing a mixed group uses
its space entries; repository entries do not become Confluence permissions.

Every target of an operation must fit the selected grant. For example, a
cross-project GitLab operation must have coherent authority for both
repositories. Partial grants are not stitched together to obtain that authority.
Existing subject precedence, priority, and credential ambiguity rules remain.

Groups and selections may currently contribute no access. They can be saved
in that state. Empty effective access always means no access, never unrestricted
access.

## Token restrictions

Agent tokens remain bounded by current principal grants and their own service,
action, and execution-context caveats. Within a service restriction:

- Omitted `resources` means no additional resource restriction: follow grants.
- Present `resources` means a restriction, including when both lists are empty.
- References to groups retain live membership, not an issuance-time expansion.

For example:

```json
{
  "name": "collaboration-reader",
  "allowedExecutionContexts": ["external"],
  "allowedServices": ["confluence"],
  "serviceRestrictions": {
    "confluence": {
      "actions": ["page.view", "search"],
      "resources": {
        "resourceIds": [],
        "resourceGroupIds": ["external-collaboration"]
      }
    }
  }
}
```

The broker resolves the token selection with the same inclusion/exclusion rules
and intersects it with current grant authorization. An exclusion in the token
boundary cannot be overridden by another grant. A selected group becoming empty
leaves the token with no access through that group. It does not revert to
following grants.

Issued token selections are immutable, but the referenced resources and group
membership remain live. Removing grants, disabling a positive entry, or changing
contexts affects subsequent requests using existing tokens. Issue a replacement
token to change the token's stored selections.

## Management and effective access

Global administrators manage the catalog. Delegated service-policy managers
can select existing entries through their service authority, but cannot broaden
shared definitions or change resource contexts.

The portal lists resources and resource groups under **Admin > Catalog**.
Resource rows, grouped by type, show the name, ID, selector, execution contexts,
and status, with an Enable/Disable control; selecting one opens a drawer with
its details, private attributes, group memberships, and **Used by** references,
plus Edit, Enable/Disable, and Delete. Search matches names, identifiers, and
resource types, with separate type and status filters kept in the page URL.
Group rows show inclusion/exclusion counts; a group's drawer lists its included
and excluded members and its references. Type labels, the coverage
choices offered for each type (namespace only where the type supports it), and
example placeholders come from `GET /v1/resource-types`; the portal hard-codes
no resource type, and a new resource defaults to the first registered type.

Resources and groups show a `Used by` section in their drawer. It shows
visible direct group, grant, and restricted-token references, plus indirect use
through a group. Tokens that only follow grants are not direct references.

Deletion is blocked while references remain. Remove them manually; the broker
does not cascade changes through grants or tokens. Revoke an issued token to
retire its immutable reference. Revoked or expired tokens do not block deletion;
paused, unexpired, unrevoked tokens do. Historical token records can retain IDs
without retaining live authority.

Disabling a resource is reversible and preserves references and exclusions.
Changing its selector or contexts deliberately changes downstream authority.
Changing its display name only changes presentation.

Grant and token editors show selected names. A grant selection preview resolves
that selection's resource coverage by service, action, and context. A token
preview additionally applies the principal's current grants, credential
precedence, and the token caveats. Both report the policy generation used.

The grant editor offers direct resources of the selected service's resource
types. It offers groups with matching included or excluded members, including
mixed-type groups, and keeps empty groups available for future membership.
Group details show visible included and excluded members separately. Delegated
policy managers see only members within their service authority, so a group
with no visible members is not necessarily empty. Existing selections remain
visible and removable when the service changes, with labels
for entries that do not apply. Filtering never removes saved references or
expands groups into a fixed member list. If no configured service is selected,
the picker shows the available catalog without service compatibility labels.

Disabled resources and inclusions that do not allow a selected execution
context remain selectable with informational labels. Contexts do not filter
the picker, and exclusions still apply regardless of their resource's enabled
state or allowed contexts. Picker feedback is non-blocking and describes the
selected catalog entries; use the effective-access preview for the resolved
boundary after exclusions.

Previews resolve selections with the same rules as execution, even when a saved
selection includes disabled entries, empty groups, or types unrelated to the
previewed action. Picker visibility does not change those references' meaning.
Unknown references fail closed for the entire service selection without returning
detailed catalog lookup errors. Issuance still validates all references strictly.

Effective access uses symbolic descriptions for broad selectors, such as `All
repositories except private`, rather than presenting today's catalog entries as
exhaustive coverage. It retains separate clauses when one grant must cover the
whole request. Each clause's coverage must contain every target; several clauses
cannot be combined to authorize different parts of one operation.

Credential precedence can also impose whole-request conditions. A higher-ranked
grant covering only repository A must not suppress a lower-ranked grant covering
both A and B when an operation touches both repositories: the higher grant does
not authorize that complete request. Previews retain such conditions explicitly,
rather than subtracting A globally from the lower grant's displayed scope.

When nothing qualifies, the view shows `No access currently`; saving is still
allowed. The summary describes current policy authority, not upstream permission
or credential validity at the moment of a future operation. Per-user credential
onboarding follows authored active grants even when their resources currently
provide no access.

## Runtime consistency and search

Resources, groups, and grants are published together in an immutable policy
snapshot. Each authorization decision uses one captured snapshot. A saved change
affects subsequent requests; a request already using an older snapshot can
finish. Effective-access previews use the same policy semantics and refresh
after mutations.

Private endpoint bindings receive a final dispatch check against resource ID,
alias/type, resource/material versions, enabled state, and context. A changed
binding fails the prepared invocation instead of adopting a replacement URL.
Encryption-key rewrap preserves these logical versions. Already dispatched
requests cannot be recalled.

Jira and Confluence searches constrain upstream queries before pagination and
counts. Exclusions remain part of those constraints, and returned objects are
checked against the same boundary. Missing or ambiguous project/space
containment fails closed. An all-except boundary is not treated as unrestricted
all for lookup or audit purposes. Search audit records include
`searchAuthorization` with the complete finite or all-except boundary, including
credential failures after authorization and before provider dispatch.

## Configuration contract

TOML uses `policy.resources`, `policy.resource_groups`, and grant `resources`
references. Managed authority stores the entire graph and rejects inline
catalog/grant definitions. See [configuration.md](configuration.md#policy).

Grant and token boundaries use typed resource references. Services use registered
provider or gateway contracts. Managed stores must use a supported schema;
unsupported databases are rejected without modification. See
[database schema requirements](database.md#schema-model) for initialization and
upgrade procedures.

## Development OAuth collections

The development service `oauth_stub`, configured by `[providers.oauth_stub]`,
uses scope `collection` and resource type `oauth_collection`, with `exact` or
`all` selectors. A build that does not select the `oauth_stub` backend has no
`oauth_collection` type. Exact values contain 1–64
lowercase ASCII letters, digits, `_`, or `-`. The account owner remains credential
identity, not a policy resource. See [oauth.md](oauth.md#typed-reads-and-policy).
