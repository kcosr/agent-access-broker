# Portal walkthroughs

Use these illustrated guides to complete common tasks in the Agent Access Broker
portal. Start with the page for your role. Each walkthrough gives prerequisites,
steps, an expected result, and checks for common problems.

| I want to… | Walkthrough |
| --- | --- |
| Sign in, check my permissions, and connect an agent | [User self-service](user.md) |
| Investigate an allowed, denied, or failed request | [Auditor investigation](auditor.md) |
| Create accounts and organize group membership | [Administrator: users, groups, and workloads](admin-users-groups.md) |
| Define a resource boundary and grant service access | [Administrator: resources and grants](admin-grants.md) |
| Review authority, delegate management, or remove access | [Administrator: maintenance and offboarding](admin-maintenance.md) |

## Before you start

Ask the deployment owner for the portal URL and your sign-in method. A deployed
portal is normally available at `https://broker.example/ui`; replace this example
with your deployment's address. Microsoft sign-in appears only when configured.
An administrator-issued temporary local password must be changed before using
other portal pages.

The administration steps assume managed identity and managed policy, management
enabled, and the portal installed. File-owned identity or policy may be inspected
but must be changed through configuration and reload. Provider integrations must
already be configured by the operator before their service actions can be granted.
See the [operator guide](../operator-guide.md) and
[administrator reference](../administrator-guide.md) for deployment and initial
administrator setup.

## Search and jump with Ctrl+K / ⌘K

Open the search button in the top bar or press **Ctrl+K** (**⌘K** on macOS).
Type a name, ID, or a few words, then use **↑ / ↓** and **Enter** to open a
result. **Escape** closes search. With no query, the palette offers navigation
and common commands.

| Results | Searchable information |
| --- | --- |
| Pages | Page names and navigation terms, including Users, Service accounts, User groups, Resources, and Resource groups |
| Principals | Display name, principal ID, email, account kind, and status |
| User groups | Display name, group ID, description, and status |
| Resources | Display name, resource ID, selector value or coverage, resource type, and enabled state |
| Resource groups | Group name and ID, plus names, IDs, selectors, and types of included or excluded resources |
| Services | Display name and service ID; imported services also include adapter and status, including drafts |
| Service actions | Action ID, description, service name/ID, required scope types, and read/write classification |
| Grants | Grant reference, service, description, subject IDs and display names, action IDs, and status |
| Your tokens | Token name, ID, and active/paused/expired/revoked status |
| Your credentials | Connection name/ID, the services using it, credential ID, profile, kind, and status; only connections with a stored token |

Search ignores case. Each space-separated word must appear in the result's
name or searchable information; words can match different fields. Exact names
and name prefixes rank ahead of other matches. It does not correct spelling or
search secret values, document bodies, or upstream Jira/GitLab/Confluence content.
Resource-group membership matches include exclusions: finding a group through a
resource does not imply that the group grants access to that resource.

Each category initially shows six matches. Choose **Show all** to expand that
category without closing the palette; changing the query resets expansion.
Loading and fetch failures appear in their categories. **Retry** reloads failed
data, and any retained results are marked when they may be out of date.

Administrators and auditors can search administrative entities; auditors get
read-only destinations and no administrative mutation commands. Service policy
managers search their scoped services, actions, and grants; selecting an action
opens Policies filtered by service/action. Personal results require self-service
and use your own access, tokens, and credential metadata. Selecting an action
from personal results opens Access filtered by service/action text.

When audit access is available, **Search audit for …** opens the Audit page
with the query and its default time range. Audit records are searched on that
page, rather than loaded into the palette.

## Understand the four controls

| Control | What it decides |
| --- | --- |
| Account role | Which administration pages and operations you may use. An auditor can inspect metadata and global audit; an administrator can change them. |
| Personal self-service | Whether you can manage your own credentials, connections, tokens, and activity. This is independent of role. |
| Invocation grants | Which service actions, resources, execution contexts, and credential modes a principal may use. Group membership can make a group grant applicable. |
| Agent token restrictions | A ceiling on existing grants, with its own lifetime and execution contexts. A token never creates an invocation grant. |

An upstream credential supplies authentication to the upstream service. Saving
one does not grant access. A Broker invocation token is the credential you give
the agent; the broker keeps the upstream execution credential. Upstream
permissions still apply. See [account roles](../roles.md) and the
[security model](../security-model.md) for the complete contracts.

## Follow the example from setup to review

1. An administrator creates a user or workload and a policy group in
   [users and groups](admin-users-groups.md).
2. The administrator selects the exact Jira `DEMO` project resource and creates
   a group grant for `issue.view` and `search` in `default`, using `per_user`
   credentials in [resources and grants](admin-grants.md).
3. Alice reviews her effective access, supplies her Atlassian credential, and
   issues a narrower token allowing only `issue.view` on `DEMO` in
   [user self-service](user.md).
4. An auditor checks the request's outcome and correlated records in
   [auditor investigation](auditor.md).
5. An administrator periodically reviews retained access and removes it when
   its purpose ends in [maintenance and offboarding](admin-maintenance.md).

The example illustrates how the controls fit together. A read preview is not an
upstream credential test, and an audit sample is not evidence that the pictured
operation ran against an upstream account.

## About the screenshots

All walkthrough images use light mode and synthetic accounts in the
[local managed demo](../../demo/README.md). No screenshot contains a raw issued
token or stored upstream secret.

Orange highlights, arrows, and short callouts identify the control or boundary
being discussed. The annotated images are separate copies; the original
captures are retained under `docs/images/portal/guide/` and in the demo capture
output. The annotations are documentation overlays, rather than portal controls.

Creation, replacement, password-change, and confirmation forms are captured as
unsubmitted drafts. The auditor screenshots use a real `auditor` account with
personal self-service disabled. Audit records are generated presentation
fixtures. Jira verification success and failure are simulated at the browser
response boundary and explicitly identified in their captions; they do not
contact a live upstream. The demo's Atlassian credential and host cannot be
used to perform the real CLI example.

Screenshots show the interface, while the steps describe what to submit in your
own configured deployment. Existing demo grants can be broader than the new
read-only grant example; those differences are called out beside the images.
For capture and fixture reproduction, see the
[demo capture instructions](../../demo/README.md#capture-showcase-and-walkthrough-images).

## More detailed references

- [End-user guide](../end-user-guide.md): personal credential/OAuth setup and CLI/MCP use.
- [Administrator guide](../administrator-guide.md): bootstrap, sign-in enrollment,
  grant-based OAuth setup, classless credential rights, and onboarding contracts.
- [Resources](../resources.md): typed selectors, live groups, and exclusions.
- [Roles](../roles.md): administrative authority and independent self-service.
- [Operator guide](../operator-guide.md): configuration, reload, backups, and recovery.
- [HTTP API](../http-api.md) and [CLI](../cli.md): automation interfaces.
