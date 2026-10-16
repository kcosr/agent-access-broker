# Agent Access Broker - Provider and Gateway Overview

This document is the provider overview and navigation hub. Detailed action
contracts live in provider-specific documents so CLI examples, canonical action
names, input fields, policy behavior, and provider caveats have one owner.

The request lifecycle, identity/policy/credential models, and egress-proxy and
security posture that surround every provider call are in
[docs/design.md](design.md). HTTP routes, response envelopes, reason codes, and
runtime spec endpoints are in [docs/http-api.md](http-api.md). Configuration
keys for credentials, providers and `gateways` are in
[docs/configuration.md](configuration.md). CLI-wide behavior is in
[docs/cli.md](cli.md). Agent-facing recipes are maintained as access-surface
skills under [skills/](../skills/). Developers writing a provider start with the
[provider SDK guide](provider-sdk.md).

## Provider Documents

Built-in provider contracts:

| Document | Scope |
| --- | --- |
| [oauth.md](oauth.md) | Delegated OAuth lifecycle and development test-provider harness. |
| [providers-gmail.md](providers-gmail.md) | Google account connections; mail reads, archive, Trash and restore. |
| [providers-teams.md](providers-teams.md) | Notifications to managed, encrypted Teams Workflow destinations. |
| [providers-jira.md](providers-jira.md) | Jira issue, search, comment, attachment, verification, URL locator, and attribution behavior. |
| [providers-confluence.md](providers-confluence.md) | Confluence page, blog, draft, comment, attachment, CQL, URL locator, and attribution behavior. |
| [providers-gitlab-rest.md](providers-gitlab-rest.md) | GitLab REST uploads, project, issue, merge-request review, repository/CI, and project-webhook behavior. |
| [providers-cloudbees-ci.md](providers-cloudbees-ci.md) | CloudBees CI jobs, builds, Pipelines, logs, test reports, downloads, queue items, and parameterless triggers. |

Configurable broker surfaces:

| Document | Scope |
| --- | --- |
| [git-http-gateway.md](git-http-gateway.md) | `[gateways]` entries with `kind = "git_http"` for Git smart HTTP fetch and push. |

## Administrator setup

Start with the [operator guide](operator-guide.md) for the managed store, identity,
encryption keys, browser access and audit. Provider configuration alone does not
create permission to invoke an action. For each integration:

1. Configure the provider and exact upstream allowlist in Broker TOML. Keep secret
   values in environment/file references or encrypted managed credentials.
2. Create the required resource entries and grant only the actions and execution
   contexts the intended principal needs. With managed policy, create grants in
   the portal or management CLI; inline TOML resources and grants are rejected.
3. Configure the grant's credential mode and any required lookup credential.
   `per_user` mode uses a
   [credential connection](configuration.md#credential-connections), which
   several services can share. Enable the owner's self-service flag for personal
   management. Ordinary managed browser and `user_manage` management of
   connection tokens uses current per-user policy visibility. Personal OAuth
   setup requires a connection with `oauth` and a matching active `per_user`
   action grant for the owner or their current groups. Existing bound
   connections remain inspectable and disconnectable after grant loss.
   See the [administrator guide](administrator-guide.md) for explicit rights when
   classless static credential management is deliberately configured.
4. Validate configuration, reload it, inspect the caller's runtime catalog, and
   verify a small authorized read before authorizing a disposable write test.
   Teams has no read action: an authorized test send reaches its Workflow.

| Integration | Upstream authority | Broker permission boundary | Setup reference |
| --- | --- | --- | --- |
| Jira | API token with username, or configured Atlassian bearer token; service/per-user, or per-user delegated Atlassian OAuth through the gateway | Jira projects plus individual actions | [Jira setup](providers-jira.md#operator-setup) and [OAuth](providers-jira.md#oauth-connections) |
| Confluence | API token with username, or configured Atlassian bearer token; service/per-user, or per-user delegated Atlassian OAuth through the gateway, shared with Jira | Confluence spaces plus individual actions | [Confluence setup](providers-confluence.md#operator-setup) and [OAuth](providers-confluence.md#oauth-connections) |
| GitLab REST | Bearer token; service/per-user, or per-user delegated GitLab OAuth | Canonical repositories plus individual actions | [GitLab setup](providers-gitlab-rest.md#operator-setup) |
| CloudBees CI | Username/API token; service/per-user | Controller/job resources plus individual actions | [CloudBees setup](providers-cloudbees-ci.md#configuration) |
| Gmail | Per-user delegated Google OAuth | Individual mailbox actions; no resource selection | [Gmail setup](providers-gmail.md#setup) |
| Teams | Signed Workflow URL held in a private managed resource; service mode | Destination resources and `notification.send` | [Teams setup](providers-teams.md#operator-setup) |
| Git HTTP | Gateway execution credential; service/per-user, or per-user delegated GitLab OAuth shared with GitLab REST | Canonical repositories and fetch/push actions | [Gateway configuration](configuration.md#gateways) and [Git setup](git-http-gateway.md#access-surfaces-and-examples) |
| Imported MCP/OpenAPI | Reviewed connection authentication | Accepted actions; no resource/query containment | [Import setup](imported-services.md) |

The Broker cannot increase the upstream account's permissions. Conversely, the
upstream credential may permit more than a Broker grant: protect its secret and
use the narrowest upstream role that supports the approved workflow.

## Shared Concepts

- **Credential mode** - every provider action advertises supported modes such as
  `service` and `per_user`. The mode that applies to a request comes from the
  matched policy grant, not from caller input.
- **Pre-authorization metadata lookup** - some actions must confirm an issue's
  project, a page's space, or a GitLab project's authoritative repository path
  before final policy authorization. Per-user-only policy paths use the caller's
  per-user credential for this lookup. If a service-mode policy path can be
  viable, the broker uses the separate read-only
  `credentials.lookup.<service>` credential. No lookup credential is returned to
  the caller.
- **Resource scopes** - actions resolve concrete scope values such as Jira
  project keys, Confluence spaces, canonical Git repository paths, or a CloudBees
  CI controller alias plus full job name. Every required scope must be
  authorized by a single matching grant.
- **Upstream throttling** - when an upstream service throttles a request, Jira,
  Confluence, GitLab REST, CloudBees CI, Gmail, and Teams return
  `upstream_rate_limited` (HTTP 429) with `result.limitScope = "upstream"`,
  `result.service`, and, when the upstream sent a valid `Retry-After`, the
  bounded `retryAfterSeconds` and `retryAt`. Upstream bodies stay hidden and no
  request is retried automatically. Throttling of a readback or verification
  after a mutation was applied is instead `mutation_verification_failed` with
  `mutationStatus: "applied_unverified"`, `retrySafe: false`, and the created or
  changed IDs, and no retry wait. See
  [http-api.md](http-api.md#reason-code-table).
- **Mutation receipts** - a failed write keeps its ordinary error and reports
  what the upstream may have done: `mutationStatus: "not_applied"`,
  `retrySafe: true` when the Broker proves the request was never sent;
  `mutationStatus: "unknown"`, `retrySafe: false` when it may have been sent
  without a definitive answer, including a redirect or a 5xx, or when a batch
  failed after an
  item may have applied; and `mutationStatus: "applied_unverified"`,
  `retrySafe: false` when the upstream answered with a success status but the
  response or a read-back could not be read or validated. Writes with their own
  verification contract keep it. See
  [mutation receipts](http-api.md#mutation-receipts).
- **Correlation headers** - broker-owned upstream Jira, Confluence, GitLab REST, and CloudBees CI
  requests include `X-Agent-Access-Request-Id` and
  `X-Agent-Access-Broker-Request-Id`. Git HTTP gateways attach the same headers
  when `gateways.<service>.correlation_headers = true`.
- **Content attribution** - when `[attribution.actions]` enables a provider
  action, the broker appends or replaces a visible footer in supported text/body
  fields before upstream execution. Audit records whether attribution was applied
  without logging body text.
- **Normalized rich-content writes** - Jira, Confluence, and GitLab rich-content
  mutations use canonical `content` plus explicit `contentFormat`. The action
  identifies the provider-native destination. Catalog schemas are the
  capability signal for clients: inspect each action's `contentFormat.enum`,
  never a Broker version. There is no format default or inference.
- **Normalized read content** - response presentation uses top-level common
  invoke fields rather than provider inputs. `readContentFormat` preserves
  native content and can add Markdown or text `renderedBody` companions;
  `responseFormat = "markdown"` returns a semantic Markdown wrapper inside the
  standard envelope. Inspect each action's `readContentFormats` and
  `responseFormats` catalog fields. Jira, Confluence, and GitLab implement
  these capabilities on their declared rich-content and retrieval results.

## Built-In Providers

### Search boundaries

An all-resource grant expands authorization; it does not remove resource
locators required by an upstream endpoint. Search behavior depends on the
provider:

| Provider | Search without a resource selection |
| --- | --- |
| Jira | Omit `projects` to use effective authorization. Finite project scopes constrain JQL; unrestricted all adds no project predicate; exclusions remain enforced. Empty or ordering-only JQL needs finite projects because the enhanced search endpoint requires a bounded query. |
| Confluence | Omit `spaces` to use effective authorization. CQL retains exclusions and the page/blog content-type restriction, including under all-space grants. |
| GitLab REST | `issue.search` and `merge_request.search` require one `project`, even with an all-resource grant. Omit search text to browse that project's items. Filters and sorting are structured inputs, not a scope-rewritten query language. |
| Gmail | `message.search` already searches the connected user's mailbox without a resource selector. The provider has action-level grants and does not inject resource predicates into Gmail queries. |
| CloudBees CI | Reads and log searches require a concrete controller/job, plus a build where applicable. All-job grants do not turn them into searches across jobs. |
| Teams | Sends to one managed destination; no search action. |
| Imported MCP/OpenAPI | Accepted upstream inputs remain authoritative. These adapters provide action-level authorization, not resource/query containment or automatic scope injection. |

Jira, Confluence, GitLab REST, CloudBees CI, Gmail and Teams are built-in provider implementations. They
are invoked through `/v1/invoke/{service}/{action}`, generic
`agent-access invoke`, JSON `agent-access send`, and typed CLI wrappers where
available. Their action contracts are reflected in `agent-access spec catalog`
and `agent-access spec send-schema`.

Jira and Confluence also support Atlassian `bearer_token` credentials routed
through `https://api.atlassian.com/ex/...`. This requires
`providers.<service>.cloud_id` and allowlisting `api.atlassian.com`.
`basic_api_token` credentials use the tenant base instead. Credential *kind*
selects gateway-vs-tenant routing; credential *mode* still comes from policy.

## Git HTTP gateway

`[gateways]` entries with `kind = "git_http"` become host-matched gateway
services on the dedicated gateway listener. Normal Git clients use these
services; they do not expose `/v1/invoke` and are not included in invoke/send
runtime specs. GitLab REST and Git HTTP share `git_repository` resource entries.
Jira uses `jira_project`; Confluence uses `confluence_space`; CloudBees CI uses
`cloudbees_ci_job`. See
[Resources and resource groups](resources.md) for the shared policy model.

## Runtime Discovery

Runtime specs are the machine contract for the broker currently running:

```bash
agent-access spec catalog
agent-access spec send-schema
agent-access spec openapi
```

Use `spec catalog` for canonical provider action names and input schemas,
`spec send-schema` for JSON request-file variants, and `spec openapi` for direct
HTTP clients. Specs are caller-filtered by default and change with config
reloads, token class, policy grants, service/action caveats, and management
rights. Finite token resource restrictions remain request-time checks and do
not change provider schemas.

## Gmail

[Gmail](providers-gmail.md) uses per-user delegated Google OAuth for account/label reads,
message search/read, thread read, archive, Trash and restore.


## Generic imported services

An administrator can import an MCP HTTP server or OpenAPI 3.1 JSON definition as
an action-only service. These instances reuse normal policy, credentials, limits,
audit, and generic clients. They
do not provide resource or query containment. See [imported services](imported-services.md)
for setup, reviewed tool mappings, credential modes, and refresh behavior.
