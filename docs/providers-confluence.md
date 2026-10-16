# Confluence Provider Contract

This document owns Confluence-specific action behavior, canonical action names,
page/blog URL locators, CQL, drafts, comments, attachments, audit metadata, and
attribution notes. Shared provider concepts and runtime discovery guidance are in
[providers.md](providers.md); CLI-wide behavior is in [cli.md](cli.md).

Service name `confluence`. Policy scope type `space`, bound to `confluence_space` resources. Every action advertises
credential modes `[service, per_user]`.

## Operator setup

This integration targets Atlassian Cloud. Add the following fragment to a Broker
configuration with identity, policy and audit already configured:

```toml
[providers.confluence]
tenant_host = "example.atlassian.net"
allowed_upstream_hosts = [
  "https://example.atlassian.net/wiki/rest/api/**",
  "https://example.atlassian.net/wiki/api/v2/**",
  "https://example.atlassian.net/wiki/download/attachments/**",
  "https://api.media.atlassian.com/**",
]

[providers.confluence.content]
page_formats = ["storage", "atlas_doc_format"]
blog_formats = ["storage"]
comment_formats = ["storage"]

[credentials.service.confluence]
type = "basic_api_token"
username_ref = "env:CONFLUENCE_SERVICE_USERNAME"
token_ref = "env:CONFLUENCE_SERVICE_API_TOKEN"

[credentials.lookup.confluence]
type = "basic_api_token"
username_ref = "env:CONFLUENCE_LOOKUP_USERNAME"
token_ref = "env:CONFLUENCE_LOOKUP_API_TOKEN"
read_only = true
```

The username is the upstream account's email address. Use a separately restricted
upstream account/token for lookup: `read_only = true` declares its Broker role;
it does not remove write permissions from the upstream token. Lookup-backed
service-mode grants require this credential. Per-user-only paths instead use the
principal's selected credential for lookup and execution.

For per-user credentials, replace the service execution stanza with a
[credential connection](configuration.md#credential-connections). Confluence and
Jira declare the same Atlassian token profiles, so one connection serves both
on one site:

```toml
[credentials.connections.atlassian]
display_name = "Atlassian"
token_profile = "atlassian-api-token"

[credentials.per_user.confluence]
type = "connection"
connection = "atlassian"

[credentials.per_user.jira]
type = "connection"
connection = "atlassian"
```

Each principal stores their own account email and classic API token for the
connection, or an administrator provisions a service account's, and grants use
`credential_mode = "per_user"`. Without Jira, omit its entry. To keep the
products' tokens separate, give each product its own connection with the same
profile. The
[configuration reference](configuration.md#connection-token-profiles) describes
secret sources, token profiles, attachment limits and optional egress/TLS
settings. Atlassian bearer credentials, such as a service account's scoped
token under the `atlassian-bearer-token` profile, additionally require
`cloud_id` and an explicit `https://api.atlassian.com/**` allowlist; credential
kind selects that gateway rather than the tenant route.

For ordinary managed browser or `user_manage` credential management, enable the
owner's self-service flag and grant them a `per_user` action on a service that
uses this connection. Those management paths use current per-user policy
visibility and do not require separate `credentials:self:*` rights for
connection tokens. The account role
alone does not grant invocation access. Deliberately configured classless
management uses explicit scoped credential rights; see the
[administrator guide](administrator-guide.md) for that distinct setup and the
complete user handoff. OAuth connections use grant-based personal setup instead.

Create `confluence_space` resources and action grants through the configured policy
authority, then validate and reload configuration. Start with a granted view or
search action and verify its scope and audit record. The explicit content settings
above enable the write formats used in this document; inspect the running catalog
before using a mutation. Confluence page create/update require an enabled native page format.

### OAuth connections

People can connect their Atlassian account instead of storing a token. Give the
connection an `oauth` registration of the [`atlassian` dialect](oauth.md#atlassian)
for the site, beside `token_profile = "atlassian-bearer-token"` for service
accounts or alone; Jira can use the same connection:

```toml
[providers.confluence]
tenant_host = "example.atlassian.net"
cloud_id = "00000000-0000-0000-0000-000000000000"
allowed_upstream_hosts = [
  "https://api.atlassian.com/ex/confluence/**",
  "https://api.media.atlassian.com/**",
]

[credentials.connections.atlassian]
display_name = "Atlassian"
token_profile = "atlassian-bearer-token"
oauth = { registration = "atlassian", profile = "default" }

[credentials.per_user.confluence]
type = "connection"
connection = "atlassian"
```

- **Route.** OAuth always goes through the Atlassian gateway,
  `https://api.atlassian.com/ex/confluence/<cloud_id>/wiki/rest/api/` and its
  `wiki/api/v2/` sibling, so `cloud_id` and `api.atlassian.com` are required;
  a classic API token keeps the site route and a bearer token the gateway. A
  connection with `oauth` cannot use `atlassian-api-token` (see the
  [validation table](oauth.md#atlassian-registration)).
- **Access per request.** Before every request, including the page, blog,
  space and comment lookups before policy and at execution, list pages and
  read-backs, Confluence revalidates the invocation's lease and pins its
  access to the gateway route's cloud ID and the `api.atlassian.com`
  audience. Access for another site fails as `credential_invalid` before
  anything is sent.
- **401.** The lookups and the execution share one recovery: when Confluence
  answers the connection's access with 401, the Broker marks it rejected,
  renews it once and repeats the request, writes and uploads included,
  because the 401 applied nothing. A second 401 fails as `credential_invalid`,
  asking the person to reconnect Atlassian. A connection that cannot be
  refreshed fails with its own reason, such as `concurrency_limited` while
  another refresh runs.
- **Writes.** A connection failure before a write keeps its own reason and
  carries no receipt; in an attachment batch, before any upload applied, the
  batch fails with it. One that stops a read-back after Confluence accepted
  the write, including a draft attachment's verification, reports
  `mutation_verification_failed` with an `applied_unverified` receipt.
- **Personal spaces.** `~key` spaces read, search and write through the
  gateway like team spaces.
- **Verification.** Credential verification (`user/current`) applies to
  stored and service tokens; OAuth connections are checked by connecting them.

Each action needs these Atlassian OAuth scopes. Confluence's REST API v1 calls
use classic scopes and its v2 calls granular ones:

| Actions | Scopes |
| --- | --- |
| `page.view`, `attachment.list`, `verify` | `read:confluence-content.all` |
| `search`, `blog.search` | `search:confluence` |
| `page.update` | `read:confluence-content.all`, `write:confluence-content` |
| `page.move` | `read:confluence-content.all`, `write:confluence-content`, `read:page:confluence`, `read:space:confluence`, `read:content.metadata:confluence`, `read:hierarchical-content:confluence` |
| `page.create`, `page.draft.create`, `page.draft.stage` | `read:confluence-content.all`, `read:page:confluence`, `read:space:confluence`, `write:page:confluence` |
| `page.draft.view`, `blog.view`, `blog.draft.view` | `read:page:confluence`, `read:space:confluence` |
| `page.draft.update`, `blog.update`, `blog.draft.stage`, `blog.draft.update` | `read:page:confluence`, `read:space:confluence`, `write:page:confluence` |
| `blog.create`, `blog.draft.create` | `read:space:confluence`, `write:page:confluence` |
| `page.draft.publish`, `blog.draft.publish` | `read:confluence-content.all`, `read:page:confluence`, `read:space:confluence`, `read:attachment:confluence`, `write:page:confluence` |
| `page.draft.discard` | `read:confluence-content.all`, `read:page:confluence`, `read:space:confluence`, `delete:page:confluence` |
| `blog.draft.discard` | `read:page:confluence`, `read:space:confluence`, `delete:page:confluence` |
| `page.draft.verify`, `page.draft.attachment.list`, `blog.draft.verify`, `blog.draft.attachment.list`, `blog.attachment.list` | `read:page:confluence`, `read:space:confluence`, `read:attachment:confluence` |
| `page.draft.attachment.add`, `blog.draft.attachment.add` | `read:page:confluence`, `read:space:confluence`, `read:attachment:confluence`, `write:confluence-file` |
| `page.draft.attachment.download`, `blog.draft.attachment.download` | `read:page:confluence`, `read:space:confluence`, `read:attachment:confluence`, `readonly:content.attachment:confluence` |
| `attachment.add` | `read:confluence-content.all`, `write:confluence-file` |
| `attachment.download` | `read:confluence-content.all`, `readonly:content.attachment:confluence` |
| `blog.attachment.add` | `read:page:confluence`, `read:space:confluence`, `write:confluence-file` |
| `blog.attachment.download` | `read:confluence-content.all`, `read:page:confluence`, `read:space:confluence`, `readonly:content.attachment:confluence` |
| `blog.verify` | `read:confluence-content.all`, `read:page:confluence`, `read:space:confluence` |
| `page.*_comment.list`, `.view` and `.reply.list`, and the `blog.*` equivalents | `read:comment:confluence` and the container's reads |
| `page.footer_comment.add`, `blog.footer_comment.add` | `write:comment:confluence` and the container's reads |
| `*_comment.reply.add`, `*_comment.update` on pages and blogs | `read:comment:confluence`, `write:comment:confluence` and the container's reads |
| `*_comment.delete` on pages and blogs | `read:comment:confluence`, `delete:comment:confluence` and the container's reads |

A comment's container reads are `read:confluence-content.all` for a page and
`read:page:confluence` with `read:space:confluence` for a blog post.
`read:confluence-user` serves only token verification and is not needed. The
registration also requests `read:me` and `offline_access`; see
[Atlassian scopes](oauth.md#atlassian-scopes).

### Personal spaces

A personal space uses the same `confluence_space` resource type as a team space.
Use its actual Confluence key, including the leading `~`: for example,
`https://example.atlassian.net/wiki/spaces/~alice/overview` identifies `~alice`.
Keep the key's case and spelling; do not construct it from the Broker username
or the upstream account's email address.

This example grants Alice page reads and search in that one personal space. It
assumes Alice's Broker principal, the `default` execution context, and the
Confluence credential connection described above are configured:

```bash
agent-access admin policy resources create \
  --id confluence-alice-personal --resource-type confluence_space \
  --selector-kind exact --selector-value '~alice' \
  --execution-context default --display-name "Alice's personal Confluence space"

agent-access admin policy grants create \
  --grant-id confluence-alice-personal-read --subject user:alice@example.com \
  --service confluence --action page.view --action search \
  --execution-context default --resource-id confluence-alice-personal \
  --credential-mode per_user --description "Alice's personal space reads"
```

The resource and grant can also be created in the portal's catalog and policy
editors. Its display name is descriptive: the explicit grant determines who can
access `~alice`. `per_user` selects the caller's upstream credential; it does not
resolve a user's home or restrict access to spaces they own. A service-mode
grant can address the same resource with a shared credential. In both cases,
Confluence's permissions still apply. An `all` space selector includes personal
spaces permitted by the selected upstream credential, subject to the grant's
exclusions and token restrictions.

This coverage applies to existing `all` resources in grants, groups, and token
restrictions too. Review them before upgrading, especially service-mode grants
using shared credentials. Select exact team-space resources when access must
remain limited to team spaces. Exact personal-space exclusions cover only the
listed keys; newly created personal spaces remain within `all` coverage.

Exclusions also compare the exact key, including case: excluding `~Alice` has
no effect on a space reported as `~alice`. Copy the key from a Broker content
result's `space` field and preserve it in the excluded resource. Confirm an
exclusion using a page ID, for example
`agent-access confluence page view 123456`, as well as search; the ID lookup
checks the space reported by Confluence.

For example, search the granted space with
`agent-access confluence page search --space '~alice' --text 'notes'`.
Use a page ID or a supported page URL to read a page; the space overview URL
above identifies the resource key but is not a page locator.

## Access surfaces and examples

Confluence actions are available through the typed CLI wrappers, generic
`agent-access invoke`, JSON `agent-access send` request files, and direct HTTP
`POST /v1/invoke/confluence/{action}`. Use `agent-access spec catalog` against
the target broker to see the caller-visible hot catalog before relying on an
action or input schema.

Typed CLI examples:

```bash
agent-access --url http://127.0.0.1:8787 confluence page view 123456789
agent-access --url http://127.0.0.1:8787 confluence page view 123456789 --read-content-format markdown
agent-access --url http://127.0.0.1:8787 confluence page view 123456789 --output-format markdown
agent-access --url http://127.0.0.1:8787 confluence page view --page-url 'https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456789'
agent-access --url http://127.0.0.1:8787 confluence page create --space ENG --title 'Deploy Runbook' --content-file page.md --content-format markdown
agent-access --url http://127.0.0.1:8787 confluence page create --space ENG --title 'Child Runbook' --parent 123456789 --content-file child.storage.html --content-format storage
agent-access --url http://127.0.0.1:8787 confluence page update 123456789 --base-version 7 --content-file page.adf.json --content-format atlas_doc_format
agent-access --url http://127.0.0.1:8787 confluence page move 234567890 --position append --target 123456789
agent-access --url http://127.0.0.1:8787 confluence page move 234567890 --position before --target 345678901
agent-access --url http://127.0.0.1:8787 confluence page draft create --space ENG --title 'Draft Runbook' --content-file draft.md --content-format markdown
agent-access --url http://127.0.0.1:8787 confluence page footer-comment add 123456789 --content 'Deployment complete.' --content-format plain_text
agent-access --url http://127.0.0.1:8787 confluence page attach 123456789 ./diagram.png --content-type image/png
agent-access --url http://127.0.0.1:8787 confluence page attachment download 123456789 --attachment-id att123 --output ./diagram.png
agent-access --url http://127.0.0.1:8787 confluence blog create --space ENG --title 'Release Notes' --content-file release.md --content-format markdown
```

Generic invoke uses canonical action names and compact JSON inputs:

```bash
agent-access invoke confluence.page.view --input-json '{"pageId":"123456789"}'
agent-access invoke confluence.page.view --input-json '{"pageId":"123456789"}' --read-content-format markdown
agent-access invoke confluence.search --input-json '{"query":{"type":"text","value":"runbook"},"spaces":["ENG"],"maxResults":10}' --output-format markdown
agent-access invoke confluence.page.view --input-json '{"url":"https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456789"}'
agent-access invoke confluence.search --input-json '{"query":{"type":"text","value":"runbook"},"spaces":["ENG"],"maxResults":10}'
agent-access invoke confluence.page.update --input-file confluence-page-update.json
agent-access invoke confluence.page.move --input-json '{"pageId":"234567890","position":"before","targetPageId":"345678901"}'
```

Example `confluence-page-update.json`:

```json
{
  "pageId": "123456789",
  "baseVersion": 7,
  "contentFormat": "markdown",
  "content": "## Updated content\n\nDeployment completed."
}
```

JSON `send` request files use the same service/action/input vocabulary:

```json
{
  "version": "agent-access.send.v1",
  "kind": "invoke",
  "service": "confluence",
  "action": "page.update",
  "inputs": {
    "pageId": "123456789",
    "baseVersion": 7,
    "contentFormat": "markdown",
    "content": "## Updated content\n\nDeployment completed."
  }
}
```

Direct HTTP uses the same action path and wraps inputs under `inputs`. The
example assumes `$AAB_CURL_AUTH` points to a curl config containing the broker
`Authorization` header.

```bash
curl -fsS \
  --config "$AAB_CURL_AUTH" \
  -H "X-Agent-Access-Request-Id: conf-page-view-1" \
  -H "Content-Type: application/json" \
  -d '{"inputs":{"pageId":"123456789"}}' \
  "$BROKER_URL/v1/invoke/confluence/page.view"
```

To preserve the native page body and add an embedded companion, add top-level
`"readContentFormat":"markdown"` (or `"text"`) beside `inputs`. To render the
complete existing result, add top-level `"responseFormat":"markdown"`
instead. These fields are response protocol controls, not Confluence inputs.
Do not combine whole-result Markdown with an explicit non-native embedded
format.

For multipart uploads and raw attachment downloads, prefer `agent-access send`
when using the CLI because it constructs upload metadata and stream outputs.
Direct HTTP multipart and raw-download negotiation are specified in
[http-api.md](http-api.md).

Broker-side malformed-body and unsupported-format failures remain actionable
on lookup-backed actions instead of being normalized to `scope_unresolved`.
After policy authorizes a Confluence mutation, a 400 or 422 may return a
bounded, sanitized `input_invalid` message only from a recognized structured
validation entry with an allowlisted validation code. Free-form top-level
messages and raw upstream bodies are not returned. Lookup, readback,
authentication, permission, existence, scope, conflict, throttling, and
server-error bodies remain hidden; the existing optimistic-concurrency
`version_conflict` behavior is unchanged. A Confluence HTTP 429 returns
`upstream_rate_limited` with the bounded `Retry-After` wait when Confluence
sends one; see [http-api.md](http-api.md#reason-code-table). When throttling
of an upload stops a page, blog, or draft attachment batch before any file was
created, the error uses `upstream_rate_limited`. If earlier files were created,
waiting and repeating the batch would upload them again, so the error is
`mutation_verification_failed`: the partial result keeps `status: "partial"`,
`attachments`, and `failures`, and adds `mutationStatus: "applied_unverified"`,
`retrySafe: false`, `verificationStage: "attachment_upload"`, and
`safeLocators` with the page or blog and created attachment IDs, with no retry
wait. Upload only the failed and skipped files, later.

Throttling after a mutation was applied is never `upstream_rate_limited`. When
the readback or verification that follows a page create, page move, page draft
create, draft publish, draft discard, comment update or reply, or a draft
attachment upload is throttled, the error is `mutation_verification_failed`
with `mutationStatus: "applied_unverified"`, `retrySafe: false`,
`verificationStage` (such as `post_create_readback`,
`post_move_hierarchy_readback`, `post_move_order_readback`,
`post_publish_attachment_readback`, `post_discard_readback`,
`post_update_readback`, or `post_upload_readback`), and `safeLocators` with the
page, blog, comment, or attachment IDs, and no retry wait. A draft attachment
batch keeps its partial result: verified uploads stay in `attachments`, the
unverified upload is a `failures` entry with `status: "unverified"` and its
`attachmentId`, later files are `skipped`, and `safeLocators.attachmentIds`
lists every created attachment. Inspect those objects instead of repeating the
mutation. A person's [OAuth connection](#oauth-connections) failing during such
a readback or verification, or Confluence rejecting its access again, reports
`mutation_verification_failed` with the same receipt, and a draft attachment
batch then reports the uploaded attachments in `safeLocators.attachmentIds`.
Before the mutation, such a failure keeps its own reason without a receipt, and
an attachment batch whose first upload could not present the connection fails
with the connection's own reason.

A Confluence write action sends its mutation request after its reads. When the
Broker proves that request never reached Confluence, because no connection was
established (including a connect timeout) or the request could not be built,
the action keeps its ordinary failure and adds `mutationStatus: "not_applied"`,
`retrySafe: true` to its result: nothing was applied, and the action can be
repeated.

- Page, blog, draft and comment writes, which send a single mutation, fail with
  `upstream_connection_failed` (`Confluence request failed`) or
  `upstream_timeout` (`Confluence request timed out`).
- A page or blog attachment batch whose first upload was never sent keeps
  `upstream_failed` with `Confluence attachment upload failed` or
  `Confluence blog attachment upload failed`.
- A page or blog draft attachment batch whose first upload was never sent keeps
  `upstream_failed` with `Confluence page draft attachment upload partially
  failed` or `Confluence blog draft attachment upload partially failed`, and its
  result keeps `status: "partial"`, the empty `attachments` and `failures`
  alongside the receipt.

A read that was never sent carries no receipt.

Every other write failure after which Confluence may have applied the write
keeps its ordinary reason and message and reports what Confluence may have
done:

| What happened | Receipt |
| --- | --- |
| The mutation request may have been sent but got no response (a timeout, a stalled upload, a connection failure after sending, or an unclassified failure), or Confluence or a proxy answered with a redirect, which the Broker never follows, or a 5xx | `mutationStatus: "unknown"`, `retrySafe: false` |
| Confluence answered the mutation with a success status, but its response then failed, stalled, exceeded the byte cap, did not parse or did not match the request; or anything after the accepted write failed, such as a read-back, a draft handle or the result size | `mutationStatus: "applied_unverified"`, `retrySafe: false`, `verificationStage: "mutation_response"`, or the read-back stage (such as `post_create_readback`) when a read-back request failed |
| A page, blog or draft attachment batch failed after an upload may have created its attachment: an earlier upload succeeded, or the failing upload got no response, a redirect, a 5xx or an unreadable success response | `mutationStatus: "unknown"`, `retrySafe: false`, alongside the batch's result |

`safeLocators` name the target from the validated request and the reads before
the write, such as the `pageId`, `blogId`, `commentId`, `parentCommentId`,
`containerId`, or the `space` and `parentPageId` of a create; a failed
read-back keeps the locators its throttled form reports. A throttled read-back
or batch keeps its `mutation_verification_failed`/`applied_unverified`
outcome. A 4xx rejection, a version conflict and throttling of the write itself
carry no receipt. Page create, page draft create and page move audit records
keep `sideEffectPossible: true` for every mutation failure. Inspect the content
before repeating a write with a `retrySafe: false` receipt.

## Actions and lookup requirements

Thirty-seven actions:

| Action | Required scope type | Pre-authorization metadata lookup |
| --- | --- | --- |
| `page.view` | `space` | yes |
| `search` | `space` | no |
| `page.create` | `space` | lookup-backed; parent lookup when supplied |
| `page.update` | `space` | yes |
| `page.move` | `space` | lookup-backed; moved page, target, and effective parent |
| `attachment.add` | `space` | yes |
| `attachment.download` | `space` | yes |
| `attachment.list` | `space` | yes |
| `verify` | `space` | yes |
| `blog.view` | `space` | yes |
| `blog.search` | `space` | no |
| `blog.create` | `space` | space-key-to-space-ID lookup |
| `blog.update` | `space` | yes |
| `blog.attachment.add` | `space` | yes |
| `blog.attachment.download` | `space` | yes |
| `blog.attachment.list` | `space` | yes |
| `blog.verify` | `space` | yes |
| `page.draft.create` | `space` | lookup-backed; space ID and optional parent |
| `page.draft.stage` | `space` | yes |
| `page.draft.view` | `space` | signed draft handle |
| `page.draft.update` | `space` | signed draft handle |
| `page.draft.publish` | `space` | signed draft handle |
| `page.draft.discard` | `space` | signed draft handle |
| `page.draft.verify` | `space` | signed draft handle |
| `page.draft.attachment.add` | `space` | signed draft handle |
| `page.draft.attachment.list` | `space` | signed draft handle |
| `page.draft.attachment.download` | `space` | signed draft handle |
| `blog.draft.create` | `space` | space-key-to-space-ID lookup |
| `blog.draft.stage` | `space` | yes |
| `blog.draft.view` | `space` | signed draft handle |
| `blog.draft.update` | `space` | signed draft handle |
| `blog.draft.publish` | `space` | signed draft handle |
| `blog.draft.discard` | `space` | signed draft handle |
| `blog.draft.verify` | `space` | signed draft handle |
| `blog.draft.attachment.add` | `space` | signed draft handle |
| `blog.draft.attachment.list` | `space` | signed draft handle |
| `blog.draft.attachment.download` | `space` | signed draft handle |

`search` and `blog.search` do not require pre-authorization metadata lookup.
The action catalog statically classifies `page.create`, `page.draft.create`, and
`page.move` as lookup-backed. `page.create` takes the requested space from
inputs; when a parent is supplied, it resolves that page and requires its
authoritative space to match. Blog create and draft create actions accept a
space key for policy authorization and then resolve that key to the Confluence
v2 `spaceId` needed by upstream. Page draft create also resolves an optional
parent page and requires the same-space relationship. Every current page-id or
blog-id action confirms the content's space by lookup before authorization.
`page.move` resolves the moved page and target; `before`/`after` also resolve
and authorize the target's current parent. It authorizes their common space and
rejects cross-space moves. Draft stage confirms the current page/blog and checks
`baseVersion` before creating a staged draft. Other draft actions resolve policy
scope from the signed draft handle before policy evaluation, then re-read the
draft after authorization. Blog pre-authorization lookup uses only blog ID,
`spaceId`, and resolved space-key evidence; current-status, title, version, and
body checks happen after policy authorizes the resolved space. Page and blog
attachment downloads also resolve only the parent content scope before
authorization; attachment existence and parent-membership checks happen after the
parent content space is authorized.

If content attribution is enabled for Confluence drafts, it applies to draft
body creation/edit actions (`page.draft.create`, `page.draft.stage`,
`page.draft.update`, `blog.draft.create`, `blog.draft.stage`, and
`blog.draft.update`). Publish actions do not add attribution; they publish the
already attributed draft body.

Static config validation requires `credentials.lookup.confluence` whenever any
lookup-backed Confluence grant uses `credential_mode = "service"`. At runtime,
the broker uses that shared lookup credential when a service-mode Confluence
grant can be viable for the caller/action. If all viable Confluence
lookup-backed grants are `per_user`, the broker uses the caller's per-user
Confluence credential for both pre-authorization metadata lookup and any
provider-side execution-time confirmation.

Confluence draft grants require `[broker_tokens].hash_key_ref` to resolve to a
valid 32-byte base64url signing key. A `draftHandle` (prefix
`aab_confluence_draft_v4_`) is a durable broker continuation with no expiry,
signed only with that key scoped to the `confluence` service, so it survives
reloads and restarts and no other backend's tokens verify as Confluence handles.
Without the key, minting or presenting a handle fails explicitly with
`upstream_protocol_failed` ("Confluence draft actions require
broker_tokens.hash_key_ref").

A handle carries the draft's space key, space ID, origin (`new` or `staged`),
staged base version, and page-draft parent placement. It is bound to the
`confluence` service, the execution context it was issued in, the tenant host,
and the content type and ID the action names; any draft action of that content
accepts it. Its owner travels inside it as a keyed commitment: a handle minted
in per-user mode belongs to that principal in per-user mode, while a service-mode
handle intentionally belongs to no principal, so a service-mode draft can be
handed off to any principal admitted in service mode within policy. It also
carries a keyed commitment to the
[credential binding](#continuation-credential-binding) it was minted with.
Before policy, scope resolution verifies the handle, accepts it only when the
caller could own it, and authorizes its space; after admission the handle is
opened again and must match the admitted credential mode, principal and
credential binding. Any other context, tenant, content, owner, credential
binding, key, or handle version is rejected with `invalid_draft_handle`.
Handles from earlier versions are not accepted; create or stage the draft
again. Page draft view, update, publish, verify, discard, and
attachment operations re-read the draft and reject placement drift from the
bound parent.

`basic_api_token` credentials use the tenant bases
(`https://<tenant_host>/wiki/rest/api/` and, for blog metadata/writes/listing,
`https://<tenant_host>/wiki/api/v2/`). `bearer_token` credentials route to the
Atlassian gateway (`https://api.atlassian.com/ex/confluence/<cloud_id>/wiki/...`)
and require `providers.confluence.cloud_id` plus `api.atlassian.com`
allowlisted.

## Browser URLs

Page and blog search, view, create, update, and draft content results include
mandatory `webUrl` and `spaceUrl` fields plus lightweight lifecycle metadata
when upstream provides it: `createdAt`, `updatedAt`, `createdBy`, and
`updatedBy`. User summaries expose only `accountId` and `displayName`. The
broker normalizes URLs as absolute HTTPS
browser URLs on `providers.confluence.tenant_host`; it never returns REST API,
download, media, edit, attachment, cross-host, non-HTTPS, fragment-bearing, or
userinfo/explicit-port URLs. Query-bearing URLs are rejected except for the
exact `viewpage.action?pageId=...` browser page family. The fields are mandatory
for those actions, so malformed upstream `_links.webui` values fail closed
rather than returning relative, unsafe, or null URLs in those fields. When a safe
upstream `_links.webui` proves the expected content ID or space key, the broker
returns that browser URL. Relative upstream web links are interpreted under the
tenant `/wiki` base, so both `/wiki/spaces/...` and `/spaces/...` normalize to
tenant browser URLs. When the upstream content link is missing or is a
same-tenant browser shape that does not prove the content ID, the broker returns
the safe fallback
`https://<tenant_host>/wiki/pages/viewpage.action?pageId=<id>`. Space URLs fall
back to `https://<tenant_host>/wiki/spaces/<space>` when the upstream space link
is missing or is an unrecognized same-space browser path.

`blog.view` and `blog.attachment.list` accept either `blogId` or `url`. The URL
locator accepts `https://<tenant_host>/wiki/pages/viewpage.action?pageId=<numeric-id>`
and modern blog browser paths of the form
`https://<tenant_host>/wiki/spaces/{space}/blog/.../{numeric-id}/...`, with no
userinfo, explicit port, extra query parameters, or fragment. Modern blog URL
space segments are checked against the authoritative blog space. For modern blog
paths, the numeric content ID must be the first path segment after the optional
`YYYY/MM/DD` date prefix; later title-slug segments may be numeric text but are
not treated as content IDs. Date/title-only blog URLs are rejected because they
do not carry a stable numeric content ID.

## Keys, locators, and page-to-space confirmation

- **Page ID** matches `^[1-9][0-9]*$`.
- **Space key** is 2–255 ASCII characters. Team-space keys match
  `^[A-Z][A-Z0-9_-]{1,254}$`; personal-space keys match
  `^~[A-Za-z0-9][A-Za-z0-9._@:+-]{0,253}$`. Keys retain their exact spelling and
  case. A bare `~`, whitespace, slashes, and percent-encoded aliases are invalid.
- **Attachment ID** matches `^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`.

A page may be supplied as a page ID or as a URL. The URL locator
(`page_locator_from_url`) requires `https`, a host equal to `tenant_host`, no
userinfo, no explicit port, and no fragment, and accepts two shapes:

- `/wiki/spaces/{SPACE}/pages/{pageId}/...` — carries a candidate space, and must
  carry no query parameters.
- `/wiki/pages/viewpage.action?pageId={id}` — a single `pageId` query parameter and
  no candidate space.

Any other shape is `locator_invalid`. A caller-supplied `space` field is rejected
by `deny_unknown_fields` on every action except `page.create`, which requires it.
All page-id actions except `page.create` confirm page→space by lookup before
authorization. Attachment downloads confirm the parent page space first, then
prove attachment→page membership after authorization and before streaming bytes.

## `search` and CQL

The `search` input mirrors Jira's: a `query` of `{ type: "cql" | "text", value }`,
an optional `spaces` array (min 1), `maxResults`, and a `nextPageToken`
continuation (see [Search pagination](#search-pagination)). Raw CQL is
parsed into a broker-owned AST and re-emitted canonically. Omit `spaces` to search
all effective broker-authorized spaces after grant, token, and execution-context
restrictions; supply it only to narrow that boundary. Empty or whitespace-only
CQL searches that boundary, and `ORDER BY lastModified DESC` works without a
caller filter. The broker always adds the authorized space constraint when
needed and `type = page` (`type = blogpost` for `blog.search`). Empty `text`
queries remain invalid.

`actions_describe` for service `confluence` and action `search` or `blog.search`
returns a `documentation.cql` block with the accepted fields, aliases,
field-specific operators, sorting, limits, examples, and scope behavior.
The detailed catalog, OpenAPI and send schema also expose this documentation;
MCP `tools/list` keeps the short description and a discovery hint.
Malformed or unsupported CQL returns `input_invalid`, with supported choices
where applicable and no operand values in diagnostics. Actual authorization
and returned-content containment errors retain their existing reason codes.

Caps:

| Limit | Value |
| --- | --- |
| Raw CQL | 4096 bytes |
| Tokens | 512 |
| Parse depth | 32 |
| `IN`-list values | 100 |
| String literal | 512 bytes |
| `ORDER BY` terms | 5 |
| Text query | 512 bytes |

The typed CLI lowers to the same JSON contract:

```bash
agent-access --url http://127.0.0.1:8787 --no-token \
  confluence page search --space ENG --cql 'title ~ "runbook"'
```

is equivalent to invoking `confluence.search` with:

```json
{
  "query": { "type": "cql", "value": "title ~ \"runbook\"" },
  "spaces": ["ENG"]
}
```

Exactly one of `--cql` or `--text` is accepted. A `text` query becomes
`title ~ "<value>"`, not a full-text `text ~ ...` CQL clause.

Accepted CQL fields: `space`, `type`, `id`/`content.id`, `title`, `text`,
`label`/`labels`, `creator`, `contributor`, `mention`, `ancestor`, `parent`,
`created`, and `lastModified`. Supported operators are field-specific:

- `space` accepts `=` and `IN`. Quote personal-space keys, for example
  `space = "~alice"` or `space IN (ENG, "~alice")`.
- `type` accepts only `= page`; other content types such as `blogpost` are
  rejected.
- `id`, `content.id`, `ancestor`, and `parent` accept `=` and `IN` with page IDs.
- `title` and `text` accept only `~` with a quoted string.
- `label`/`labels` accept `=`, `!=`, `IN`, and `NOT IN`.
- `creator` and `contributor` accept `=`, `!=`, `IN`, and `NOT IN`.
- `mention` accepts `=` and `IN`.
- `created` and `lastModified` accept `=`, `!=`, `<`, `<=`, `>`, and `>=`.

CQL functions and `IS EMPTY`/`IS NOT EMPTY` are not supported. Date values must
be valid dates in `YYYY-MM-DD` or `YYYY/MM/DD` form, optionally with `HH:MM`;
they canonicalize to quoted dash-separated values. User-field operands for
`creator`, `contributor`, and `mention` canonicalize to quoted strings whether
they were entered as bare identifiers or quoted strings, which matches
Atlassian's account-id examples. `ORDER BY` supports only `created`,
`lastModified`, and `title`; omitted directions canonicalize to `ASC`.

The broker accepts `parent IN (...)` because Atlassian publishes `IN` for the
Confluence Cloud `parent` field. It does not rewrite that syntax. Live
Confluence Cloud `/wiki/rest/api/content/search` has been observed returning an
upstream error for `parent IN (...)`; the conformance smoke records that as an
expected upstream incompatibility when present.

Scope composition adds `space IN (...)` for finite space coverage or
`space NOT IN (...)` for all-except coverage, grouped with the caller query,
and always injects `type = page`. Positive caller space predicates narrow the
authorized boundary without losing exclusions. Every returned page is validated
against the effective space boundary. Backend search
GETs `content/search` with `cql=<composed>`, `limit=<max>`,
`expand=space,version,history`, and an optional `cursor`. As with Jira, `<max>` (the
caller's `maxResults`) defaults to `providers.confluence.search.max_results`
(default `50`), rejects `0`, and is clamped to that same value, while the response
is bounded by `limits.max_upstream_response_bytes`. Page status is read from the
base content item. Every result must be a current page in an authorized space;
otherwise the request denies with `scope_unresolved` and returns no partial
results.

Personal-space keys are also quoted in injected scope constraints. For example,
`--space '~alice' --cql ''` emits `space IN ("~alice") AND type = page`.

Examples with a finite space scope of `ENG`:

| Input | Composed CQL sent upstream |
| --- | --- |
| `--cql ''` | `space IN (ENG) AND type = page` |
| `--cql 'ORDER BY lastModified DESC'` | `space IN (ENG) AND type = page ORDER BY lastModified DESC` |
| `--text runbook` | `(title ~ "runbook") AND space IN (ENG) AND type = page` |
| `--cql 'title ~ "runbook"'` | `(title ~ "runbook") AND space IN (ENG) AND type = page` |
| `--cql 'text ~ "deploy"'` | `(text ~ "deploy") AND space IN (ENG) AND type = page` |
| `--cql 'labels NOT IN (security, "needs triage")'` | `(label NOT IN (security, "needs triage")) AND space IN (ENG) AND type = page` |
| `--cql 'creator = "abc:123" AND contributor != alice'` | `(creator = "abc:123" AND contributor != "alice") AND space IN (ENG) AND type = page` |
| `--cql 'mention IN ("abc:123")'` | `(mention IN ("abc:123")) AND space IN (ENG) AND type = page` |
| `--cql 'ancestor IN (123456, 234567) AND parent = 345678'` | `(ancestor IN (123456, 234567) AND parent = 345678) AND space IN (ENG) AND type = page` |
| `--cql 'created >= 2024/01/31 AND lastmodified < "2024-02-01 12:30" ORDER BY lastModified DESC, title'` | `(created >= "2024-01-31" AND lastModified < "2024-02-01 12:30") AND space IN (ENG) AND type = page ORDER BY lastModified DESC, title ASC` |

Examples rejected by the broker include `type = blogpost`, `space != OPS`,
`title !~ "runbook"`, `currentUser()`, `content.property.foo = bar`,
`label IS EMPTY`, `created >= 2024-01-01T12:30:00Z`, and mixed `AND`/`OR`
without explicit parentheses.

Live upstream compatibility evidence for the broker-emitted Confluence CQL
subset is collected by the read-only Confluence CQL conformance smoke described
in `docs/testing.md`.

### Search pagination

A `search` or `blog.search` result's `nextPageToken` is an opaque broker-signed
continuation, not Confluence's own cursor. To fetch the next page, pass it back
unchanged as `nextPageToken` to the same action with the same search:

- the same `query` type and canonical CQL (equivalent spellings are the same
  query);
- the same `spaces`, compared as a set;
- the same effective `maxResults`; an omitted value equals the configured
  default, and values above `providers.confluence.search.max_results` equal the
  cap.

The continuation is also bound to the execution context, the principal and
whether it authenticated, the credential mode, the
[credential binding](#continuation-credential-binding), and the Confluence
configuration the cursor depends on: `tenant_host`, `cloud_id`, and whether
`api.atlassian.com` is allowed. Any change rejects the token with
`input_invalid`. Continuations expire 15 minutes after they are issued. They are
signed with a key generated for each broker runtime generation, so a
configuration reload or restart also invalidates them. Confluence may also
expire its own cursor.

A continuation carries no authority and does not bind the effective space
boundary. Every page is authorized again under current policy, its CQL is
composed under the current boundary, and returned content is checked against
it, so a grant change applies from the next page. When that change alters the
composed CQL, the continuation is rejected with `input_invalid` ("the effective
Confluence space scope changed since nextPageToken was issued; repeat the search
without nextPageToken") before Confluence is called; Confluence's cursor is
never sent with a different query. The broker adds no cursor length limit of its
own: Confluence's cursor arrives in a response bounded by
`limits.max_upstream_response_bytes`, and a continuation that would not fit that
bound fails with `upstream_protocol_failed`, never truncated.

### Continuation credential binding

Search continuations, comment and attachment list tokens, and draft handles
are bound to the credential method that reaches Confluence and:

- for a stored or service token, its type, which chooses the tenant or gateway
  route. The token value is not bound, so replacing a stored token with another
  of the same type keeps them;
- for delegated (OAuth) access, the OAuth connection and its generation, never the current access token: a routine
  refresh keeps them, while disconnecting and reconnecting or connecting
  another Atlassian account invalidates them;
- for a route through the Atlassian gateway (a bearer token or OAuth), the
  site's `cloud_id`. A draft handle used with a Basic API token on the tenant
  route therefore survives a `cloud_id` change.

A switch between a token and OAuth, between token types, or to another account
or gateway site rejects a continuation with `input_invalid` and a draft handle
with `invalid_draft_handle`. Draft handles and list tokens signed with the
stable key keep working across restarts while their binding is unchanged.

## Normalized read content and whole-result Markdown

Confluence read presentation uses common invoke-envelope fields and never adds
format controls to Confluence provider inputs. `readContentFormat` accepts
`native`, `markdown`, or `text`; omission is `native`. A non-native request
preserves the existing storage or ADF body and adds
`renderedBody = { format, value }` beside the owning entity's `body`, never
inside the representation map.

Exactly these 26 actions advertise embedded read formats:

| Result family | Actions and companion placement |
| --- | --- |
| Current content view | `page.view`, `blog.view`; `result.renderedBody` beside root `body` |
| Draft view | `page.draft.view`, `blog.draft.view`; `result.renderedBody` beside root `body` |
| Comment collections | `{page,blog}.{footer_comment,inline_comment}.list` and `.reply.list`; each body-bearing `comments[]` item gets its own companion |
| Comment view | `{page,blog}.{footer_comment,inline_comment}.view`; companion inside returned `comment` |
| Footer-comment add | `page.footer_comment.add`, `blog.footer_comment.add`; companion inside returned `comment` |
| Comment update | `{page,blog}.{footer_comment,inline_comment}.update`; companion inside returned `comment` |
| Reply add | `{page,blog}.{footer_comment,inline_comment}.reply.add`; companion inside returned `comment` |

Page, draft, and comment bodies normally have the native shape
`body.<format>.{representation,value}`. `atlas_doc_format.value` is a serialized
JSON string: the Broker checks source bytes before parsing it as ADF. The
current `blog.view` result is the exception and exposes bare
`body.storage` text. Missing or null content and an empty representation map do
not gain a companion; a present empty native body does.

When a current page result contains both configured representations, selection
is deterministic: present `atlas_doc_format` first, otherwise present
`storage`. Malformed selected ADF returns the fixed sanitized
`upstream_protocol_failed`/502 response instead of falling back to storage.
Draft and comment reads normalize the representation already selected by their
native `inputs.bodyFormat`; formatting makes no second provider call.

Storage conversion is deterministic and offline. A bounded fragment parser
preserves namespaced `ac:` and `ri:` elements and handles standard text,
headings, lists, tables, safe links, image alternative text, task/layout
containers, readable Confluence references, and code/noformat macros. Scripts,
styles, frames, objects, embeds, templates, forms, inputs, active HTML/widget/
include macros, macro parameters, and opaque internal identifiers are
suppressed. Valid unknown containers keep safe textual descendants; valid
unknown leaves use a fixed placeholder. The Broker never calls Atlassian's
asynchronous content conversion endpoint.

`responseFormat` accepts `json` or `markdown`; omission is `json`. Exactly
these 26 non-streaming retrievals advertise whole-result Markdown:

- `page.view`, `search`, `verify`, `blog.view`, `blog.search`, and
  `blog.verify`;
- `page.draft.view`, `page.draft.verify`, `blog.draft.view`, and
  `blog.draft.verify`;
- `attachment.list`, `blog.attachment.list`,
  `page.draft.attachment.list`, and `blog.draft.attachment.list`; and
- every `{page,blog}.{footer_comment,inline_comment}.{list,view,reply.list}`.

The renderer uses only the already-produced result, includes every meaningful
present field in stable semantic sections, and preserves identifiers, URLs,
timestamps, versions, counts, order, booleans, and pagination tokens. Page and
blog searches and all attachment lists stay body-free. Comment and reply lists
convert only the bodies already returned; they do not fetch more content or
follow pagination. Verification mismatches format the attached result while
retaining `allow_with_result`, HTTP 409, and CLI exit 2.

HTTP and `send` keep the normal JSON envelope with
`result = { "format": "markdown", "value": "..." }`. Typed commands and
generic `invoke --output-format markdown` print only the Markdown value on an
allowed result. JSON is the typed CLI default, including attachment lists and
draft-attachment lists. Raw attachment downloads and all mutation
confirmations remain ineligible for whole-result Markdown.

All declared returned Confluence bodies are structurally validated and bounded
by `providers.confluence.content.max_body_bytes`, including omitted or explicit
`native` mode. Source parsing, depth/events/work, per-body rendering, aggregate
collection rendering, whole-document output, and the final serialized result
are additionally bounded. Malformed content or any overflow returns only the
fixed sanitized `upstream_protocol_failed`/502 response, never partial or
native fallback output. Native/rendered bodies and pagination tokens are not
recorded in audit, tracing, logs, errors, object identifiers, or metric labels.

Write `inputs.contentFormat`, native-read `inputs.bodyFormat`, embedded
`readContentFormat`, and whole-result `responseFormat` are four distinct
controls. Discover support from the selected caller-filtered action's
`readContentFormats` and `responseFormats`, not from provider configuration or
a Broker version.

## Normalized rich-content write contract

The following twenty actions use required canonical `content` and
`contentFormat` inputs:

| Actions | Formats | Native output |
| --- | --- | --- |
| `page.create`, `page.update` | `storage`, `atlas_doc_format`, `markdown`, `plain_text` | selected native representation for native input; storage for normalized input |
| `blog.create`, `blog.update` | `storage`, `markdown`, `plain_text` | storage |
| `page.draft.create`, `page.draft.stage`, `page.draft.update` | `storage`, `markdown`, `plain_text` | storage |
| `blog.draft.create`, `blog.draft.stage`, `blog.draft.update` | `storage`, `markdown`, `plain_text` | storage |
| `page.footer_comment.add`, `page.footer_comment.update`, `page.footer_comment.reply.add`, `page.inline_comment.update`, `page.inline_comment.reply.add` | `storage`, `markdown`, `plain_text` | storage |
| `blog.footer_comment.add`, `blog.footer_comment.update`, `blog.footer_comment.reply.add`, `blog.inline_comment.update`, `blog.inline_comment.reply.add` | `storage`, `markdown`, `plain_text` | storage |

Current page create/update accept configured `storage` and
`atlas_doc_format`, plus `markdown` and `plain_text` when storage is enabled.
The other eighteen accept `storage`, `markdown`, and `plain_text` when their
storage target is available. Page drafts use hardcoded storage. Current blog
and blog-draft actions depend on `blog_formats`; comments depend on
`comment_formats`. These operator lists contain native representations only.
An action with no effective required-content format is omitted from the runtime
catalog. Clients inspect the exact action's `contentFormat.enum`, never a
Broker version.

Markdown and plain text deterministically convert to constrained storage HTML.
Raw Markdown HTML becomes escaped text; generated HTML uses an allowlisted
element/attribute subset and safe links. Plain text is HTML-escaped and retains
line boundaries without Markdown interpretation. Conversion is offline,
incrementally bounded, never truncates, and has deterministic readable
fallbacks for unsupported constructs. The supported Markdown subset includes
paragraphs, headings, breaks, rules, emphasis/strong/strike/inline code, fenced
and indented code blocks, nested ordered and unordered lists, block quotes,
tables, safe links, and readable image-alt fallbacks.

The provider validates the explicit source format, type, structure, and source
byte cap; validates native input or converts normalized input; applies existing
attribution in native form on the sixteen actions that already support it;
validates the complete native structure; enforces the final serialized native
body cap; then submits upstream. The four comment updates
(`page.footer_comment.update`, `page.inline_comment.update`, and the matching
two blog actions) retain their existing no-attribution behavior. Source,
converted, and mutation-readback bodies never appear in audit, tracing, errors,
or object identifiers. Oversize returns `body_size_denied`/413 and unsupported
formats return `body_format_unsupported`/415.

Caller-supplied native storage must satisfy the configured-format,
non-whitespace, and byte-limit acceptance contract. The Broker does not sanitize
arbitrary native Confluence storage. Broker-generated storage is
strictly validated against the converter's constrained subset. Native
`atlas_doc_format` remains structurally validated.

Write inputs use `content` and `contentFormat`. Read bodies and
read-side representation selectors use the provider-native name
`bodyFormat`; that is separate from write `contentFormat`, embedded
`readContentFormat`, and whole-result `responseFormat`.

Typed commands require exactly one of `--content STRING` and `--content-file
PATH`, plus `--content-format`. `atlas_doc_format` files are parsed as JSON;
storage, Markdown, and plain text are literal UTF-8. File reads have a 512 MiB
CLI safety ceiling, while lower Broker/provider caps remain authoritative.
Inline content may appear in shell history and process listings, so prefer a
file for long or sensitive values. There is no stdin, format inference,
configuration default, or environment override.

## `page.create`, `page.update`, and `page.move`

`page.create` and `page.update` accept `contentFormat` of
`atlas_doc_format`, `storage`, `markdown`, or `plain_text` according to the
effective format rules above. Native storage is a non-empty string; native
`atlas_doc_format` is an Atlassian document
(`{ type: "doc", version: 1, content: [...] }`). Normalized input becomes
storage. `page.create` requires `space`, `title`, `contentFormat`, and `content`.
It optionally accepts exactly one of
`parentPageId` or `parentUrl`. The parent must resolve to a page in the requested
space. If neither parent locator is supplied, Confluence places the page under
the space homepage: the broker sends `root-level=false` without `parentId`, then
verifies the returned page against the resolved homepage ID.

`page.update` is optimistic-concurrency. It requires `pageId`, `baseVersion`
(`>= 1`), `contentFormat`, and `content`. If the page's current version does not equal
`baseVersion` (or the upstream reports a conflict), the request returns
`version_conflict` (HTTP 409). After the update, the page must report
`version == baseVersion + 1`.

`page.move` is a separately granted hierarchy mutation; `page.update`
does not change hierarchy. It requires exactly one moved-page locator (`pageId`
or `url`), a `position` of `before`, `after`, or `append`, and exactly one target
locator (`targetPageId` or `targetUrl`). The page and target must be distinct
current pages in the same space.

For `append`, the target becomes the page's parent and the page is placed last
in that parent's direct-child order. For `before` and `after`, the target is a
sibling; its current page parent becomes the effective parent. A top-level
target without a page parent is rejected. The broker authorizes the moved page,
target, and effective parent, rejects cycles, calls Confluence's corresponding
move operation, then verifies both the effective parent and the direct-child
ordering. Successful results include `position`, `targetPageId`, `parentPageId`,
`previousParentId`, `previousParentType`, `childPosition`, and, for sibling
moves, `targetChildPosition`. The previous parent may be another supported
content-tree type, but the requested target and effective destination parent
must be pages. The action does not clear a page's parent, move pages across
spaces, or target folders, databases, whiteboards, or other non-page content.

## Page and blog drafts

Draft actions are separate from current content actions. Current page and blog
view/update/attachment/verify actions reject non-current content; callers must
use `page.draft.*` or `blog.draft.*` for draft content.

`page.draft.create` and `blog.draft.create` create new draft content through
Confluence REST API v2 with `status = "draft"` and return a `draftHandle`.
Page draft create optionally accepts exactly one of `parentPageId` or
`parentUrl`; the parent must be a page in the requested space. With no parent,
Confluence places the page under the space homepage. Blog draft create does not
accept page hierarchy inputs.
`page.draft.stage` and `blog.draft.stage` create a draft against an existing
current page/blog through the proven `get-draft=true` path: the broker confirms
the current content, checks `baseVersion`, checks that no visible draft already
exists, and then sends a v2 draft update with `status = "draft"` and
`version.number = 1`.

Draft writes accept `storage`, `markdown`, and `plain_text` through the
canonical pair. Normalized input becomes storage. Page drafts use their
hardcoded storage target; blog drafts require configured blog storage support.

`page.draft.view`, `page.draft.update`, `page.draft.publish`,
`page.draft.discard`, and `page.draft.verify` require the content ID and the
matching signed draft handle; blog draft actions use the same shape with
`blogId`. Draft update keeps the draft at version `1`. Publish re-reads the
draft body/title/version, requires draft version `1`, sends `status = "current"`
with `version.number = 1`, and verifies that new-draft attachments still exist
on the published current content. Discard is supported only for new drafts; a
staged draft discard fails closed until live behavior is proven. After a new
draft discard, the broker verifies that the draft is gone and that current
content was not created as a side effect.

New-draft attachment add/list/download are supported for page and blog drafts.
Upload uses the v1 content attachment endpoint with `status=draft` and
`X-Atlassian-Token: nocheck`; listing uses the v2 page/blog attachment endpoint
without a status flag; download uses the v1 content attachment download endpoint
with `status=draft`. Each operation validates the signed draft handle and proves
attachment parent membership before returning metadata or bytes. Staged draft
attachment add/list/download, staged draft discard, attachment delete,
cross-credential draft visibility assumptions, and draft comments are not
implemented; those paths fail closed until live evidence is added.

## Blog posts

Blog actions are separate from page actions. Existing page grants do not
implicitly authorize blog access; policy must list `blog.*` actions explicitly.
The grantable scope remains `space`, and response/audit metadata may include
`blogId` and `spaceId` without adding a grantable `blog` scope.

`blog.view` accepts `blogId` or `url` and returns current blog metadata, the
configured body formats, `webUrl`, and `spaceUrl`.
`blog.create` requires `space`, `title`, `contentFormat`, and `content`; it authorizes
the space key, resolves it to a v2 `spaceId`, and creates the blog post.
`blog.update` requires `blogId`, `baseVersion`, `contentFormat`, and `content`, with
optional `title` and `versionMessage`. Updates are optimistic-concurrency and
must return `version == baseVersion + 1`.

Blog native format support is controlled by
`providers.confluence.content.blog_formats`. Storage is a non-empty UTF-8
string; when enabled it also backs normalized Markdown and plain-text writes.

`blog.search` has the same input shape, authorization planning, and
[pagination](#search-pagination) as page search, but it composes `type = blogpost` and rejects page hierarchy predicates
(`id`, `content.id`, `ancestor`, and `parent`). It uses the v1
`content/search` endpoint with `expand=space,version,history`, an optional
cursor, and validates that every result is a current blog post in an authorized
space.

Examples with a finite space scope of `ENG`:

| Input | Composed CQL sent upstream |
| --- | --- |
| `--text release` | `(title ~ "release") AND space IN (ENG) AND type = blogpost` |
| `--cql 'title ~ "release"'` | `(title ~ "release") AND space IN (ENG) AND type = blogpost` |
| `--cql 'labels IN (release, "llm") ORDER BY created DESC'` | `(label IN (release, "llm")) AND space IN (ENG) AND type = blogpost ORDER BY created DESC` |

Blog metadata, create, update, and attachment listing use Confluence REST API v2.
Blog attachment upload/download use the v1 content attachment endpoints.
Downloads prove explicit attachment-to-blog parent membership after the blog
space has already been authorized. Endpoint choice alone is not accepted as
membership proof.

## Comments

Confluence comments are split by both container and comment kind. Page actions
are `page.footer_comment.*` and `page.inline_comment.*`; blog actions are
`blog.footer_comment.*` and `blog.inline_comment.*`. Page grants do not authorize
blog comments, and footer-comment grants do not authorize inline comments.

The current comment action families are:

| Container | Footer comments | Inline comments |
| --- | --- | --- |
| Page | `list`, `view`, `add`, `update`, `delete`, `reply.list`, `reply.add` | `list`, `view`, `update`, `delete`, `reply.list`, `reply.add` |
| Blog | `list`, `view`, `add`, `update`, `delete`, `reply.list`, `reply.add` | `list`, `view`, `update`, `delete`, `reply.list`, `reply.add` |

Top-level inline comment creation is intentionally not exposed. There are no
broad unscoped comment collection actions; list actions always target a parent
page or blog, and reply-list actions always target a parent comment.

The broker maps these actions to Confluence Cloud REST v2 comment endpoints:

| Operation | Upstream endpoint |
| --- | --- |
| Page footer list | `GET /wiki/api/v2/pages/{id}/footer-comments` |
| Page inline list | `GET /wiki/api/v2/pages/{id}/inline-comments` |
| Blog footer list | `GET /wiki/api/v2/blogposts/{id}/footer-comments` |
| Blog inline list | `GET /wiki/api/v2/blogposts/{id}/inline-comments` |
| Footer view | `GET /wiki/api/v2/footer-comments/{comment-id}` |
| Inline view | `GET /wiki/api/v2/inline-comments/{comment-id}` |
| Footer replies | `GET /wiki/api/v2/footer-comments/{comment-id}/children` |
| Inline replies | `GET /wiki/api/v2/inline-comments/{comment-id}/children` |
| Footer add/reply | `POST /wiki/api/v2/footer-comments` |
| Inline reply | `POST /wiki/api/v2/inline-comments` |
| Footer update | `PUT /wiki/api/v2/footer-comments/{comment-id}` |
| Inline update | `PUT /wiki/api/v2/inline-comments/{comment-id}` |
| Footer delete | `DELETE /wiki/api/v2/footer-comments/{comment-id}` |
| Inline delete | `DELETE /wiki/api/v2/inline-comments/{comment-id}` |

The unscoped `GET /wiki/api/v2/footer-comments` and
`GET /wiki/api/v2/inline-comments` collection endpoints are not exposed.

Comment read bodies use `bodyFormat` and are limited by
`providers.confluence.content.comment_formats`, which currently supports
`storage`. The ten comment writes in the normalized action matrix require
`content` plus `contentFormat = storage|markdown|plain_text`; all normalize to a
non-whitespace storage body. Audit metadata records safe comment IDs, kind,
container IDs, content format, result counts, and pagination state, but never
records source, converted, or readback comment content.

Comment authorization is lookup-backed. For a top-level list or add, the broker
confirms the current parent page or blog and authorizes its space. For a comment
view, update, delete, reply list, or reply add, the broker traverses parent
comments up to a bounded depth until it finds the root page or blog, requiring
every traversed comment to be current and to match the requested comment kind.
The selected execution credential is still used for the requested
list/view/write operation, and comment-id actions re-confirm the same parent
chain with that execution credential before returning, updating, deleting, or
creating comments.

Comment updates require `baseVersion` and send `baseVersion + 1` to Confluence.
If the current comment version differs from `baseVersion`, the broker returns
`version_conflict` without applying the mutation. Delete results return
`{ commentId, status: "deleted" }` after Confluence returns a successful
no-content response.

Comment list pagination uses opaque broker-signed `nextPageToken`
continuations carrying Confluence's cursor. Tokens expire 15 minutes after they
are issued and are bound to the action, comment kind, container type and ID,
parent comment for reply lists, requested filters and effective `maxResults`,
authorized space, execution context, principal and whether it authenticated,
credential mode, [credential binding](#continuation-credential-binding) and
the Confluence route configuration, like [attachment list tokens](#attachments). Upstream next links are accepted only when
they remain on the same Confluence v2 comment collection and contain no
unsupported query parameters. Pagination may come from `_links.next`, `next`, or
an RFC `Link` header with `rel="next"`; multiple next links, changed resources,
unsupported query parameters, or disagreement between body and header next links
fail closed.

List results return `{ comments, count, hasMore, nextPageToken }`, where each
comment includes `commentId`, `kind`, `containerType`, `pageId` or `blogId`,
`space`, `status`, optional `resolutionStatus`, optional author/version/timeline
metadata, optional `parentCommentId`, and a Confluence body map such as
`body.storage.value` and `body.storage.representation`. View and write results
wrap the same comment object as `{ comment }`. The broker rejects attachment,
custom-content, wrong-container, missing-container, non-current, cyclic-parent,
or over-depth comment responses instead of returning partial results.

## Attachments

**`attachment.add`** accepts multipart parts and applies the same per-file checks
as Jira (non-empty `field`/`filename`, no `/` or `\` in the filename, size within
caps, allowlisted media type, 64-hex `sha256`), confirming the page→space first.

**`attachment.download`** confirms page→space by lookup before authorization,
then proves attachment→page membership, validates metadata, and streams the
bounded content with up to 5 allowlisted redirects and same-origin-only auth.

**`attachment.list`** is cursor-paginated. Its input accepts `{ pageId }` or
`{ url }` plus optional `maxResults` and `nextPageToken`. The `nextPageToken` is
an opaque broker-signed continuation carrying Confluence's next position. It
expires 15 minutes after it is issued and is bound to the action, the page ID
and its space, the effective `maxResults` (an omitted value equals the
configured default; larger values equal the cap), the execution context, the principal and whether it
authenticated, the credential mode, the
[credential binding](#continuation-credential-binding) (which includes the
tenant or gateway route), and the Confluence route configuration
(`tenant_host`, `cloud_id`, and whether `api.atlassian.com` is allowed). `blog.attachment.list`
tokens bind the blog ID, space key, and space ID instead of the page. When
`broker_tokens.hash_key_ref` is configured, list tokens are signed with that
stable key and validate across restarts and instances whose clocks differ by up
to a minute; otherwise the broker signs with a key generated for each runtime
generation that cannot validate after a reload, a restart, or on a different
instance. Any other binding, an expired token, or an earlier token version is
rejected with `input_invalid`; every page is authorized again. Confluence
positions are bounded only by `limits.max_upstream_response_bytes`, as for
search.

Draft attachment list pagination tokens use the same continuation model but bind
the draft handle facts (content type and ID, space key and ID, origin, base
version, and parent-page placement) instead of the page, with the effective
`maxResults`. They follow the
handle's ownership: a service-mode listing may be continued by any principal
admitted in service mode, while a per-user listing belongs to its principal.

## `verify`

`verify` requires at least one of `expectVersion` (`>= 1`), `expectTitle`, or
`expectAttachmentId`. The page's space must resolve and authorize first (a missing
or unauthorized page denies with `scope_unresolved`). After authorization, a
mismatch returns decision `allow` with `verification.status = "mismatch"`.
