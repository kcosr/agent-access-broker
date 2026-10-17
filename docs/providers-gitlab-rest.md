# GitLab REST Provider Contract

This document owns GitLab REST-specific action behavior, canonical action names,
URL locators, notes/comments terminology, issue and merge request mutations,
repository metadata, CI/job actions, audit metadata, and attribution notes.
Shared provider concepts and runtime discovery guidance are in
[providers.md](providers.md); CLI-wide behavior is in [cli.md](cli.md).

Service name `gitlab`. Scope type `repository`. Every action advertises
credential modes `[service, per_user]`. It presents `bearer_token` credentials
or, in `per_user` mode, a person's [GitLab OAuth connection](#oauth-connections).

This provider is for GitLab REST API access. It does not implement native Git
fetch/push, clone, checkout, or merge-request checkout flows; those remain the
job of Git HTTP gateway services.

## Operator setup

Configure the REST API root and browser origin for the same GitLab instance:

```toml
[providers.gitlab]
api_base_url = "https://gitlab.example.com/api/v4"
web_base_url = "https://gitlab.example.com"
allowed_upstream_hosts = ["https://gitlab.example.com/api/v4/**"]

[credentials.service.gitlab]
type = "bearer_token"
token_ref = "env:GITLAB_SERVICE_TOKEN"

[credentials.lookup.gitlab]
type = "bearer_token"
token_ref = "env:GITLAB_LOOKUP_TOKEN"
read_only = true
```

The API URL must end in `/api/v4`; retain any instance context prefix in both
URLs and allowlist. Lookup resolves the canonical project, including from a
[moved project's old path](#moved-or-renamed-projects), before repository
policy authorization. Use a separate upstream read credential for service-mode
lookup paths: the Broker's `read_only` declaration does not alter GitLab scopes.
Per-user-only paths use the selected principal credential for lookup instead.

For per-user execution, configure a
[credential connection](configuration.md#credential-connections) with the
`gitlab-access-token` profile and name it from `[credentials.per_user.gitlab]`:

```toml
[credentials.connections.gitlab]
display_name = "GitLab"
token_profile = "gitlab-access-token"

[credentials.per_user.gitlab]
type = "connection"
connection = "gitlab"
```

A [GitLab Git gateway](git-http-gateway.md#credentials-limits-and-audit) can
consume the same connection, so each principal stores one GitLab token for both.
People can instead connect their GitLab account through
[OAuth](#oauth-connections).

Have the principal store their token, connect their account, or provision a
service account's token, and grant `credential_mode = "per_user"`. Upstream
project membership and token or OAuth scopes must support the chosen actions. Configure `git_repository` resources and action grants
through the selected policy authority. Validate and reload the Broker, verify a
small `project.view` or `issue.search`, and inspect audit before write tests.

For ordinary managed browser or `user_manage` credential management, enable the
owner's self-service flag and grant them a `per_user` action on a service that
uses this connection. Those management paths use current per-user policy
visibility and do not require separate `credentials:self:*` rights for
connection tokens. The account role
alone does not grant invocation access. Deliberately configured classless
management uses explicit scoped credential rights; see the
[administrator guide](administrator-guide.md) for that distinct setup and the
complete user handoff. OAuth connections use grant-based personal setup instead.

### OAuth connections

People can connect their GitLab account through OAuth instead of storing a
token: configure a `gitlab` OAuth registration for the instance, as described
in [GitLab OAuth](oauth.md#gitlab), and reference it from the connection:

```toml
[credentials.connections.gitlab]
display_name = "GitLab"
token_profile = "gitlab-access-token" # optional: service-account tokens
oauth = { registration = "gitlab", profile = "default" }
```

People then always use their OAuth connection and never store a token through
it. Service accounts keep administrator-provisioned tokens when the connection
also sets `token_profile`; without it, only people have a GitLab credential.
The registration's `target` must be this provider's instance, `api_base_url`
without `/api/v4`, or `config validate` rejects the connection.

- **Scopes.** The connection acts as the person's GitLab account, within the
  scopes the profile requests and GitLab grants; Broker grants still decide
  which actions and repositories agents reach. Request `api` when you grant
  any write, or `read_api` for read-only REST, and add a repository scope when
  a Git gateway shares the connection ([GitLab scopes](oauth.md#gitlab-scopes)).
  GitLab refuses an action outside the granted scopes or the account's project
  role with 403. That is reported as `upstream_forbidden`, or for a project
  lookup as the concealed `scope_unresolved`, and never renews the access.
- **One lease per invocation.** The project lookup before policy, the lookups
  at execution and the execution itself use one lease on the person's
  connection.
- **Fresh access for every request.** Immediately before each GitLab request,
  including each lookup, page and read-back, the Broker confirms the
  connection is still current and presents its current access for this
  instance, with audience `gitlab`. Access another request renewed meanwhile is
  picked up; access for another instance is refused before anything is sent.
  Page tokens bind the connection, not its access, so they survive a refresh.
- **401 recovery.** GitLab invalidates both earlier tokens on every refresh,
  so a request in flight while another refreshes is answered 401. GitLab
  applied nothing it answered with 401: the Broker marks that access rejected,
  renews it once per invocation, whether the 401 answered a lookup or the
  execution, and repeats the request, including a write or an upload. Another
  401 in the same invocation fails as `credential_invalid`; if it persists,
  reconnect GitLab in the portal. Connection failures, such as a connection
  that needs reconnecting after a lost refresh response, consent in progress,
  or refresh busy or throttled, are reported as described in
  [refresh, durability and recovery](oauth.md#refresh-durability-and-recovery),
  with their retry metadata, including at a review submission's GitLab version
  check. Such a failure before a write applied nothing. One that stops the
  read-back of a write GitLab applied reports the write as
  `mutation_verification_failed` with `mutationStatus = "applied_unverified"`,
  `retrySafe = false` and its safe locators instead; see
  [unsent and unanswered writes](#unsent-and-unanswered-writes).
- **Token-only actions.** Project and service-account token issuance and
  rotation need a personal access token, so they are unavailable through an
  OAuth connection; see [bot accounts and issued tokens](#bot-accounts-and-issued-tokens).
- **Verification.** Credential verification reads `/user` with stored tokens.
  An OAuth connection identifies its GitLab account when the person connects.

Provisioning and webhook destinations have additional opt-in controls described
below and in [bot provisioning](gitlab-bot-provisioning.md). REST grants do not
authorize native Git fetch/push; configure the [Git gateway](git-http-gateway.md)
separately. Egress, TLS, limits and credential sources are in the
[configuration reference](configuration.md).

## Project uploads

`project.upload` is a repository-scoped write backed by GitLab's
[`POST /projects/:id/uploads`](https://docs.gitlab.com/api/project_markdown_uploads/#create-an-upload).
Supply exactly one `project` path or configured-instance project `url`, plus one
file. The Broker confirms the canonical upstream project and enforces the
existing grant and broker-token restrictions before sending bytes with the
selected service or per-user credential. This uploads an attachment; use its
returned Markdown in a separately authorized issue/MR/note write to publish a link.

```bash
agent-access gitlab project upload team/project --file session.html --content-type text/html
agent-access gitlab project upload --project-url https://gitlab.example.com/team/project --file session.html
```

JSON `send` generates the filename, size, SHA-256 and multipart metadata from
the local file:

```json
{
  "version": "agent-access.send.v1",
  "kind": "invoke",
  "service": "gitlab",
  "action": "project.upload",
  "inputs": { "project": "team/project" },
  "files": [
    { "role": "attachment", "path": "session.html", "contentType": "text/html" }
  ]
}
```

Run `agent-access send --request-file upload.json`. Use typed CLI or `send`
for files: generic `invoke` accepts JSON inputs and cannot carry file parts.
The canonical HTTP invoke action, hot catalog, OpenAPI and send schema declare
the one-file constraint.

Direct HTTP uses `POST /v1/invoke/gitlab/project.upload` with multipart fields:
the first part is `request` (`application/json`) containing
`{"inputs":{"project":"team/project","attachments":[{"field":"file0","filename":"session.html","contentType":"text/html","size":123,"sha256":"<64 lowercase hexadecimal characters>"}]}}`;
the second part is `file0`, with matching filename, MIME type, actual byte count
and SHA-256. Metadata is authorized before file parts are read. The Broker
spools bounded bytes privately and removes the temporary file after invocation.
Plain JSON cannot supply the file contents.

The JSON response includes `result.upload` with `alt`, `url`, `fullPath`,
`markdown`, and optional `id`. GitLab's `url` is its attachment Markdown path;
`fullPath` is the web attachment path. Preserve the returned `markdown` when
linking it. `id` is absent on GitLab versions before its introduction in 17.3.
The file bytes are passed through unchanged, including HTML exports; issue/MR
content conversion and attribution do not modify the uploaded file.

`providers.gitlab.attachments` defaults to a 10 MiB per-file cap, a 50 MiB
aggregate cap, and an unrestricted MIME list. Exactly one file is allowed, so
both caps apply to that file. Configured MIME allowlists must include `text/html`
for HTML exports. Global HTTP-body, upload-spool and timeout limits also apply,
and the upstream instance may impose a smaller size limit. Filename, MIME,
size and digest must match the received file; extra or missing parts fail.
Audit records omit file contents, credentials and secret attachment URLs/Markdown.

GitLab [attachment access](https://docs.gitlab.com/security/user_file_uploads/#access-control-for-uploaded-files)
follows project visibility, including when linked from a confidential issue or
MR. Public-project uploads can be publicly accessible. Treat returned attachment
paths and Markdown as sensitive. Uploads are not rendered or scanned by the
Broker. The API can create an attachment before a response is lost; inspect the outcome before retrying an uncertain upload.

## Access surfaces and examples

GitLab REST actions are available through the typed CLI wrappers, generic
`agent-access invoke`, JSON `agent-access send` request files, and direct HTTP
`POST /v1/invoke/gitlab/{action}`. Use `agent-access spec catalog` against the
target broker to see the caller-visible hot catalog before relying on an action
or input schema. Canonical GitLab REST action names use GitLab's term `note`
where the typed CLI uses the user-facing term `comment`.

Typed CLI examples:

```bash
agent-access --url http://127.0.0.1:8787 gitlab project view team/project
agent-access --url http://127.0.0.1:8787 gitlab project view team/project --output-format markdown
agent-access --url http://127.0.0.1:8787 gitlab project view --project-url 'https://gitlab.example.com/team/project'
agent-access --url http://127.0.0.1:8787 gitlab issue view team/project 123 --read-content-format markdown
agent-access --url http://127.0.0.1:8787 gitlab issue view team/project 123 --output-format markdown
agent-access --url http://127.0.0.1:8787 gitlab issue create team/project --title 'Fix deploy docs' --content-file issue.md --content-format markdown --label docs
agent-access --url http://127.0.0.1:8787 gitlab issue comment team/project 123 --content 'Looks good.' --content-format plain_text
agent-access --url http://127.0.0.1:8787 gitlab merge-request view team/project 45
agent-access --url http://127.0.0.1:8787 gitlab merge-request list-discussions team/project 45 --max-results 20
agent-access --url http://127.0.0.1:8787 gitlab merge-request view-discussion team/project 45 DISCUSSION_ID
agent-access --url http://127.0.0.1:8787 gitlab merge-request list-diffs team/project 45 --unidiff
agent-access --url http://127.0.0.1:8787 gitlab merge-request list-diff-versions team/project 45
agent-access --url http://127.0.0.1:8787 gitlab merge-request diff-raw team/project 45 --output mr-45.diff
agent-access --url http://127.0.0.1:8787 gitlab merge-request comment team/project 45 --content-file review.md --content-format markdown
agent-access --url http://127.0.0.1:8787 gitlab merge-request discussion team/project 45 --content-file discussion.md --content-format markdown
agent-access --url http://127.0.0.1:8787 gitlab file view team/project --path README.md --ref main
agent-access --url http://127.0.0.1:8787 gitlab job trace team/project 67890 --output job-trace.txt
```

Generic invoke uses canonical action names and compact JSON inputs:

```bash
agent-access invoke gitlab.project.view --input-json '{"project":"team/project"}'
agent-access invoke gitlab.issue.view --input-json '{"project":"team/project","iid":123}'
agent-access invoke gitlab.issue.view --input-json '{"project":"team/project","iid":123}' --read-content-format text
agent-access invoke gitlab.issue.search --input-json '{"project":"team/project","state":"opened","maxResults":10}' --output-format markdown
agent-access invoke gitlab.issue.view --input-json '{"url":"https://gitlab.example.com/team/project/-/issues/123"}'
agent-access invoke gitlab.issue.search --input-json '{"project":"team/project","state":"opened","search":"deploy","maxResults":10}'
agent-access invoke gitlab.issue.note.add --input-json '{"project":"team/project","iid":123,"content":"Looks good.","contentFormat":"plain_text","confidential":false}'
agent-access invoke gitlab.merge_request.note.add --input-json '{"project":"team/project","iid":45,"content":"**Review note.**","contentFormat":"markdown"}'
agent-access invoke gitlab.merge_request.discussion.list --input-json '{"project":"team/project","iid":45,"maxResults":20}'
agent-access invoke gitlab.merge_request.discussion.view --input-json '{"project":"team/project","iid":45,"discussionId":"DISCUSSION_ID"}'
agent-access invoke gitlab.merge_request.diff.list --input-json '{"project":"team/project","iid":45,"maxResults":20,"unidiff":true}'
agent-access invoke gitlab.merge_request.diff_version.view --input-json '{"project":"team/project","iid":45,"diffVersionId":7,"unidiff":true}'
```

JSON `send` request files use the same service/action/input vocabulary:

```json
{
  "version": "agent-access.send.v1",
  "kind": "invoke",
  "service": "gitlab",
  "action": "issue.view",
  "inputs": {
    "project": "team/project",
    "iid": 123
  },
  "responseFormat": "markdown"
}
```

`send` keeps the standard JSON response envelope. Extract
`result.format = "markdown"` and `result.value`; CLI config and environment
presentation defaults are never injected into a request file.

Direct HTTP uses the same action path and wraps inputs under `inputs`. The
example assumes `$AAB_CURL_AUTH` points to a curl config containing the broker
`Authorization` header.

```bash
curl -fsS \
  --config "$AAB_CURL_AUTH" \
  -H "X-Agent-Access-Request-Id: gitlab-issue-view-1" \
  -H "Content-Type: application/json" \
  -d '{"inputs":{"project":"team/project","iid":123},"readContentFormat":"markdown"}' \
  "$BROKER_URL/v1/invoke/gitlab/issue.view"
```

To request the whole result through HTTP, send
`"responseFormat":"markdown"` beside `inputs`. HTTP remains
`application/json`; the Markdown is returned in
`result = {"format":"markdown","value":"..."}`.

For raw file and job-trace downloads, prefer `agent-access send` when using the
CLI because it handles stream outputs and metadata files. Direct HTTP
raw-download negotiation is specified in [http-api.md](http-api.md). Native Git
fetch/push examples are in [git-http-gateway.md](git-http-gateway.md).

After policy authorizes a GitLab REST mutation, a 400 or 422 may return a
bounded, sanitized `input_invalid` message only from GitLab's structured field
error map and only for fields allowlisted for that action. Scalar messages,
unrecognized fields, and raw upstream bodies are not returned. Lookup,
readback, authentication, permission, existence, repository scope, conflict,
throttling, and server-error bodies remain hidden. This contract applies only
to the REST provider; native Git fetch and push use the separate smart HTTP
gateway contract.

A GitLab HTTP 429 returns `upstream_rate_limited` with the bounded
`Retry-After` wait when GitLab sends one; see
[http-api.md](http-api.md#reason-code-table). GitLab rejects a throttled
mutation request without applying it. When a mutation was accepted but a
readback that verifies it is throttled (webhook create, update, and custom
header changes, as well as review and discussion readbacks), the error is
`mutation_verification_failed`/409 like any other readback failure, with
`mutationStatus: "applied_unverified"`, `retrySafe: false`,
`verificationStage`, and `safeLocators`, and no retry wait: refresh by the
returned IDs instead of repeating the mutation. A write proven never sent is
reported as `not_applied`, and one that may have applied without confirmation
as `applied_unverified` or `unknown`; see
[Unsent and unanswered writes](#unsent-and-unanswered-writes).

## Actions and lookup requirements

Current GitLab REST actions:

| Action | Required scope type | Lookup requirement |
| --- | --- | --- |
| `project.upload` | `repository` | yes; one multipart file |
| `project.view` | `repository` | yes |
| `issue.view` | `repository` | yes |
| `issue.search` | `repository` | yes |
| `issue.create` | `repository` | yes |
| `issue.update` | `repository` | yes |
| `issue.note.list` | `repository` | yes |
| `issue.note.view` | `repository` | yes |
| `issue.note.add` | `repository` | yes |
| `issue.note.update` | `repository` | yes |
| `issue.note.delete` | `repository` | yes |
| `merge_request.view` | `repository` | yes |
| `merge_request.search` | `repository` | yes |
| `merge_request.create` | `repository` | yes |
| `merge_request.update` | `repository` | yes |
| `merge_request.note.list` | `repository` | yes |
| `merge_request.note.view` | `repository` | yes |
| `merge_request.note.add` | `repository` | yes |
| `merge_request.note.update` | `repository` | yes |
| `merge_request.note.delete` | `repository` | yes |
| `merge_request.discussion.list` | `repository` | yes |
| `merge_request.discussion.view` | `repository` | yes |
| `merge_request.discussion.add` | `repository` | yes |
| `merge_request.discussion.inline.add` | `repository` | yes |
| `merge_request.discussion.note.add` | `repository` | yes |
| `merge_request.discussion.note.update` | `repository` | yes |
| `merge_request.discussion.note.delete` | `repository` | yes |
| `merge_request.discussion.resolve` | `repository` | yes |
| `merge_request.discussion.reopen` | `repository` | yes |
| `merge_request.merge` | `repository` | yes |
| `merge_request.reviewer.list` | `repository` | yes |
| `merge_request.commit.list` | `repository` | yes |
| `merge_request.pipeline.list` | `repository` | yes |
| `merge_request.diff.list` | `repository` | yes |
| `merge_request.diff.raw.download` | `repository` | yes |
| `merge_request.diff_version.list` | `repository` | yes |
| `merge_request.diff_version.view` | `repository` | yes |
| `merge_request.draft_note.list` | `repository` | yes |
| `merge_request.draft_note.view` | `repository` | yes |
| `merge_request.draft_note.add` | `repository` | yes |
| `merge_request.draft_note.update` | `repository` | yes |
| `merge_request.draft_note.delete` | `repository` | yes |
| `merge_request.draft_note.publish` | `repository` | yes |
| `merge_request.draft_note.publish_all` | `repository` | yes |
| `merge_request.review.submit` | `repository` | yes |
| `merge_request.approval.view` | `repository` | yes |
| `merge_request.approval_state.view` | `repository` | yes |
| `merge_request.approval_rule.list` | `repository` | yes |
| `merge_request.approval_rule.view` | `repository` | yes |
| `merge_request.approve` | `repository` | yes |
| `merge_request.unapprove` | `repository` | yes |
| `merge_request.suggestion.apply` | `repository` | yes |
| `merge_request.suggestion.batch_apply` | `repository` | yes |
| `branch.list` | `repository` | yes |
| `branch.view` | `repository` | yes |
| `branch.create` | `repository` | yes |
| `protected_branch.list` | `repository` | yes |
| `protected_branch.view` | `repository` | yes |
| `protected_branch.verify` | `repository` | yes |
| `file.view` | `repository` | yes |
| `file.raw.download` | `repository` | yes |
| `file.create` | `repository` | yes |
| `file.update` | `repository` | yes |
| `file.delete` | `repository` | yes |
| `commit.list` | `repository` | yes |
| `commit.view` | `repository` | yes |
| `commit.create` | `repository` | yes |
| `pipeline.list` | `repository` | yes |
| `pipeline.view` | `repository` | yes |
| `pipeline.run` | `repository` | yes |
| `pipeline.retry` | `repository` | yes |
| `pipeline.cancel` | `repository` | yes |
| `job.list` | `repository` | yes |
| `job.view` | `repository` | yes |
| `job.trace.download` | `repository` | yes |
| `job.retry` | `repository` | yes |
| `job.cancel` | `repository` | yes |
| `job.play` | `repository` | yes |
| `webhook.list` | `repository` | yes |
| `webhook.view` | `repository` | yes |
| `webhook.create` | `repository` | yes |
| `webhook.update` | `repository` | yes |
| `webhook.delete` | `repository` | yes |
| `webhook.test` | `repository` | yes |
| `webhook.event.list` | `repository` | yes |
| `webhook.event.resend` | `repository` | yes |
| `webhook.custom_header.set` | `repository` | yes |
| `webhook.custom_header.delete` | `repository` | yes |

All current GitLab REST actions confirm the project through `/projects/:id`
before final policy authorization. For service-mode grants, configure
`credentials.lookup.gitlab` as a read-only `bearer_token`. For per-user-only
paths, the caller's per-user GitLab credential is used for lookup and invocation.

`repository` targets are matched against shared `git_repository` resource
entries selected by grants and token restrictions. Exact canonical paths,
namespace selectors including nested subgroups, and all repositories are
supported. All and namespace selectors include newly created upstream projects;
lookup credentials do not replace authorization. Group exclusions are subtracted
within each grant or token boundary. See [resources.md](resources.md).

## Project webhooks

The ten `webhook.*` actions expose GitLab project hooks only; group, system,
and file hooks are not exposed. Every action is independently grantable,
requires the normal `repository` scope, and executes with the selected service
or per-user GitLab credential. The Broker does not track who created a hook.
Agent Access policy and the selected GitLab user's upstream webhook permission
are both required.

| Action | Operation | Minimum GitLab availability |
| --- | --- | --- |
| `webhook.list` | List bounded hook summaries. | Project hooks API |
| `webhook.view` | Read one complete observable hook. | Project hooks API |
| `webhook.create` | Create one hook. | Project hooks API |
| `webhook.update` | Partially update one hook. | Project hooks API |
| `webhook.delete` | Delete one hook. | Project hooks API |
| `webhook.test` | Send one synthetic event. | 16.11 |
| `webhook.event.list` | Inspect recent delivery rows. | 17.3 |
| `webhook.event.resend` | Resend one historical delivery. | 17.4 |
| `webhook.custom_header.set` | Create or replace one masked header. | 17.1 |
| `webhook.custom_header.delete` | Delete one masked header. | 17.1 |

Signing-token writes require GitLab 19.0 (the feature flag was removed in
19.1). GitLab 19.0 also adds optional `tokenPresent` and
`signingTokenPresent` read fields. Those fields remain absent on older servers.
Unsupported endpoints or fields use the normal sanitized upstream error; the
Broker never retries through a weaker operation. There is no
`webhook.event.view`: GitLab exposes delivery detail only in event-list rows.

### Destination and TLS policy

Operators configure the destination ceiling only in
`[providers.gitlab.webhooks]` in broker TOML. It is not part of a policy grant,
agent token, or portal form. The allowlist is checked before `webhook.create`
and before an update that changes the complete canonical URL. An omitted or
canonically equivalent URL preserves the destination. A path or query change is
a URL change, although query values do not participate in pattern matching.

An empty allowlist denies creation and URL-changing updates. It does not
quarantine existing hooks. With the applicable grant, an agent may list, view,
update without changing the URL, test, inspect deliveries, resend, or delete an
existing hook outside the allowlist. Existing disabled TLS verification may
also be preserved by a URL-preserving update.

Patterns require `http` or `https`, a concrete host, and optional `*`/`**` path
segments. Userinfo, host wildcards, pattern queries, fragments, invalid
wildcards, and duplicate-normalized patterns are rejected. An `http://` pattern
explicitly permits plaintext delivery; there is no separate `allow_http`
switch. Starting disabled certificate verification for HTTPS, including
carrying it onto a changed URL, requires
`allow_disable_ssl_verification = true`.

The Broker validates only the submitted URL. GitLab performs DNS resolution,
redirect handling, and delivery, and GitLab Self-Managed may separately block
local/private destinations. Use GitLab outbound-request filtering and network
egress controls as complementary boundaries.

### Events and update preflight

Create requires `project`, `url`, and a complete `events` array. Update requires
`project`, `webhookId`, and at least one mutable field; omitted fields are
preserved. A present `events` array completely replaces the enabled set.

| Canonical event | GitLab field | Test trigger |
| --- | --- | --- |
| `push` | `push_events` | `push_events` |
| `tag_push` | `tag_push_events` | `tag_push_events` |
| `issues` | `issues_events` | `issues_events` |
| `confidential_issues` | `confidential_issues_events` | `confidential_issues_events` |
| `merge_requests` | `merge_requests_events` | `merge_requests_events` |
| `notes` | `note_events` | `note_events` |
| `confidential_notes` | `confidential_note_events` | not testable |
| `jobs` | `job_events` | `job_events` |
| `pipelines` | `pipeline_events` | `pipeline_events` |
| `wiki_pages` | `wiki_page_events` | `wiki_page_events` |
| `deployments` | `deployment_events` | not testable |
| `releases` | `releases_events` | `releases_events` |
| `milestones` | `milestone_events` | `milestone_events` |
| `feature_flags` | `feature_flag_events` | not testable |
| `emoji` | `emoji_events` | `emoji_events` |
| `resource_access_tokens` | `resource_access_token_events` | `resource_access_token_events` |
| `resource_deploy_tokens` | `resource_deploy_token_events` | `resource_deploy_token_events` |
| `vulnerabilities` | `vulnerability_events` | `vulnerability_events` where Ultimate exposes it |

`webhook.test` accepts only rows with a test trigger and maps to that exact
GitLab path token. No substitute event is sent.

Changing a URL requires exactly one legacy-token disposition: supply sensitive
`token`, or set `clearToken = true`. GitLab may also clear custom headers and
URL variables when the effective destination changes. If the pre-read reports
either, an unconfirmed attempt returns `input_invalid` with bounded non-secret
names in `resetConfiguration` and performs no mutation. Inspect those names and
resubmit with `confirmDestinationReset = true`. URL-variable mutation is not
exposed because substitution could bypass destination authorization.

### Secrets, deliveries, and recovery

Legacy tokens, signing tokens, and custom-header values are sensitive. They are
forwarded but never returned, audited, traced, or placed in errors. Typed
commands accept them only from environment, file, or stdin. JSON `send` callers
should use `secretSources`; generic `invoke` callers should use `--input-file`
or `--input-stdin`, not literal arguments. Direct HTTP necessarily carries
them inside its authenticated TLS request body.

`webhook.event.list` is content-disclosing and should be granted deliberately:
it can return bounded recorded request JSON and receiver response content even
without separate issue or merge-request read actions. Sensitive headers,
including the hook's custom-header names, are replaced with `[REDACTED]`.
Normalized rows omit GitLab's upstream `url` field because URL-variable
interpolation can expose secret values.
Oversized request data is omitted for that row with
`requestDataTruncated = true`; oversized response text is UTF-8-safely
truncated with `responseBodyTruncated = true`.
GitLab retains this endpoint's recent history for seven days and caps pages at
20. `status` accepts an exact three-digit response status or `successful`,
`client_failure`, or `server_failure`. The signed continuation binds the
execution context, principal, credential mode and credential binding (see
[`pageToken`](#locators-and-inputs)), project, hook ID, status, page size, and
upstream page state.

Create, update, delete, and custom-header mutations use readback where GitLab
exposes observable state. Test and resend cause outbound delivery and are
non-retry-safe. The Broker never automatically retries an ambiguous mutation.
`mutation_verification_failed` reports `applied_unverified`,
`retrySafe = false`, and only bounded hook/event IDs in safe locators. A
mutation GitLab accepted whose readback then fails for any reason, including a
401, 403 or 404, is reported this way with the hook's ID: for a create, the ID
GitLab returned, so a retry does not add a second hook unnoticed. Inspect
current state before deciding on a manual retry. An ambiguous custom-header
mutation exposes only the safe hook ID, never the header key or value, and no
receipt carries a token or signing token.

### Error behavior

- malformed URLs, events, statuses, headers, mutually exclusive secrets, or a
  missing URL-change token disposition return `input_invalid`/400;
- an introduced URL or disabled-HTTPS transition outside operator TOML returns
  `webhook_destination_denied`/403 without the URL or allowlist;
- an unconfirmed destination reset returns `input_invalid`/400 plus bounded
  affected key names and performs no PUT;
- until GitLab accepts a mutation, hidden/missing projects, hooks, or events
  retain `scope_unresolved` and GitLab permission failures remain sanitized
  `upstream_forbidden`, without a receipt;
- malformed/oversized upstream structures use `upstream_protocol_failed`;
- a mutation or delivery request proven never sent returns
  `upstream_connection_failed` (or `upstream_timeout` for a connect timeout)
  with `mutationStatus = "not_applied"` and `retrySafe = true`; and
- ambiguous mutations or deliveries, including an accepted mutation whose
  readback fails with any status, use `mutation_verification_failed`/409,
  `applied_unverified`, and `retrySafe = false`.

## Locators and inputs

Project locators accept exactly one of:

- `{ "project": "namespace/repository" }`
- `{ "url": "https://gitlab.example.com/namespace/repository" }`

Issue and merge-request view locators accept exactly one of:

- `{ "project": "namespace/repository", "iid": 123 }`
- `{ "url": "https://gitlab.example.com/namespace/repository/-/issues/123" }`
- `{ "url": "https://gitlab.example.com/namespace/repository/-/merge_requests/123" }`

GitLab web URLs must match `providers.gitlab.web_base_url`; query strings and
fragments are rejected. Bare numeric project IDs are rejected as caller locators
so policy is always expressed in repository-path terms.

Issue and merge-request searches require one canonical `project` path even when
the caller has a namespace or all-repository grant. Those grants authorize the
selected project; they do not enumerate projects or turn these actions into
global searches. Project URLs and numeric project IDs are not search locators.

MCP descriptions explain the project boundary and basic filter behavior. For
extended guidance and examples, call `actions_describe` with `service="gitlab"`
and `action="issue.search"` or `action="merge_request.search"`. The returned
`documentation` includes supported state/sort values and pagination rules.
These stable service/action values also work when a harness renames MCP tools.

Omit `search` and unwanted filters to browse the selected project's items. The
`search` field matches title and description text; it is not JQL or CQL. Use
separate `orderBy` and `sort` fields for sorting. User filters (`assignee`,
`author`, and MR-only `reviewer`) accept usernames rather than numeric user IDs;
`milestone` accepts a title and `labels` requires matching all supplied labels.
`createdAfter` and `updatedAfter` accept inclusive ISO 8601 timestamps, such as
`2026-01-01T00:00:00Z`; Jira relative dates and functions do not apply.

```json
{"project":"team/service","orderBy":"updated_at","sort":"desc"}
```

Issue and merge-request searches accept bounded optional
filters such as `state`, `labels`, `milestone`, `assignee`, `author`,
`reviewer`, `sourceBranch`, `targetBranch`, `search`, `createdAfter`,
`updatedAfter`, `sort`, `orderBy`, `maxResults`, and `pageToken`. The broker
caps `maxResults` to `providers.gitlab.search.max_results`, which remains
limited to GitLab's `100` item REST page cap. Issue searches, merge-request
searches, issue-note lists, merge-request-note lists, merge-request discussions,
reviewers, commits, pipelines, diffs, diff-version lists, draft-note lists, and
approval-rule lists return
`count`, effective `maxResults`, `isLast`, and `nextPageToken` alongside their
normal collection. Continue any action by passing `pageToken` with the original
action, locators, filters, `maxResults`, and `unidiff` choice unchanged; the
four projected review collections also retain `projection`.
`orderBy` is validated per resource: issue search accepts
`created_at`, `due_date`, `label_priority`, `milestone_due`, `popularity`,
`priority`, `relative_position`, `title`, `updated_at`, or `weight`;
merge-request search accepts `created_at`, `updated_at`, `merged_at`,
`label_priority`, `priority`, `milestone_due`, `popularity`, or `title`; note
lists accept only `created_at` or `updated_at`.

`pageToken` is a broker-signed 15-minute continuation bound to the action,
execution context, resolved project path and numeric ID, principal, credential
mode, credential binding, effective page size, validated filters and sort
order, and GitLab provider endpoint fingerprint. The credential binding is the
credential method and, for a stored or service token, its type; the token
value is not bound, so replacing a stored token keeps the continuation. For
delegated (OAuth) access, it is the OAuth
connection and its generation and the instance the access is for, never the
current access token: a routine refresh keeps the continuation, while
disconnecting and reconnecting or connecting another GitLab account
invalidates it. Changing any bound input or the execution context, including a
switch between a token and OAuth, rejects the token. With
`broker_tokens.hash_key_ref`, tokens remain valid across reloads and broker
instances sharing that key; otherwise they use a process-local key and expire
on restart. Validation permits at most 60 seconds of inter-instance clock skew.
The broker never exposes or embeds an upstream continuation URL.
It treats GitLab's `X-Next-Page` as authoritative and requires it to advance by
exactly one page. A `Link` continuation used without that header must identify
the same origin and collection; when both are present, the Link contributes
only a numeric consistency check so reverse-proxy URL rewriting cannot discard
an otherwise valid page. Malformed, conflicting, skipped, or backward
continuations are rejected. GitLab offset pagination does not provide snapshot
isolation, so concurrent upstream edits can still reorder records between pages.

GitLab's Draft Notes list endpoint is not paginated. For
`merge_request.draft_note.list`, the Broker fetches the endpoint's single array
once per request, subject to the configured upstream response-byte cap, and
applies `maxResults` plus a signed local-offset `pageToken`. This preserves the
normal list envelope without pretending GitLab supplied pages. The token does
not provide snapshot isolation: concurrent draft additions, edits,
publication, or deletion can shift the array, so a continuation can repeat or
omit items.

### Moved or renamed projects

When a project, or a group or user namespace above it, is renamed, moved or
transferred, GitLab keeps the old path as a redirect. A `project` path or web
URL with the old path resolves to the project's current identity before
policy: GitLab 16.7 and later answer a lookup of the old path, for a
credential that can read the project, with a redirect naming its numeric ID.
The Broker takes only that ID, without following the redirect or contacting
the host it names, and reads the project by ID from `api_base_url` with the
same lookup credential. Grants, token restrictions, results, audit and page
tokens then use the project's current path and ID, and requests, including
writes, address the project by ID. Earlier GitLab versions answer an old path
with 404, reported as `scope_unresolved`; use the current path there.

- **Authorization uses the current path.** Resource entries name paths, not
  projects: after a move, update the project's entries and groups to its new
  path. An entry for the old path no longer covers the project, but covers any
  project that later takes that path.
- **The current owner wins.** GitLab drops the redirect once another project,
  group or user takes the old path or a namespace above it, and the path then
  names that project, as in GitLab itself. The Broker authorizes and acts on
  that project.
- **Execution rechecks the path.** Execution looks the project up again and
  refuses it with `scope_unresolved` unless its current path is one that was
  authorized, so a project moved between authorization and execution to a
  path that was not authorized is not acted on. A project that took over an
  authorized path in between passes, as any project at that path does. A move
  or takeover between pages invalidates a `pageToken`.
- Results carry the project's current path and `web_url`.

The [Git HTTP gateway](git-http-gateway.md#moved-or-renamed-repositories)
authorizes the path a Git client requests instead.

### Review collection projections and exact note reads

These list actions accept `projection = full|summary`, default to `full`, and
echo the selected projection in the result:

- `issue.note.list`;
- `merge_request.note.list`;
- `merge_request.discussion.list`; and
- `merge_request.draft_note.list`.

`full` preserves the complete normalized objects and existing rich-content
behavior. `summary` keeps stable IDs, actor/state fields, timestamps, commit
association, and the complete normalized `position` when present, but omits
`body`, `renderedBody`, all suggestions, `resolvedBy`, and redundant target
metadata. Absent optional summary fields are omitted rather than serialized as
null. A discussion summary preserves discussion and nested-note order, includes
`noteCount`, and summarizes every nested note without truncating the thread. A
draft summary preserves `discussionId` for replies and `position` for
positioned drafts.

Projection is output-only: authorization, target/owner validation, body caps,
and normalized-position validation run first, and the Broker fetches the same
upstream page. It reduces Broker response and agent-context size, not upstream
GitLab bandwidth. With `summary`, `readContentFormat` is a no-op because no
body owner remains. Whole-result Markdown is still supported and contains
projection, locators, state, timestamps, positions, and pagination without
body or suggestion content.

Continuation tokens bind projection in addition to the existing action,
locator, pagination, sort, execution context, principal, credential-mode,
credential-binding, and endpoint context.
Draft tokens also bind the proven upstream actor ID. Repeat the same projection
with `pageToken`; a `full` token is invalid for `summary` and credential
rotation to a different GitLab actor invalidates a draft continuation.

`issue.note.view` and `merge_request.note.view` are separately grantable exact
reads with `project`, positive `iid`, and positive `noteId`. Each authorizes and
proves the parent issue or merge request, fetches that one note, verifies its
target, enforces the body cap, and returns the full normalized note. Use these
actions when a note ID is known instead of scanning a list. A known discussion
uses `merge_request.discussion.view`; draft-note exact view already exists.

Issue create/update accepts explicit fields only: `title`, canonical
`content`/`contentFormat`,
`stateEvent`, `labels`, `addLabels`, `removeLabels`, `milestone`, `assignees`,
and `confidential`. `assignees` are numeric GitLab user IDs. `labels` is a full
replacement and cannot be combined with `addLabels` or `removeLabels`.
`milestone` is the exact GitLab milestone title string accepted by the issue
write endpoints. Issue view/search/write results include GitLab's
`description` field when GitLab returns it, plus lightweight issue metadata
when present: `createdAt`, `updatedAt`, `author`, `assignees`, `labels`, and
`milestone`. GitLab user summaries expose only `id`, `username`, `name`, and
`webUrl`. Content attribution for `issue.create` and `issue.update` applies only
when the request supplies `content`. Omitting the content pair does not create
a description solely for a footer; explicitly empty content becomes a
footer-only description when attribution is enabled for the action.

Issue notes support list, add, update, and delete. Add accepts required,
non-whitespace `content`/`contentFormat` and optional `confidential`; update
accepts only the required content pair; delete returns
a broker-owned acknowledgement with `deleted: true`, project, IID, and note ID.
`internal` notes and GitLab's deprecated `confidential` update field are not
exposed.

Merge-request create accepts explicit fields only: `sourceBranch`,
`targetBranch`, `title`, canonical `content`/`contentFormat`, `labels`, `assignees`, `reviewers`,
`removeSourceBranch`, `squash`, and `draft`. Merge-request update accepts
`targetBranch`, `title`, canonical `content`/`contentFormat`, `stateEvent`, `labels`, `addLabels`,
`removeLabels`, `assignees`, `reviewers`, `removeSourceBranch`, and `squash`.
`assignees` and `reviewers` are numeric GitLab user IDs. `draft: true` is
implemented by adding GitLab's draft title marker before creation; the provider
does not send unsupported raw request fields. Create preflights both source and
target branches in the resolved project; update preflights a new target branch
when supplied. Cross-project merge requests and target-project overrides are not
exposed. Merge-request view/search/create/update results include GitLab's
`description` field when GitLab returns it. Merge-request
view/search/create/update/merge results include lightweight metadata when
present: `createdAt`, `updatedAt`, `author`, `assignees`, `reviewers`,
`labels`, `milestone`, and `draft`. Content attribution for
`merge_request.create` and `merge_request.update` applies only when the request
supplies `content`; note and discussion add attribution applies to `content`.
The broker appends a deterministic delimited Markdown footer but does not repair
malformed or unterminated caller Markdown, so a footer can render inside an
existing construct such as an unclosed code fence.
`merge_request.merge` omits description content from its returned merge-request
metadata.

Merge-request notes support list, add, update, and delete. An ordinary note is
an overview-page comment from GitLab's Notes API: it is not the complete review
feed and does not carry a file/line position. Use
`merge_request.discussion.list` or `.view` when line association matters.
General merge-request discussions support list/view/add, content-only
discussion-note update, discussion-note delete, thread resolve, and thread
reopen. Resolve and reopen are separate policy actions and call GitLab's
thread-level discussion endpoint; discussion-note update never sends GitLab's
`resolved` parameter. Description, note, and discussion bodies are bounded by
`providers.gitlab.content.max_body_bytes`.

### Merge-request review context

`merge_request.view` preserves review-relevant metadata when GitLab returns it:
the source/target project IDs, `diffRefs` (`baseSha`, `startSha`, `headSha`),
`changesCount`, `userNotesCount`, discussion lock and blocking-discussion
status, conflicts, `preparedAt`, squash commit SHA, and the visible head
pipeline summary. `mergeStatus` remains available, but automation should use
GitLab's `detailedMergeStatus`.

For read results, `diffRefs.baseSha` and `position.baseSha` are `null` when
GitLab reports no merge base; `startSha` and `headSha` remain required and
present. Broker/API-created multiline positions use `old` for removed or
unchanged/context `lineRange` endpoints and `new` for added endpoints; GitLab
UI-created or otherwise returned data may instead expose `null` for an
unchanged/context endpoint. Clients must preserve
the returned type rather than inventing a side. Read results may
therefore preserve a null base SHA. Positioned discussion and draft creation
separately require a complete, non-null base/start/head triplet before the
broker writes.

Discussion results preserve every note's `type`, `commitId`, `position`,
resolver and resolution time, and suggestions. A diff note's `position`
contains its exact reported base/start/head SHA association, old/new paths,
old/new lines or line range, and image coordinates where applicable.
`lineRange` endpoints keep
GitLab's native line code and side/type. A missing position means a general
thread. A position is bound to the diff version on which it was created: after
a push, an old `headSha` and line remain historical evidence and are not
silently remapped to current HEAD. Use `diff_version.view` to inspect that
historical snapshot. Malformed present association data fails the whole result
instead of degrading a diff note into a general comment.

The review-context read actions are:

| Action | Inputs after `project`, `iid` | Result |
| --- | --- | --- |
| `merge_request.reviewer.list` | optional `maxResults`, `pageToken` | Assigned reviewers with normalized user, opaque upstream state, and creation time. |
| `merge_request.commit.list` | optional `maxResults`, `pageToken` | Commits belonging to this MR, distinct from repository `commit.list`. |
| `merge_request.pipeline.list` | optional `maxResults`, `pageToken` | Pipelines attached to this MR, distinct from project/ref `pipeline.list`. |
| `merge_request.diff.list` | optional `maxResults`, `pageToken`, `unidiff` | Current structured diff files and bounded patches. |
| `merge_request.diff.raw.download` | none | Bounded raw current-diff stream plus preflight-head metadata. |
| `merge_request.diff_version.list` | optional `maxResults`, `pageToken` | Historical diff-version IDs, SHA triplets, state, size, and patch ID. |
| `merge_request.diff_version.view` | `diffVersionId`, optional `unidiff` | One exact historical version with bounded commits and file diffs. |
| `merge_request.discussion.view` | `discussionId` | One complete normalized thread. |
| `merge_request.approval.view` | none | Free-tier aggregate approval state and actor-specific fields when returned. |
| `merge_request.approval_state.view` | none | Premium/Ultimate rule-satisfaction state. |
| `merge_request.approval_rule.list` | optional `maxResults`, `pageToken` | Paginated Premium/Ultimate approval rules. |
| `merge_request.approval_rule.view` | `approvalRuleId` | One Premium/Ultimate approval rule. |

Structured diff files preserve paths, modes, patch text, new/renamed/deleted
flags, and optional `generatedFile`, `collapsed`, and `tooLarge` signals.
GitLab may omit patches because of its own diff limits; the Broker preserves
those signals and never claims completeness or truncates a patch. The optional
`collapsed` and `tooLarge` fields require GitLab 18.4 or newer and stay absent
on older servers rather than being synthesized as `false`.

Raw current diff uses GitLab's `/raw_diffs` endpoint and requires GitLab 17.9
or newer. It reuses the bounded streaming/download contract. GitLab provides no
SHA parameter for that endpoint, so result metadata reports
`headShaAtPreflight` but cannot promise an immutable snapshot if the MR advances
during transfer. Use `merge_request.diff_version.view` for version-pinned
review. Unsupported endpoints retain the sanitized upstream failure; the
Broker does not retry as a weaker or semantically different request.

### Direct and pending review participation

`merge_request.discussion.inline.add` creates a current-version text, whole-file,
or image discussion. It requires `expectedHeadSha`, explicit
`content`/`contentFormat`, and a closed `position` object. Text positions use
both paths and exactly one coordinate form: `newLine`, `oldLine`, both for an
unchanged/context line, or `lineRange` endpoints. File positions contain only
paths. Image positions add positive width/height and non-negative integer x/y.
GitLab's REST prose describes x and y as
floats, but the executable Grape parameter contract rejects fractional values;
the Broker validates the runtime contract before mutation.
Multiline callers provide coordinates only; the Broker derives GitLab line
codes and the required native anchor from a bounded verified patch.

Every positioned create freshly reads the MR, requires the full current
base/start/head diff-ref triplet and exact `expectedHeadSha`, and rejects an
unprepared, stale, mismatched, or not-yet-collected version with
`version_conflict` before POST. Missing/ambiguous/reversed range coordinates use
`input_invalid` with safe `inputCategory = coordinates_unresolved`; a missing,
collapsed, too-large, or malformed patch uses `inputCategory =
patch_unavailable`. Diff-version states `overflow` and `without_files` also
mean `patch_unavailable`, not a refreshable version conflict. No positioned
write is retried after an ambiguous upstream result.

`merge_request.discussion.note.add` replies to a proven discussion ID. Because
the target is the thread rather than a newly constructed position, callers can
reply to general, current, or outdated diff discussions. Resolving or reopening
the thread remains a separately granted action.

Draft Notes are the current upstream credential owner's unpublished review:

- `draft_note.list/view` read only drafts visible to that credential;
- `draft_note.add` creates exactly one of a general draft, a positioned draft
  with `expectedHeadSha`/`position`, or a reply draft using
  `inReplyToDiscussionId`; only a reply may set `resolveDiscussion`;
- `draft_note.update` changes content and/or replaces a positioned draft's
  position, preserving the current content or position when the caller omits
  that field; it cannot assign an independent position to a reply draft. A
  body-only update whose stored position lacks a complete full-SHA triplet
  fails with `version_conflict` before the write; retry with
  `expectedHeadSha` and a replacement position from the current diff;
- `draft_note.delete` removes one current-owner draft;
- `draft_note.publish` publishes one draft and, on verified success, returns
  the exact resulting `discussionId` and `noteId`; and
- `draft_note.publish_all` snapshots and publishes all current-owner drafts,
  then optionally creates a general summary note. Optional `internal` is valid
  only with that summary.

Every successful draft-note action and `merge_request.review.submit` includes
`reviewContext`. Its `credentialMode` is `service` or `per_user`,
`credentialBinding` is respectively `shared` or `principal`, and
`upstreamActor` contains only the live GitLab user's positive `id` and non-empty
`username`. Service mode therefore operates on the shared service account's
drafts; per-user mode operates on the selected principal-bound credential's
drafts. The context describes credential selection, not account uniqueness:
two principals can provision credentials for the same GitLab user.

These eight actions advertise
`upstreamResourceOwnership: acting_user` in their caller-filtered capability
metadata. If one returns `scope_unresolved`, the error result includes the
static hint `hints.upstreamResourceOwnership = acting_user`. The hint describes
the action's ownership model only; it does not reveal whether the requested
draft exists, belongs to another actor, or was otherwise unresolved.

Normalized draft notes use `position` as their only authoritative current
location. They do not expose GitLab's top-level `line_code`, which GitLab can
leave stale after a position-only update. Multiline
`position.lineRange.start.lineCode` and `.end.lineCode` remain native anchor
components and are not top-level draft locations.

`merge_request.review.submit` uses the publish-all shape plus required
`reviewerState = reviewed|requestedChanges`. It requires GitLab 19.2 or newer,
checks that the acting upstream user is an assigned reviewer without a formal
approval, publishes that user's snapshotted drafts, verifies the resulting
reviewer state, and then optionally creates a general summary. Zero pending
drafts are valid, so state-only and summary-only submissions work. GitLab
reviewer `requested_changes` is not a formal approval or unapproval; formal
approval actions remain separate.

Before publishing drafts or changing reviewer state, the Broker calls GitLab
`GET /version` with the execution credential and requires a supported version
of 19.2 or newer. An older version returns `upstream_failed`; malformed version
metadata or failed version discovery returns `upstream_protocol_failed`. A
rate-limited version probe returns `upstream_rate_limited`. These failures stop
submission before any write. The version check does not use the lookup credential
or fall back to a different submission workflow.

Recording `requestedChanges` does not alone establish that merging is blocked.
GitLab provides requested-change merge blocking only in Premium/Ultimate, and
the behavior depends on project configuration. Use applicable merge-status and
project-policy reads when deciding merge eligibility; never derive it solely
from a reviewer entry.
An unassigned acting user returns `version_conflict` before publication so the
caller refreshes assignment/reviewer state rather than treating it as policy
denial.

### Formal approvals and suggestion application

Formal approval is separate from reviewer state. `merge_request.approval.view`
returns GitLab's free-tier aggregate summary, including `approvalsRequired`,
`approvalsLeft`, `approved`, `approvedBy`, `userHasApproved`, and
`userCanApprove` when returned. The aggregate `approved` value has
edition-dependent semantics and never proves that the acting user approved;
use `approvedBy` and `userHasApproved` for actor-specific state.
`merge_request.approval_state.view` and approval-rule list/view expose
Premium/Ultimate rule satisfaction. They preserve
`approvalRulesOverwritten`, eligible and approved users/groups, `overridden`,
`containsHiddenGroups`, `codeOwner`, nullable `section`, and nullable
`sourceRule.approvalsRequired` when GitLab returns them. Tier or permission
failures remain sanitized upstream errors rather than empty rules.

`merge_request.approve` requires `headSha`. Before writing, the Broker proves
the acting numeric user, exact current MR head and diff-ref triplet, a matching
latest collected diff version, a prepared MR whose detailed merge status is
not `preparing`, `checking`, or `approvals_syncing`, and a non-null
`patchIdSha`. It sends the exact SHA to GitLab and verifies that the acting user
appears in `approvedBy` and that `userHasApproved` is true when present.
`merge_request.unapprove` removes only the acting credential owner's approval
and verifies the inverse actor-specific state. Neither action uses aggregate
`approved` as actor proof; neither accepts an approval password.
If a fresh actor-specific approval summary proves the actor is already approved
for `approve`, or has no approval for `unapprove`, the Broker returns
`version_conflict` (HTTP 409) before any GitLab approval POST.

A null patch ID is a hard readiness block. In particular, an unchanged empty
diff or untouched legacy version can retain null indefinitely; refreshing and
retrying the same approval cannot make it ready. A push, rebase, or other
branch change that creates a prepared diff version is required before retry,
and an unchanged empty-diff MR cannot be approved through the Broker.

`merge_request.suggestion.apply` applies one suggestion proven through its
scoped discussion/note. `merge_request.suggestion.batch_apply` accepts 1 to
100 unique `{discussionId,noteId,suggestionId}` entries from one MR. Both
require `expectedHeadSha`; an applicable suggestion whose stored position head
does not match it is rejected as `input_invalid` with fixed category
`suggestion_outdated`. The optional `commitMessage` is bounded Git commit
message template text, not rich content. GitLab expands its documented
`%{...}` placeholders; supplying a message replaces GitLab's default message,
including its default `Co-authored-by` trailer, while the execution credential
remains the commit author.

The Broker re-reads every scoped discussion/note before the global suggestion
endpoint and proves each suggestion is unapplied and applicable. GitLab's
endpoint accepts no expected SHA, so GitLab's live source-head comparison is
the final atomic race guard. The credential must be allowed to push the MR
source branch. Applying a suggestion does not resolve its discussion; callers
use the separately grantable resolve action when desired.

Suggestion application may write a fork's source repository. Immediately
before mutation, the Broker re-reads the target MR, resolves the canonical
source project, and authorizes both target and source repository scopes. One
selected grant must cover the complete deduplicated scope set through exact
repository and/or namespace selectors; grants are never combined to obtain
coverage. Same-project MRs resolve to one scope. A changed, hidden, missing, or
malformed source identity fails closed before the global endpoint.

GitLab can return `applied = false` in an accepted suggestion response even
after committing. The Broker therefore validates response IDs and re-reads
every scoped discussion/note, requiring each requested suggestion to be
applied. Successful results contain verified suggestion IDs/state only. GitLab
returns no commit metadata, so the Broker neither exposes nor infers it.
Readback failure or any missing, contradictory, or still-unapplied suggestion
after an accepted mutation uses `mutation_verification_failed`; callers must
refresh the safe suggestion locators and must not automatically retry.

Per-user credentials make drafts, comments, and reviewer state belong to the
delegated GitLab user. Service mode is supported for deliberate bot-reviewer
workflows, but all Broker principals sharing that credential share the bot's
draft set and can observe, update, delete, or publish it when granted those
actions. Sample high-impact reviewer grants therefore use `per_user`.

Every review mutation verifies its effect and returns `mutationStatus = "applied"`
with `retrySafe = false` on success. If GitLab may have applied the mutation but
the Broker cannot prove the final state, the response is HTTP 409,
`decision = "error"`, `reasonCode = "mutation_verification_failed"`, and CLI
exit 2, with `mutationStatus = "applied_unverified"`, `retrySafe = false`, a
fixed verification stage, and only proven safe IDs. This outcome is unsafe to
retry: refresh by those IDs before considering another mutation.
For direct and single-item review mutations, an upstream 5xx after the mutation
request is treated as potentially applied and returns this 409
applied-unverified contract. `draft_note.publish_all` and `review.submit`
re-read the owner-draft snapshot and reviewer state; they return the 409
contract if any effect may have applied, but may surface an ordinary sanitized
upstream failure when readback proves the operation left both unchanged. A
mutation request proven never sent returns `mutationStatus = "not_applied"`
with `retrySafe = true` instead (see
[Unsent and unanswered writes](#unsent-and-unanswered-writes)). The
`review.submit` summary note follows a publication that already applied, so
any failure to create it, sent or not, stays applied-unverified.

GitLab returns no created-note body from its single-draft publish endpoint, so
`merge_request.draft_note.publish` proves the resulting locator with bounded
readback. Before publishing, the Broker snapshots the exact parent discussion
for a reply draft or at most 10 pages of 100 merge-request discussions for a
general/positioned draft. After GitLab accepts publication, it reads the same
scope and requires exactly one new, non-system note by the acting upstream user
whose normalized body and semantic position match the draft. It then re-reads
the exact resulting discussion and proves the original draft is absent. It
never chooses by timestamp, numeric ID, or traversal order.

Verified success includes required, non-null locators:

```json
{
  "mutationStatus": "applied",
  "retrySafe": false,
  "draftNoteId": 11964,
  "published": true,
  "discussionId": "abc123def456",
  "noteId": 48291
}
```

If publication may have applied but the Broker cannot prove exactly one
resulting note, the normal HTTP 409 `mutation_verification_failed` result uses
`verificationStage = "published_note_readback"`,
`mutationStatus = "applied_unverified"`, and `retrySafe = false`. Its
`safeLocators` contain only the original `draftNoteIds` until the published
note is proven. If the note locators are proven but the final draft-absence
check fails, the stage remains `draft_absence_readback` and safe locators also
include the proven `discussionId` and `noteId`. Neither outcome is safe to
retry automatically.

## Normalized rich-content writes

GitLab body-bearing actions use canonical `content` plus explicit
`contentFormat`:

| Actions | Destination | Formats |
| --- | --- | --- |
| `issue.create`, `issue.update` | issue description | `markdown`, `plain_text` |
| `issue.note.add`, `issue.note.update` | issue note | `markdown`, `plain_text` |
| `merge_request.create`, `merge_request.update` | merge-request description | `markdown`, `plain_text` |
| `merge_request.note.add`, `merge_request.note.update` | merge-request note | `markdown`, `plain_text` |
| `merge_request.discussion.add`, `merge_request.discussion.note.update` | discussion note | `markdown`, `plain_text` |
| `merge_request.discussion.inline.add`, `merge_request.discussion.note.add` | positioned discussion or reply | `markdown`, `plain_text` |
| `merge_request.draft_note.add`, `merge_request.draft_note.update` | draft note | `markdown`, `plain_text` |
| optional summaries on `merge_request.draft_note.publish_all`, `merge_request.review.submit` | general MR note | `markdown`, `plain_text` |

Descriptions are optional on create/update and may omit the pair. An explicitly
empty description on update clears it when attribution is disabled for that
action; enabled attribution produces a footer-only description. Note and
discussion content is required and non-whitespace. Rich-content write schemas
use `content` and `contentFormat` and reject undeclared fields. Repository
`file.create`, `file.update`, and commit actions are not rich-content actions and retain their
separate file-content contracts.

GitLab Markdown is already provider-native, so `markdown` is preserved
byte-for-byte through conversion. `plain_text` is deterministically encoded as
literal GitLab Markdown: Markdown punctuation, raw HTML, mentions, issue and
merge-request references, autolinks, and GitLab extensions do not acquire
active semantics. Line boundaries and readable text are preserved. The Broker
never guesses a format from content, filenames, configuration, environment, or
defaults.

GitLab rich-content writes reject quick-action command lines outside fenced
code and suggestion blocks before submission so prose cannot trigger hidden
mutations or be stripped by GitLab. After leading whitespace, an unfenced
logical line is command-like only when it begins `/` plus an ASCII letter, its
command token contains only ASCII letters, digits, underscores, or hyphens, and
that token ends at whitespace or end of line. Thus `/approve`,
`  /assign @me`, and `/request_changes` are rejected in ordinary prose, while
fenced code/suggestions, inline prose, URLs, `/usr/bin`, `/docs/readme.md`, and
ordinary slash-containing Markdown remain allowed.

Typed commands accept exactly one of `--content STRING` or `--content-file
PATH` plus required `--content-format markdown|plain_text`. Inline content can
appear in shell history or process listings; prefer files for long or sensitive
values. `--content-file` reads are incrementally bounded by the CLI's 512 MiB
safety cap; the lower Broker/provider body cap remains authoritative. The
repository-file CLI's separate content-file option is outside this contract.

Every covered write validates the closed shape, source type, pairing,
emptiness, and source byte cap; converts when needed; appends configured
attribution in native Markdown only on the twelve actions that support
it; validates the complete native value; enforces the final native-body cap;
and only then calls GitLab. Attribution remains excluded from
`issue.note.update`, `merge_request.note.update`,
`merge_request.discussion.note.update`, and `merge_request.draft_note.update`.
The review workflow adds exactly five attribution-capable writes: direct inline
add, reply add, draft add, publish-all summary, and review-submit summary.
Oversized source or final content
returns `body_size_denied` (HTTP 413), while an unsupported format returns
`body_format_unsupported` (HTTP 415). Content is never truncated and source,
converted, attributed, or readback bodies do not appear in audit, tracing,
errors, metrics labels, or object identifiers.

GitLab has no native-format allowlist, so each available covered action
advertises both values directly in its caller-filtered catalog
`contentFormat.enum`. Clients, including Dispatch, detect capability from that
exact enum rather than a Broker version. OpenAPI and the action-specific send
schema project the same pair and enum.

For note and discussion mutations, the broker resolves the project path,
preflights the scoped issue or merge request with lookup credentials, authorizes
the resolved repository scope, and then executes with the selected service or
per-user credential. Deletes and discussion-note mutations first read the
target note or discussion through the exact scoped GitLab route using the
execution credential, so lookup credentials do not become note-body oracles.
Those preflight bodies are not returned or audited. Delete endpoints require
GitLab's empty `204 No Content` response and return broker-shaped
acknowledgements.

Returned note/discussion metadata is validated against the scoped route when
GitLab provides it. Issue/MR note mutations reject contradictory `projectId`,
`noteableType`, `noteableIid`, or `noteableId` values. Single MR discussion
proof tolerates missing or null `noteableIid`, which GitLab can return for live
discussion payloads, but still rejects contradictory project or merge-request
metadata and requires the requested note ID for note-level mutations.
Returned notes, including notes nested in discussions, expose GitLab's immutable
numeric `authorUserId` alongside `authorUsername` when GitLab supplies the
author identity.

## Normalized read content and whole-result Markdown

GitLab read presentation uses the common top-level invoke controls, never
GitLab `inputs`. `readContentFormat` accepts `native`, `markdown`, or `text`;
omission is `native`. A non-native request preserves the native `description`
or `body` and adds `renderedBody = { format, value }` beside its owning issue,
merge request, note, or nested discussion note. Missing and null bodies remain
absent; a present empty string produces a present empty companion.

GitLab action results declare rich content for these families:

| Result family | Actions and content owner |
| --- | --- |
| Issue description | `issue.view`, `issue.search`, `issue.create`, `issue.update`; singleton or each issue `description` |
| Issue notes | `issue.note.list`, `issue.note.view`, `issue.note.add`, `issue.note.update`; each returned note `body` |
| Merge-request description | `merge_request.view`, `merge_request.search`, `merge_request.create`, `merge_request.update`; singleton or each merge request `description` |
| Merge-request notes | `merge_request.note.list`, `merge_request.note.view`, `merge_request.note.add`, `merge_request.note.update`; each returned note `body` |
| Discussions | `merge_request.discussion.list`, `merge_request.discussion.view`, `merge_request.discussion.add`, `merge_request.discussion.inline.add`, `merge_request.discussion.resolve`, `merge_request.discussion.reopen`; every returned nested `notes[].body` |
| Discussion note | `merge_request.discussion.note.add`, `merge_request.discussion.note.update`; returned note `body` |
| Draft notes | `merge_request.draft_note.list`, `merge_request.draft_note.view`, `merge_request.draft_note.add`, `merge_request.draft_note.update`; each returned draft note `body` |

`merge_request.merge` returns no declared description. Delete acknowledgements,
repository-file content, commit messages, and job traces are not guessed as
rich content. Embedded Markdown is the exact GitLab-native string, byte for
byte. Embedded `text` uses a bounded CommonMark/GitLab-aware traversal that
keeps readable structure while suppressing active raw HTML. It never follows
links, resolves references, or fetches related resources.

`responseFormat` accepts `json` or `markdown`; omission is `json`.
Non-streaming retrieval actions advertise whole-result Markdown for these
families:

- `project.view`;
- `issue.view`, `issue.search`, and `issue.note.list/view`;
- `merge_request.view`, `merge_request.search`,
  `merge_request.note.list/view`, `merge_request.discussion.list/view`, reviewer,
  MR commit, MR pipeline, current structured diff, diff-version reads, and
  `merge_request.draft_note.list/view`, plus approval summary, approval state,
  and approval-rule list/view reads;
- `branch.list`, `branch.view`, `protected_branch.list`,
  `protected_branch.view`, and `protected_branch.verify`;
- `file.view`, `commit.list`, and `commit.view`; and
- `pipeline.list`, `pipeline.view`, `job.list`, and `job.view`.

Each renderer is a typed semantic template, not a recursive JSON-to-bullet
dump. It includes every meaningful present result field in stable order and
preserves exact identifiers, SHAs, timestamps, booleans, URLs, collection
order, counts, and opaque continuation tokens. Issue and merge-request searches
and note/discussion lists render only descriptions or bodies already contained
in their normal result. `file.view` preserves `contentBase64` in a
collision-safe fenced block without decoding it, and commit messages are
literal preformatted text rather than outer-document Markdown. GitLab bodies
are parsed and safely re-emitted for whole-result composition so an unclosed
fence, list, raw HTML block, or extension cannot consume later broker metadata.

Formatting never changes the GitLab endpoint, query parameters, selected
fields, page membership, or continuation-token contract and performs zero
additional provider requests. Mutations do not advertise whole-result
Markdown. `file.raw.download`, `job.trace.download`, and
`merge_request.diff.raw.download` advertise neither read feature and retain the
raw stream contract.

Typed and generic CLI commands use `--read-content-format` and
`--output-format`; successful whole-result Markdown prints only the Markdown
value. Direct HTTP and `send` keep the standard JSON envelope. Client defaults
are `[defaults].read_content_format` and `[defaults].output_format`, with
environment overrides `AGENT_ACCESS_READ_CONTENT_FORMAT` and
`AGENT_ACCESS_OUTPUT_FORMAT`; resolution is command flag, then client config,
then environment, then `native`/`json`. A valid ambient non-default is omitted
for an action that does not advertise it. `send` never injects ambient values.
An explicit non-native embedded format cannot be combined with whole-result
Markdown. Always inspect `readContentFormats` and `responseFormats` in the
caller-filtered catalog instead of inferring capability from a Broker version
or GitLab write support.

Every declared returned body is structurally checked and bounded by
`providers.gitlab.content.max_body_bytes`, including omitted or explicit
`native`. Parsing depth, event count, work, per-body rendered output, and
aggregate rendered-work caps are fixed defensive constants. Aggregate rendered
bytes, whole-document bytes, and the final serialized result are bounded by the
configurable `limits.max_upstream_response_bytes`. All limits apply without
truncation.
Malformed or oversized upstream content, complexity exhaustion, or rendered
output overflow fails atomically as sanitized
`upstream_protocol_failed`/502—there is no native or partial fallback. Native
bodies, rendered bodies, whole-result Markdown, file base64, arbitrary literal
values, and pagination tokens are excluded from audit records, tracing, logs,
errors, metric labels, and object identifiers.

## Merge, repository, and CI action contracts

Merge-request merge accepts `project`, `iid`, mandatory full 40-character
`sha`, and optional `squash`, `shouldRemoveSourceBranch`,
`mergeCommitMessage`, and `squashCommitMessage`. The broker preflights the
current merge request, rejects stale `sha` values with `version_conflict`, and
then calls GitLab's server-side merge endpoint. GitLab remains authoritative for
target-branch protection, approvals, CI status, merge trains, and upstream
credential permissions. Deployments that do not want agents to merge must not
grant `merge_request.merge`.

Branch listing accepts `project`, optional `search` or `regex`, and optional
`maxResults`. Branch view accepts `project` and `branch`; branch names may not
start with `refs/`, contain dot segments, controls, backslashes, or leading and
trailing slashes.

Branch create accepts `project`, `branch`, and `ref`; `ref` may be an existing
branch or another GitLab-resolvable commit or tag ref. Direct writes reject the
configured default branch, literal `main`, literal `master`, existing protected
branches, and matching protected-branch patterns before calling GitLab.

Protected branch listing accepts `project`, optional `search`, and optional
`maxResults`. Protected branch view accepts `project` and
`branchOrWildcardName`, which may be a literal branch name or GitLab protected
branch wildcard rule such as `release/*`. Protected branch verify checks whether
the current default branch, `main`, `master`, and any caller-supplied
`requiredPatterns` are covered by GitLab protected branch rules. Verification is
diagnostic only; GitLab-side protected branch enforcement remains the security
boundary for upstream merges and direct GitLab access.

Repository file view accepts `project`, `path`, and `ref`. Inline file content
is returned as `contentBase64` only when it fits
`providers.gitlab.content.max_file_bytes` and the configured upstream JSON
response cap; larger files should be retrieved with `file.raw.download`.
`file.raw.download` returns a broker-managed raw stream and does not place file
bytes in the JSON response or audit log. Raw downloads resolve file metadata
first and stream from the metadata commit SHA, returned as `resolvedRef`, so a
movable branch or tag cannot change between metadata lookup and byte streaming.

File create/update/delete act on one relative repository path on a non-default,
unprotected branch. Create requires absent target file; update and delete require
`lastCommitId` when GitLab file metadata exposes `last_commit_id`, preventing
silent overwrites. File create/update content is bounded after base64 decoding
when `encoding = "base64"` is used, otherwise by UTF-8 byte length. File
create/update may also set GitLab's `executeFilemode` flag.

Commit listing accepts `project`, optional `refName`, `path`, `since`, `until`,
`firstParent`, and `maxResults`. Commit view accepts `project` and a 7-to-64
character hex `sha`.

Commit create accepts a finite action list of `create`, `update`, `move`,
`delete`, and `chmod` operations. The broker rejects empty action lists,
duplicate target paths, invalid paths, over-limit content, default/protected
target branches, and missing or mismatched `lastCommitId` for existing-file
update/delete/move operations. `startSha`, when supplied, must be a full
40-character commit SHA. The broker sends bounded REST commit actions to GitLab;
it does not accept Git pack data, force branch rewrites, or operate on a local
checkout.

Pipeline listing accepts `project`, optional `ref`, `sha`, `status`, `source`,
`updatedAfter`, `updatedBefore`, and `maxResults`. Pipeline view/retry/cancel
accept `project` and `pipelineId`. Pipeline run accepts only `project` and
`ref`; caller-supplied variables are not exposed. The run ref must resolve to an
existing branch and the broker rejects the configured default branch, literal `main`, literal `master`, branch metadata marked protected, and
matching protected-branch patterns before calling GitLab.

Job listing accepts `project`, optional `pipelineId`, `scope`, and
`maxResults`. Job view/retry/cancel accept `project` and `jobId`.
`job.trace.download` returns a broker-managed raw stream and does not place trace
bytes in the JSON response or audit log. The trace response must have a known
size from GitLab job metadata or the upstream `Content-Length`; traces without a
known size fail closed. Job play accepts only `project` and `jobId`;
caller-supplied variables are not exposed. The broker looks up the job, pipeline,
and ref before play and applies the same default/protected branch denial used by
`pipeline.run`.

## Results and audit

Successful provider results wrap GitLab objects under a service-specific key,
including `project`, `issue`, `issues`, `note`, `notes`, `mergeRequest`,
`mergeRequests`, `discussion`, `discussions`, `branches`, `branch`,
`protectedBranches`, `protectedBranch`, `protectedBranchVerification`, `file`,
`draftNote`, `draftNotes`, `commits`, `commit`, `pipelines`, `pipeline`, `jobs`,
or `job`, plus resolved
`resourceScopes.repository`. List/search results include the confirmed project
path on each issue or merge request. Paginated searches and collection reads
include `count`, effective `maxResults`, `isLast`, and the opaque
`nextPageToken` or `null` as declared by the action.

Audit records include provider operation, upstream status, object identifiers,
credential mode, egress proxy state, and redacted request-body metadata for
write operations, such as JSON field names, text byte counts, and list counts.
They do not include issue descriptions, note or draft bodies, review summaries,
discussion bodies, merge-request descriptions, titles, merge messages, patches,
native line codes, continuation tokens, commit messages, or other returned
content. Merge audit records include safe source branch, target branch,
expected SHA, merge option flags, and upstream merge status.
Review audit may include bounded position type and numeric-line metadata,
expected/proven head SHA, reviewer state, resolution flag, and safe object IDs.

### Unsent and unanswered writes

A GitLab write action sends its mutation request after its reads. When the
Broker proves that request never reached GitLab, because no connection was
established (including a connect timeout) or the request could not be built,
the action fails with its ordinary `upstream_connection_failed` (HTTP 502), or
`upstream_timeout` (HTTP 504) for a connect timeout, and a result of:

```json
{ "mutationStatus": "not_applied", "retrySafe": true }
```

Nothing was applied, and the action can be repeated. This covers every write,
with or without a verification contract, including provisioning and project
uploads. A read that was never sent carries no mutation receipt.

Only that proof yields `not_applied`. Writes with a verification contract
(inline discussions, discussion replies, draft notes, draft publication, review
submission, approvals, suggestion application, webhook and provisioning
mutations) treat the other failures of their mutation request by what GitLab
may have done:

- when the request may have been applied without confirmation, because it timed
  out or its connection failed after sending, GitLab answered 5xx, or a success
  response stalled, failed, exceeded the byte cap or did not have the expected
  shape, the action returns `mutation_verification_failed`/409 with
  `mutationStatus = "applied_unverified"` and `retrySafe = false`, or the
  ordinary error when readback proves the target unchanged;
- when GitLab definitively rejected the request, with a redirect, a 4xx status
  such as 401, 403, 404, 409 or 422 (provisioning reports 400 and 422 as
  `input_invalid`), or throttling (`upstream_rate_limited`), the action keeps
  its ordinary error without a receipt. So does a failure of the person's
  OAuth connection that stops the request, which applies nothing, and a
  request the Broker could not prepare, such as one the upstream allowlist
  refuses, which is never sent: it keeps the reason of its cause, such as
  `upstream_protocol_failed`, and the action does not probe its target.

Once GitLab has accepted the mutation request, every failure of a later
readback or verification request also returns the `applied_unverified`
contract, whatever its cause and with a static token or an OAuth connection
alike. That includes a readback GitLab rejects with any status, such as 401,
403 or 404, or throttles, one answered 5xx, never sent, timed out or failed,
one whose response is unusable or exceeds the configured content bounds, and
one the person's OAuth connection could not authorize (refresh throttled, busy
or uncertain, or a reconnect required). Its `safeLocators` name what the
accepted write established, such as the webhook ID `webhook.create` received.

Other writes (issue, note, merge-request and merge, general discussion,
discussion-note edit/delete, resolve/reopen, branch, file, commit, pipeline and
job mutations, and project uploads) keep their ordinary sanitized error and
reason, and add a receipt for what GitLab may have done:

| What happened | Receipt |
| --- | --- |
| The request may have been sent, but no response arrived: a timeout (including a stalled upload) or a connection failure after sending (`upstream_timeout`, HTTP 504, or `upstream_connection_failed`, HTTP 502) | `{ "mutationStatus": "unknown", "retrySafe": false }` |
| GitLab, or a proxy in front of it, answered with a redirect, which the Broker never follows on a write, or a 5xx (`upstream_failed`); the write may have committed first | `{ "mutationStatus": "unknown", "retrySafe": false }` |
| GitLab answered with a success status, but its response then failed, stalled, exceeded the byte cap, did not parse, carried a body on a no-content response, or did not match the request, such as an issue in another project | `mutationStatus = "applied_unverified"`, `retrySafe = false`, `verificationStage = "mutation_response"` and `safeLocators` |

The `safeLocators` name the target from the validated request, never from the
response: always `project`, and `issueIid`, `mergeRequestIid`, `noteId`,
`discussionId`, `branch`, `path`, `ref`, `pipelineId`, `jobId`, or
`sourceBranch` and `targetBranch`, as the action has them. Inspect the target
before repeating a write with either receipt. A rejection with another HTTP
status, such as 400, 403, 404, 409, 422 or 429, and a failure before
the request is sent, such as an upload file the Broker cannot open, carry no
receipt.

A later request that fails after a write applied, such as a readback or the
`review.submit` summary note, never reports `not_applied`.

## Bot accounts and issued tokens

Project access-token and project service-account provisioning is separately
grantable and disabled by default. The complete action, policy, token delivery,
version, and lifecycle contract is in [GitLab bot provisioning](gitlab-bot-provisioning.md).

`project.access_token.create`, `project.access_token.rotate`,
`service_account.token.create` and `service_account.token.rotate` are
[token-only](provider-sdk.md#token-only-actions). GitLab documents project
access-token creation and rotation as requiring a personal access token, and
the Broker treats service-account tokens the same way. They run with the service
credential or a principal's stored GitLab token, never with delegated (OAuth)
access: where a principal's winning grant is `per_user` and their connection
selects OAuth, the Broker hides and denies them rather than using a lower grant.
