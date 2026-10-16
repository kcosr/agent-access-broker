# Manual Live Smoke Runbook

This runbook describes a sanitized manual smoke workflow for validating Agent
Access Broker against live Jira, Confluence, and GitLab backends. It complements
the ignored Cargo live-smoke tests in `docs/testing.md` by covering the operator
steps around daemon startup, managed grants, token setup, attribution config,
and targeted CLI commands.

Keep environment-specific paths, tenant URLs, resource IDs, raw token values,
credential files, managed-store databases, and copied upstream responses out of
tracked docs. Store concrete run artifacts outside the repository or under an
ignored local scratch directory.

## Safety Rules

- Use an explicitly authorized test tenant/project and throwaway Jira issues,
  Confluence pages/blogs, and GitLab issues/MRs/source branches. Webhook test and
  resend commands require a dedicated receiver prepared for duplicate delivery.
- Use token files or environment variables; do not put raw broker or upstream
  tokens in shell history.
- Keep local configs, managed-store databases, raw CLI outputs, HTML bodies,
  and copied upstream responses outside tracked files.
- Do not copy customer hostnames, page IDs, issue keys, repository names, or
  emails into tracked docs.
- Prefer `target/debug/agent-access` while validating local changes; install or
  use `target/release/agent-access` only after confirming the binary under test.

## Artifact Layout

A local smoke directory commonly contains:

- `admin-cli-config.toml` - local admin CLI config for the scratch broker. It
  should point at a local or test broker and an external token file.
- `*.out.json` - captured CLI JSON responses.
- `*.storage.html`, `*.md`, `*.txt`, and `*.adf.json` - Confluence native and
  normalized rich-content sources for page/blog/comment/draft smoke.
- `*.md`, `*.txt`, and `*.adf.json` - Jira normalized and native rich-content
  sources. Never put broker or upstream tokens in any content fixture.
- `*.md` - GitLab Markdown request bodies used for issue and note smoke.

Treat all of these as local artifacts unless they have been fully sanitized.

## Environment Skeleton

Use placeholders or local exports instead of hardcoded values:

```bash
export AAB_BIN=target/debug/agent-access
export BROKER_BIN=target/debug/agent-access-broker
export BROKER_URL=http://127.0.0.1:8787
export ADMIN_CONFIG=/secure/path/admin-cli-config.toml
export AGENT_CONFIG=/secure/path/agent-cli-config.toml
export SMOKE_DIR=/secure/path/live-smoke

export JIRA_PROJECT=PROJ
export JIRA_ISSUE=PROJ-123
export JIRA_BLOCKING_ISSUE=PROJ-124
export JIRA_BLOCKED_ISSUE=PROJ-125
export JIRA_PARENT_STANDARD_ISSUE=PROJ-126
export JIRA_PARENT_EPIC_ISSUE=PROJ-100
export JIRA_PARENT_SUBTASK_ISSUE=PROJ-127
export JIRA_PARENT_SUBTASK_PARENT_ISSUE=PROJ-128
# Set JIRA_CREATE_ISSUE_TYPE_ID from project issue-type discovery below.
export CONFLUENCE_SPACE=SPACE
export CONFLUENCE_PAGE_ID=123456
export CONFLUENCE_PAGE_VERSION=1
export CONFLUENCE_BLOG_ID=234567
export CONFLUENCE_BLOG_VERSION=1
export GITLAB_REPOSITORY=namespace/project

umask 077
mkdir -p "$SMOKE_DIR"
```

For an execution-context deployment, set `BROKER_URL` and the Git remote to
trusted-ingress endpoints configured as named asserted callers. They must replace
client copies of `X-Agent-Access-Context` with the smoke context and inject their
private `X-Agent-Access-Caller-Authorization` credential. Do not add either header to
the CLI config, curl config, or command line. Public and gateway listeners need
separate ingress coverage.

The admin CLI config should look like this shape, with the token file outside
the repository:

```toml
[service]
url = "http://127.0.0.1:8787"

[identity]
token_file = "/secure/operator/path/admin-token"
header = "Authorization"
scheme = "Bearer"
disabled = false
```

Use the same identity header and scheme in the agent CLI config, with an agent
token file instead of the admin token:

```toml
[service]
url = "http://127.0.0.1:8787"

[identity]
token_file = "/secure/agent/path/agent-token"
header = "Authorization"
scheme = "Bearer"
disabled = false
```

## Build And Broker Startup

Build the binaries first. Prefer the repository-configured build service; use a
local build if the service is unavailable:

```bash
BUILD_SERVICE_ENABLED=true \
BUILD_SERVICE_ENDPOINT=http://build-host.example:6680 \
build-cli build cargo -- build
```

For local-only validation:

```bash
cargo build
```

Start or restart the broker with the local managed-store config for the smoke
environment. Keep the concrete config path out of tracked docs:

```bash
"$BROKER_BIN" --config /secure/or/scratch/path/broker.toml serve
```

After startup:

```bash
"$AAB_BIN" --config "$ADMIN_CONFIG" admin policy status
"$AAB_BIN" --config "$ADMIN_CONFIG" admin policy catalog
```

Create or validate smoke grants with one or more repeatable
`--execution-context` flags, and confirm managed and TOML grant projections show
the same finite `executionContexts` shape. Use contexts that let the smoke prove
one shared action and at least one context-exclusive action.

## Runtime Spec And Generic Surface

Before provider mutations, prove the runtime description surfaces match the
broker that is actually running:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  spec catalog --output-format json \
  > "$SMOKE_DIR/spec-catalog.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  spec openapi --output-format json \
  > "$SMOKE_DIR/spec-openapi.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  spec send-schema --output-format json \
  > "$SMOKE_DIR/spec-send-schema.out.json"
```

The canonical broker actions are the names shown by runtime spec, policy, audit,
HTTP invoke, generic CLI `invoke`, and JSON `send`. The typed CLI provider
commands are ergonomic wrappers over those actions. For example,
`agent-access invoke jira.comment.add ...` and JSON `send` action
`comment.add` use the canonical Jira action, while
`agent-access jira issue comment add ...` is the typed CLI wrapper.
Confirm each caller catalog contains the expected `executionContext`, repeat
discovery through another context entrypoint, and verify context-exclusive
actions disappear. An admin `--visibility all` catalog must omit the field.
For Jira, Confluence, and GitLab, also confirm action entries advertise
`readContentFormats` only for declared rich-content result owners and
`responseFormats` only for eligible retrievals. The corresponding
`readContentFormat` and `responseFormat` fields are top-level request properties
beside `inputs` in OpenAPI and action-specific send variants; they must not
appear inside provider `inputs`. For GitLab, spot-check an embedded-capable
mutation readback as well as a body-bearing retrieval, and confirm raw file and
job-trace downloads advertise neither capability.

For direct HTTP API probes, always include the request-id header required by the
HTTP contract:

```bash
umask 077
printf 'header = "Authorization: Bearer %s"\n' \
  "$(cat /secure/agent/path/agent-token)" \
  > "$SMOKE_DIR/curl-auth.cfg"

curl -fsS \
  --config "$SMOKE_DIR/curl-auth.cfg" \
  -H "X-Agent-Access-Request-Id: live-smoke-jira-view" \
  -H "Content-Type: application/json" \
  -d '{"inputs":{"issue":"PROJ-123"}}' \
  "$BROKER_URL/v1/invoke/jira/issue.view" \
  > "$SMOKE_DIR/http-jira-issue-view.out.json"
```

Repeat the direct Jira issue-view probe in embedded Markdown mode:

```bash
curl -fsS \
  --config "$SMOKE_DIR/curl-auth.cfg" \
  -H "X-Agent-Access-Request-Id: live-smoke-jira-view-rendered" \
  -H "Content-Type: application/json" \
  -d '{"inputs":{"issue":"PROJ-123"},"readContentFormat":"markdown"}' \
  "$BROKER_URL/v1/invoke/jira/issue.view" \
  > "$SMOKE_DIR/http-jira-issue-view-rendered.out.json"
```

Confirm the original native ADF description is unchanged and a sibling
`renderedBody` reports `format = "markdown"` with readable content. Then probe
one eligible body-free Jira search or list with top-level
`"responseFormat":"markdown"`; the HTTP response remains a JSON envelope whose
`result` is `{ "format": "markdown", "value": "..." }`. Do not combine
whole-result Markdown with a non-native `readContentFormat`.

Also verify `GET /v1/tokens/options`, then exercise self and admin issuance with
one and with multiple repeated `--execution-context` flags. Exercise a
token/context mismatch and record
`execution_context_denied`; in an isolated strict test path, verify missing and
malformed ingress produce `execution_context_required` and
`execution_context_invalid`. Confirm provider and Git upstream captures never
contain `X-Agent-Access-Context`.

Issue one purpose-specific token with `--service`, `--action`, and a finite
`--resource-id SERVICE=ID` or `--resource-group-id SERVICE=ID` from the
current catalog options.
Confirm an included action/resource succeeds, an excluded action and excluded
resource return `service_action_denied`, and caller catalog/OpenAPI/send
discovery omits the excluded action. Remove the supporting grant and confirm
the stored boundary remains inspectable while invocation denies; restore it and
confirm access returns without reissuing or editing the token. Pause and resume
the token once and verify the identical boundary is retained. Also verify a token that follows current grants without resource restrictions. Audit output may contain the
canonical boundary and token ID but must not contain the revealed token secret.

Exercise the generic CLI invoke surface separately from typed wrappers:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  invoke gitlab.issue.view \
  --input-json '{"project":"namespace/project","iid":1}' \
  > "$SMOKE_DIR/invoke-gitlab-issue-view.out.json"
```

Exercise both Jira presentation modes through generic `invoke` as well:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  invoke jira.issue.view \
  --input-json "{\"issue\":\"$JIRA_ISSUE\"}" \
  --read-content-format markdown \
  > "$SMOKE_DIR/invoke-jira-issue-view-rendered.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  invoke jira.search \
  --input-json "{\"jql\":\"project = $JIRA_PROJECT\"}" \
  --output-format markdown \
  > "$SMOKE_DIR/invoke-jira-search.out.md"
```

The first output remains JSON with native ADF plus `renderedBody`. The second
contains only the Markdown value—no envelope and no raw ADF. An omitted option
must continue to produce native JSON. Unsupported explicit flags fail locally;
ambient defaults for a capability the selected action does not advertise are
omitted rather than sent.

Exercise the JSON `send` surface with at least one JSON-body mutation and one
file-bearing operation. `send` request files are ordinary local smoke artifacts;
do not include broker or upstream tokens in them.

Example JSON-body mutation request:

```json
{
  "version": "agent-access.send.v1",
  "kind": "invoke",
  "service": "jira",
  "action": "comment.add",
  "inputs": {
    "issue": "PROJ-123",
    "contentFormat": "markdown",
    "content": "## Live smoke\n\nAgent Access live smoke comment."
  }
}
```

`send` never injects response defaults from CLI config or the environment. To
exercise whole-result Markdown, put the explicit top-level camel-case field in
the request file, for example an invoke-kind Jira `issue.view` request with
`"responseFormat":"markdown"`. The CLI output remains the JSON response
envelope; compare its `result.value` with the generic/typed Markdown output.

Run it with:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  send --request-file "$SMOKE_DIR/send-jira-comment-add.json" \
  > "$SMOKE_DIR/send-jira-comment-add.out.json"
```

## Grant And Token Prep

Inspect existing grants before modifying anything:

```bash
"$AAB_BIN" --config "$ADMIN_CONFIG" admin policy grants list \
  > "$SMOKE_DIR/admin-grants-before.out.json"
```

Create or update service grants with only the actions needed for the smoke. Use
stable grant IDs and `--expected-version` on update:

```bash
"$AAB_BIN" --config "$ADMIN_CONFIG" admin policy grants update <grant-id> \
  --expected-version <n> \
  --subject user:<principal> \
  --service jira \
  --credential-mode per_user \
  --action issue_type.list \
  --action issue.view \
  --action issue.create \
  --action issue.child.create \
  --action issue.update \
  --action issue.parent.set \
  --action issue.dependency.add \
  --action comment.add \
  --action comment.reply \
  --action comment.update \
  --resource-id <registered-jira-resource-id>
```

Use exact policy subjects such as `user:<principal>` or `group:<group-id>`.
Repeat `--subject` to grant the same rule to multiple subjects. On update, any
provided subjects replace the grant's full subject list.

For Confluence draft and attribution smoke, include the concrete page/blog,
draft, attachment, publish, and comment actions being exercised. For GitLab,
grant only the target repository selector and the specific REST actions under
test.

Issue short-lived broker tokens when needed:

```bash
"$AAB_BIN" --config "$ADMIN_CONFIG" admin tokens issue <principal> \
  --token-class user_manage \
  --name smoke-setup \
  --ttl 2h

"$AAB_BIN" --config "$ADMIN_CONFIG" admin tokens issue <principal> \
  --token-class agent_invoke \
  --name smoke-agent \
  --service jira \
  --service confluence \
  --service gitlab \
  --ttl 2h
```

Store returned raw tokens in local secret files. Do not paste them into this
file or into tracked docs.

## Upstream Credential Prep

Use `user_manage` or admin credential routes to store each principal's token for
its credential connections. Prefer generic field sources for upstream token
material:

```bash
export ATLASSIAN_API_TOKEN_FILE=/secure/path/atlassian-api-token
export GITLAB_TOKEN_FILE=/secure/path/gitlab-token

# One classic Atlassian API token serves Jira and Confluence when both name
# the atlassian connection. Verify it through each product.
"$AAB_BIN" --config "$ADMIN_CONFIG" admin credentials put <principal> atlassian \
  --username <email-or-user> \
  --field-file token="$ATLASSIAN_API_TOKEN_FILE" \
  --verify --verify-service jira

"$AAB_BIN" --config "$ADMIN_CONFIG" admin credentials verify <principal> atlassian \
  --service confluence

"$AAB_BIN" --config "$ADMIN_CONFIG" admin credentials put <principal> gitlab \
  --field-file token="$GITLAB_TOKEN_FILE" \
  --verify

# When the GitLab Git gateway shares the gitlab connection, verify the same
# token through it against the smoke repository.
"$AAB_BIN" --config "$ADMIN_CONFIG" admin credentials verify <principal> gitlab \
  --service gitlab_git --repository "$GITLAB_REPOSITORY"
```

Verification probes as the principal through a service it is granted
`per_user`, so grant the principal before verifying.

## Attribution Setup

Content attribution is daemon-side config. For broad smoke coverage, enable all
provider actions in the broker config:

```toml
[attribution.actions]
jira = ["*"]
confluence = ["*"]
gitlab = ["*"]
```

Restart the broker after changing attribution config, then confirm provider
mutations add or update the visible footer. Request bodies should not carry the
footer; the broker should add it.

## Jira Smoke Matrix

View the issue before mutation:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue view "$JIRA_ISSUE" \
  > "$SMOKE_DIR/attribution-jira-issue-before.out.json"
```

Exercise embedded and whole-result rendering before mutation:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue view "$JIRA_ISSUE" \
  --read-content-format markdown \
  > "$SMOKE_DIR/jira-issue-view-rendered.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue search --jql "project = $JIRA_PROJECT" \
  --output-format markdown \
  > "$SMOKE_DIR/jira-issue-search.out.md"
```

The embedded result must retain the exact native description and add its
Markdown companion. The search Markdown must represent the same body-free
metadata as the default JSON search—normalization must not add descriptions or
cause an additional Jira fetch. JSON is the default Jira presentation.

Inspect the corresponding audit record (with a SQLite audit store,
`agent-access admin audit requests inspect <brokerRequestId>`) and structured
service logs. They may record requested/effective format names, byte counts,
and conversion outcome, but must not contain native ADF, rendered text,
whole-result Markdown, property values, pagination tokens, parser excerpts, or
extracted links. If an isolated
smoke broker is deliberately configured with a low Jira `max_body_bytes`, an
oversized returned issue description or comment body must fail with the fixed
sanitized `upstream_protocol_failed`/502 response and no partial output. Do
not lower a shared live broker's limit solely for this check.

Update a description from Markdown:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue update "$JIRA_ISSUE" \
  --content-file "$SMOKE_DIR/attribution-jira-description.md" \
  --content-format markdown \
  --suppress-notifications \
  > "$SMOKE_DIR/attribution-jira-issue-update.out.json"
```

Before creating issues, grant `issue_type.list` and discover the throwaway
project's types with the same credential used for creation:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue-type list --project "$JIRA_PROJECT" --max-results 100 \
  > "$SMOKE_DIR/jira-issue-types.out.json"
```

If `result.isLast` is false, repeat with `--start-at` set to
`result.nextStartAt`. Select a returned non-subtask type that does not require
extra custom fields and set `JIRA_CREATE_ISSUE_TYPE_ID` to its `id`. Do not infer
IDs from type names or copy IDs from another project or tenant.

Create summary-only and native-ADF-described issues in the throwaway project:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue create \
  --project "$JIRA_PROJECT" \
  --issue-type-id "$JIRA_CREATE_ISSUE_TYPE_ID" \
  --summary "Agent Access Broker smoke create $(date -u +%Y%m%dT%H%M%SZ)" \
  > "$SMOKE_DIR/attribution-jira-issue-create-summary.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue create \
  --project "$JIRA_PROJECT" \
  --issue-type-id "$JIRA_CREATE_ISSUE_TYPE_ID" \
  --summary "Agent Access Broker smoke create ADF $(date -u +%Y%m%dT%H%M%SZ)" \
  --content-file "$SMOKE_DIR/attribution-jira-description.adf.json" \
  --content-format adf \
  > "$SMOKE_DIR/attribution-jira-issue-create-adf.out.json"
```

Use an issue type that does not require extra custom fields. If the create
succeeds upstream but the broker fails closed during response validation or
readback, reconcile the created issue from the failure audit's `issueId` and
`issueKey`; the audit intentionally omits submitted summary and description
content.

Create parented child issues in projects where Jira accepts those
relationships. Run whichever case your tenant supports, and run both when
possible:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue child create \
  --project "$JIRA_CHILD_STANDARD_PROJECT" \
  --issue-type-id "$JIRA_CHILD_STANDARD_ISSUE_TYPE_ID" \
  --summary "Agent Access Broker smoke child $(date -u +%Y%m%dT%H%M%SZ)" \
  --parent "$JIRA_CHILD_EPIC_ISSUE" \
  --content "Created by the normalized plain-text smoke." \
  --content-format plain_text \
  > "$SMOKE_DIR/attribution-jira-issue-child-create-epic.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue child create \
  --project "$JIRA_CHILD_SUBTASK_PROJECT" \
  --issue-type-id "$JIRA_CHILD_SUBTASK_ISSUE_TYPE_ID" \
  --summary "Agent Access Broker smoke subtask $(date -u +%Y%m%dT%H%M%SZ)" \
  --parent "$JIRA_CHILD_SUBTASK_PARENT_ISSUE" \
  > "$SMOKE_DIR/attribution-jira-issue-child-create-subtask.out.json"
```

The broker creates the child with Jira `fields.parent`, verifies the parent by
readback, and emits side-effect audit details if Jira accepts the create but
the parent cannot be confirmed.

Assign disposable child issues to disposable parents in projects where Jira
accepts those relationships. Run whichever case your tenant supports, and run
both when possible:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue parent set "$JIRA_PARENT_STANDARD_ISSUE" \
  --parent "$JIRA_PARENT_EPIC_ISSUE" \
  > "$SMOKE_DIR/attribution-jira-issue-parent-set-epic.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue parent set "$JIRA_PARENT_SUBTASK_ISSUE" \
  --parent "$JIRA_PARENT_SUBTASK_PARENT_ISSUE" \
  > "$SMOKE_DIR/attribution-jira-issue-parent-set-subtask.out.json"
```

Link two disposable issues with a dependency relation:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue dependency add \
  --blocking "$JIRA_BLOCKING_ISSUE" \
  --blocked "$JIRA_BLOCKED_ISSUE" \
  > "$SMOKE_DIR/attribution-jira-issue-dependency-add.out.json"
```

For an Epic/child/dependency smoke, treat issue creation, child creation, and
dependency linking as separate mutations. If a later command fails, reconcile
the already-created Jira objects from the command output or failure audit; the
broker does not perform multi-call rollback.

Add, update, reply, and update a reply:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue comment add --issue "$JIRA_ISSUE" \
  --content-file "$SMOKE_DIR/attribution-jira-comment-add.md" \
  --content-format markdown \
  > "$SMOKE_DIR/attribution-jira-comment-add.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue comment update <comment-id> --issue "$JIRA_ISSUE" \
  --content-file "$SMOKE_DIR/attribution-jira-comment-update-with-old-footer.adf.json" \
  --content-format adf \
  --notify-users false \
  > "$SMOKE_DIR/attribution-jira-comment-update.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue comment reply <comment-id> --issue "$JIRA_ISSUE" \
  --content "Normalized plain-text reply." \
  --content-format plain_text \
  > "$SMOKE_DIR/attribution-jira-comment-reply.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue comment update <reply-id> --issue "$JIRA_ISSUE" \
  --content-file "$SMOKE_DIR/attribution-jira-reply-update-with-old-footer.md" \
  --content-format markdown \
  --notify-users false \
  > "$SMOKE_DIR/attribution-jira-reply-update.out.json"
```

Verify with `jira issue view` and `jira issue comment view`. Confirm the visible
footer exists once, has the current operation label, and does not duplicate.
Jira attachments currently expose add, list, and raw download; there is no
broker attachment-delete action.

## Confluence Page And Blog Smoke Matrix

Before mutation, exercise one embedded native-body conversion and one body-free
whole-result rendering:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page view "$CONFLUENCE_PAGE_ID" \
  --read-content-format markdown \
  > "$SMOKE_DIR/confluence-page-view-rendered.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page search --space "$CONFLUENCE_SPACE" --text runbook \
  --output-format markdown \
  > "$SMOKE_DIR/confluence-page-search.out.md"
```

Confirm page view preserves every native `body` representation and adds
`renderedBody` beside `body`. If both ADF and storage are present, confirm ADF
is selected. The search Markdown must represent the same body-free result and
must not cause another Confluence request. JSON is the default Confluence
presentation.

Create a page and verify attribution:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page create \
  --space "$CONFLUENCE_SPACE" \
  --title "Agent Access Smoke Page" \
  --content-file "$SMOKE_DIR/attribution-page-create.storage.html" \
  --content-format storage \
  > "$SMOKE_DIR/attribution-page-create.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page view <page-id> \
  > "$SMOKE_DIR/attribution-page-create-view.out.json"
```

Create another throwaway page below the first, then append it below a different
same-space throwaway page. Confirm each response/readback reports the requested
parent and `childPosition`:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page create \
  --space "$CONFLUENCE_SPACE" \
  --title "Agent Access Smoke Child Page" \
  --parent <first-page-id> \
  --content-file "$SMOKE_DIR/attribution-page-create.storage.html" \
  --content-format storage \
  > "$SMOKE_DIR/confluence-child-page-create.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page move <child-page-id> \
  --position append \
  --target-url <second-parent-page-url> \
  > "$SMOKE_DIR/confluence-page-move.out.json"
```

Then create a sibling below the second parent and exercise `--position before`
and `--position after` against that sibling. Confirm `parentPageId`,
`childPosition`, and `targetChildPosition` reflect the requested adjacent order.
Use throwaway pages in one space. This action intentionally cannot clear the
parent, cross spaces, or target non-page content.

Update an existing page and verify footer dedupe:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page update "$CONFLUENCE_PAGE_ID" \
  --base-version "$CONFLUENCE_PAGE_VERSION" \
  --content-file "$SMOKE_DIR/attribution-page-update-with-old-footer.storage.html" \
  --content-format storage \
  > "$SMOKE_DIR/attribution-page-update.out.json"
```

Repeat the same shape for blogs:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence blog create \
  --space "$CONFLUENCE_SPACE" \
  --title "Agent Access Smoke Blog" \
  --content-file "$SMOKE_DIR/attribution-blog-create.storage.html" \
  --content-format storage \
  > "$SMOKE_DIR/attribution-blog-create.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence blog update "$CONFLUENCE_BLOG_ID" \
  --base-version "$CONFLUENCE_BLOG_VERSION" \
  --content-file "$SMOKE_DIR/attribution-blog-update-with-old-footer.storage.html" \
  --content-format storage \
  > "$SMOKE_DIR/attribution-blog-update.out.json"
```

## Confluence Draft Smoke Matrix

Create new page and blog drafts, then leave them unpublished for review:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page draft create \
  --space "$CONFLUENCE_SPACE" \
  --title "Agent Access Draft Page" \
  --parent "$CONFLUENCE_PAGE_ID" \
  --content-file "$SMOKE_DIR/confluence-review-page-draft.storage.html" \
  --content-format storage \
  > "$SMOKE_DIR/confluence-review-page-draft-create.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence blog draft create \
  --space "$CONFLUENCE_SPACE" \
  --title "Agent Access Draft Blog" \
  --content-file "$SMOKE_DIR/confluence-review-blog-draft.storage.html" \
  --content-format storage \
  > "$SMOKE_DIR/confluence-review-blog-draft-create.out.json"
```

Capture `pageId`/`blogId` and `draftHandle` from the create responses. View and
update through the draft handle:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page draft view <page-id> \
  --draft-handle <draft-handle> \
  --body-format storage \
  > "$SMOKE_DIR/attribution-page-draft-view.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page draft update <page-id> \
  --draft-handle <draft-handle> \
  --content-file "$SMOKE_DIR/confluence-draft-new-page-update.storage.html" \
  --content-format storage
```

Draft attachments are supported for new drafts only:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page draft attach <page-id> \
  --draft-handle <draft-handle> \
  "$SMOKE_DIR/confluence-draft-attachment.txt" \
  --content-type text/plain

"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page draft attachment list <page-id> \
  --draft-handle <draft-handle> \
  --output-format markdown
```

For staged drafts from existing content, validate create/view/update/publish or
discard separately. Staged-draft attachments fail closed unless and until they
are explicitly supported.

## Confluence Comment Mutation Smoke

Use throwaway page/blog content. Exercise footer comments and inline replies:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page footer-comment add "$CONFLUENCE_PAGE_ID" \
  --content-file "$SMOKE_DIR/confluence-footer-comment.storage.html" \
  --content-format storage

"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page footer-comment update <comment-id> \
  --base-version <version> \
  --content-file "$SMOKE_DIR/comment-mutation/page-footer-update.storage.html" \
  --content-format storage

"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page footer-comment delete <comment-id>
```

The same flow applies to `confluence blog footer-comment ...`. Inline comment
top-level creation is not exposed; use `inline-comment reply` on an existing
inline thread, then view/update/delete that reply as needed.

Also list the footer-comment thread once with `--read-content-format text` and
once with `--output-format markdown`. The embedded result must preserve each
native comment body and place a companion inside every body-bearing `comments[]`
item; whole-result output must include only the returned comments and must not
fetch replies or another page. Audit and service logs may record format names,
selected representation, byte counts, and stable outcomes, but not storage/ADF,
rendered content, pagination tokens, parser excerpts, links, macro parameters,
or internal identifiers. A deliberately low isolated Confluence
`max_body_bytes` must produce sanitized `upstream_protocol_failed`/502 with no
partial output; do not lower a shared live Broker solely for this check.

## GitLab Smoke Matrix

For the ten exact-filtered automated live tests, full environment contract,
and mutation confirmation sentinels, see
[GitLab Live Smokes](testing.md#gitlab-live-smokes).

The five approval/suggestion additions use these exact test names and
requirements:

- `real_broker_gitlab_merge_request_approval_read_smoke` is read-only and uses
  `AGENT_ACCESS_REAL_BROKER_URL`, `AGENT_ACCESS_REAL_GITLAB_PROJECT`, and
  `AGENT_ACCESS_REAL_GITLAB_MERGE_REQUEST_IID`.
- `real_broker_gitlab_merge_request_approval_rule_read_smoke` is read-only,
  requires Premium/Ultimate approval-rule access, and adds positive
  `AGENT_ACCESS_REAL_GITLAB_APPROVAL_RULE_ID`.
- `real_broker_gitlab_merge_request_suggestion_read_smoke` is read-only and
  uses `AGENT_ACCESS_REAL_BROKER_URL`,
  `AGENT_ACCESS_REAL_GITLAB_MUTATION_PROJECT`,
  `AGENT_ACCESS_REAL_GITLAB_MUTATION_MERGE_REQUEST_IID`,
  `AGENT_ACCESS_REAL_GITLAB_MUTATION_SOURCE_BRANCH`,
  `AGENT_ACCESS_REAL_GITLAB_MUTATION_EXPECTED_HEAD_SHA`, plus
  `AGENT_ACCESS_REAL_GITLAB_SUGGESTION_DISCUSSION_ID`,
  `AGENT_ACCESS_REAL_GITLAB_SUGGESTION_NOTE_ID`, and
  `AGENT_ACCESS_REAL_GITLAB_SUGGESTION_ID`. The configured suggestion must be
  applicable, unapplied, and associated with that expected head.
- `real_broker_gitlab_throwaway_formal_approve_unapprove_smoke` uses
  `AGENT_ACCESS_REAL_BROKER_URL`,
  `AGENT_ACCESS_REAL_GITLAB_MUTATION_PROJECT`,
  `AGENT_ACCESS_REAL_GITLAB_MUTATION_MERGE_REQUEST_IID`,
  `AGENT_ACCESS_REAL_GITLAB_MUTATION_SOURCE_BRANCH`, and
  `AGENT_ACCESS_REAL_GITLAB_MUTATION_EXPECTED_HEAD_SHA`, and requires
  `AGENT_ACCESS_REAL_GITLAB_APPROVE_UNAPPROVE_CONFIRM=throwaway-approve-unapprove`.
- `real_broker_gitlab_throwaway_single_suggestion_apply_smoke` uses all
  suggestion-read variables, adds canonical
  `AGENT_ACCESS_REAL_GITLAB_MUTATION_SOURCE_PROJECT`, and requires
  `AGENT_ACCESS_REAL_GITLAB_SUGGESTION_APPLY_CONFIRM=throwaway-single-suggestion`.
  It permanently commits to the configured source branch.
- `real_broker_gitlab_webhook_read_smoke` is read-only and uses
  `AGENT_ACCESS_REAL_BROKER_URL`,
  `AGENT_ACCESS_REAL_GITLAB_WEBHOOK_PROJECT`, and positive
  `AGENT_ACCESS_REAL_GITLAB_WEBHOOK_ID`.
- `real_broker_gitlab_throwaway_webhook_lifecycle_smoke` creates, delivers,
  resends, and deletes one disposable hook. It uses
  `AGENT_ACCESS_REAL_BROKER_URL`,
  `AGENT_ACCESS_REAL_GITLAB_WEBHOOK_MUTATION_PROJECT`, an explicitly safe
  `AGENT_ACCESS_REAL_GITLAB_WEBHOOK_RECEIVER_URL`, and requires
  `AGENT_ACCESS_REAL_GITLAB_WEBHOOK_LIFECYCLE_CONFIRM=throwaway-webhook-lifecycle`.

Run each test by its exact filter; never run all ignored live tests:

```bash
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_merge_request_approval_read_smoke -- --ignored --exact

BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_merge_request_approval_rule_read_smoke -- --ignored --exact

BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_merge_request_suggestion_read_smoke -- --ignored --exact

export AGENT_ACCESS_REAL_GITLAB_APPROVE_UNAPPROVE_CONFIRM=throwaway-approve-unapprove
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_throwaway_formal_approve_unapprove_smoke -- --ignored --exact

export AGENT_ACCESS_REAL_GITLAB_SUGGESTION_APPLY_CONFIRM=throwaway-single-suggestion
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_throwaway_single_suggestion_apply_smoke -- --ignored --exact

BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_webhook_read_smoke -- --ignored --exact

export AGENT_ACCESS_REAL_GITLAB_WEBHOOK_LIFECYCLE_CONFIRM=throwaway-webhook-lifecycle
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set BUILD_SERVICE_ENDPOINT}" \
build-cli build cargo -- test -p agent-access --test real_gitlab_smoke \
  real_broker_gitlab_throwaway_webhook_lifecycle_smoke -- --ignored --exact
```

After storing a GitLab upstream token and granting the repository selector,
start with read-only actions:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab branch list "$GITLAB_REPOSITORY" \
  > "$SMOKE_DIR/gitlab-branch-list.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab commit list "$GITLAB_REPOSITORY" \
  > "$SMOKE_DIR/gitlab-commit-list.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab pipeline list "$GITLAB_REPOSITORY" \
  > "$SMOKE_DIR/gitlab-pipeline-list.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab issue view "$GITLAB_REPOSITORY" <issue-iid> \
  --read-content-format markdown \
  > "$SMOKE_DIR/gitlab-issue-view-rendered.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab issue search "$GITLAB_REPOSITORY" --state opened --max-results 10 \
  --output-format markdown \
  > "$SMOKE_DIR/gitlab-issue-search.out.md"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request list-discussions "$GITLAB_REPOSITORY" <mr-iid> \
  --max-results 10 \
  > "$SMOKE_DIR/gitlab-mr-discussions.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request view-discussion "$GITLAB_REPOSITORY" <mr-iid> <discussion-id> \
  > "$SMOKE_DIR/gitlab-mr-discussion.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request list-reviewers "$GITLAB_REPOSITORY" <mr-iid> \
  > "$SMOKE_DIR/gitlab-mr-reviewers.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request list-commits "$GITLAB_REPOSITORY" <mr-iid> \
  > "$SMOKE_DIR/gitlab-mr-commits.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request list-pipelines "$GITLAB_REPOSITORY" <mr-iid> \
  > "$SMOKE_DIR/gitlab-mr-pipelines.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request list-diffs "$GITLAB_REPOSITORY" <mr-iid> --unidiff \
  > "$SMOKE_DIR/gitlab-mr-diffs.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request list-diff-versions "$GITLAB_REPOSITORY" <mr-iid> \
  > "$SMOKE_DIR/gitlab-mr-diff-versions.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request view-diff-version "$GITLAB_REPOSITORY" <mr-iid> <version-id> \
  --unidiff \
  > "$SMOKE_DIR/gitlab-mr-diff-version.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request diff-raw "$GITLAB_REPOSITORY" <mr-iid> \
  --output "$SMOKE_DIR/gitlab-mr.diff"
```

Confirm the embedded result preserves the exact native GitLab description and
adds a sibling Markdown `renderedBody`. The whole-result output must be plain
Markdown with the same issue page and continuation metadata as JSON mode and no
JSON envelope. Repeat one body-bearing note or discussion list in `text` and
whole-result modes; formatting must not issue a second GitLab request.

Use an MR containing at least one current line discussion and, if practical,
one discussion made outdated by a later push. Verify each positioned note has
paths, side/line or line range, and its reported base/start/head SHA
association. When GitLab reports no merge base, verify `baseSha` is `null`
while `startSha` and `headSha` remain present. Broker/API-created line-range
endpoints use `type = old` for removed or unchanged/context points and `type =
new` for added points; GitLab UI-created or otherwise returned positions may
expose `null` for unchanged/context endpoints. Preserve either returned
shape. An
ordinary `list-comments` result is expected not to contain line association.
Follow `nextPageToken` for discussions, each review-context list, and draft
notes with the
same action, page size, filters, and `--unidiff` choice. Correlate an outdated
position to `view-diff-version`; do not expect a synthetic current-line map.
Draft Notes are locally sliced from a fresh, single upstream array on every
request; do not expect the continuation to snapshot concurrent draft edits.
For positioned writes, refresh MR/diff context immediately beforehand and use
the expected current head; verify the Broker's fresh MR context contains the
complete non-null base/start/head triplet. Typed callers do not pass that
triplet. Do not reuse an outdated note's position as a current anchor.

On GitLab 18.4 or newer, confirm structured diffs preserve `collapsed` and
`tooLarge` when GitLab returns them. Older instances must omit those fields,
not synthesize `false`. Raw MR diff requires GitLab 17.9 or newer and records
the preflight head but is not a SHA-pinned snapshot. Verify an older server
fails explicitly rather than falling back to another route. Do not lower a
shared download cap merely to force an overflow test.

Also exercise the protocol surfaces: generic `invoke` with
`--output-format markdown`, a JSON `send` request carrying top-level
`responseFormat`, and direct HTTP carrying top-level `readContentFormat`.
`send` and HTTP keep the standard JSON envelope; typed and generic CLI print
only `result.value` on successful whole-result Markdown. Verify raw file, raw
MR diff, and job-trace downloads reject the presentation flags and retain
stream behavior.

With a throwaway MR and a per-user grant, exercise direct and pending review
participation. Replace the placeholders with a fresh head and coordinates from
the current structured diff:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request inline-discussion "$GITLAB_REPOSITORY" <mr-iid> \
  --expected-head-sha <head-sha> --position-type text \
  --old-path src/lib.rs --new-path src/lib.rs --new-line 42 \
  --content-file "$SMOKE_DIR/gitlab-inline.md" --content-format markdown

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request reply-discussion "$GITLAB_REPOSITORY" <mr-iid> \
  <outdated-discussion-id> --content-file "$SMOKE_DIR/gitlab-reply.md" \
  --content-format markdown

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request add-draft-note "$GITLAB_REPOSITORY" <mr-iid> \
  --content-file "$SMOKE_DIR/gitlab-draft.md" --content-format markdown

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request list-draft-notes "$GITLAB_REPOSITORY" <mr-iid>

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request submit-review "$GITLAB_REPOSITORY" <mr-iid> \
  --reviewer-state requested-changes \
  --content-file "$SMOKE_DIR/gitlab-summary.md" --content-format markdown

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request view-approval "$GITLAB_REPOSITORY" <mr-iid>

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request view-approval-state "$GITLAB_REPOSITORY" <mr-iid>

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request list-approval-rules "$GITLAB_REPOSITORY" <mr-iid>
```

Also cover positioned draft add/update using `--position-file` or the flat
text/file/image flags, draft view/update/delete, single publish, `publish-all`,
and a reply draft with `--in-reply-to-discussion-id`; exercise multiline and
image positions when the MR supports them. Stale-head writes must fail without
mutation, and multiline proof failures expose only `coordinates_unresolved` or
`patch_unavailable`; verify `overflow` and `without_files` versions use
`patch_unavailable`. Image x/y require nonnegative integers; include a
fractional-coordinate case and confirm the Broker rejects it before mutation.
Confirm replies to outdated discussions remain possible.

Drafts are owned by the active GitLab credential. Repeat with two distinct
per-user credentials to prove isolation; if service mode is intentionally used,
document that every granted principal shares the bot-owned draft set. On GitLab
19.2 or newer, verify `submit-review` permits zero drafts, changes only the
acting assigned reviewer's state to `reviewed` or `requested_changes`, and does
not claim formal approval. Older or unreadable versions must fail before
publication. An unassigned reviewer must receive `version_conflict` before any
write.

Force one accepted-but-unverifiable review mutation in a disposable setup. It
must return HTTP 409, `decision = error`,
`mutation_verification_failed`, `retrySafe = false`, and CLI exit 2. Refresh via
the safe result locators; do not retry automatically. Audit output must exclude
bodies, summaries, patches, native line codes, and continuation tokens; bounded
position type and numeric-line metadata may remain.
Also force an upstream 5xx after a disposable direct or single-item review
mutation request; it is potentially applied and must return the same
applied-unverified 409 contract, not an ordinary retryable upstream failure.
For publish-all and review-submit, verify the Broker re-reads the draft snapshot
and reviewer state: an ordinary sanitized upstream failure is valid only if
both prove unchanged, while any possible effect returns the 409 contract.
When submitting `requestedChanges`, verify only the reviewer-state transition.
Do not claim the MR is merge-blocked unless the GitLab tier and project setting
enable that behavior and current merge status independently confirms it.

On a dedicated throwaway MR, test formal approval using the freshly read full
head SHA. Confirm readiness includes a matching collected diff version,
non-`preparing`/`checking`/`approvals_syncing` detailed status, and non-null
patch ID before the write. Then verify the acting user appears in
`approvedBy` and `userHasApproved` is true when returned; after `unapprove`,
verify the inverse. Never use aggregate `approved` as actor proof. On an empty
or untouched legacy diff with null patch ID, verify approval fails before
mutation and do not loop retries; only a branch-changing push/rebase that
creates a new prepared version can make that case ready.

Suggestion apply permanently commits to the source branch. Use only a
dedicated throwaway MR/branch with a currently applicable suggestion and fresh
head:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request apply-suggestion "$GITLAB_REPOSITORY" <mr-iid> \
  <discussion-id> <note-id> <suggestion-id> \
  --expected-head-sha <head-sha> \
  --commit-message-file "$SMOKE_DIR/gitlab-suggestion-message.txt"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab merge-request apply-suggestions "$GITLAB_REPOSITORY" <mr-iid> \
  --suggestions-file "$SMOKE_DIR/gitlab-suggestions.json" \
  --expected-head-sha <new-head-sha>
```

The batch file is a JSON array of 1 to 100 unique
`discussionId`/`noteId`/`suggestionId` objects. Verify a custom message expands
GitLab `%{...}` templates and replaces its default message/co-author trailer.
Verify success by rereading each scoped discussion: the accepted endpoint
response can contain stale `applied = false` and contains no commit metadata.
Applying must not resolve the discussion. For a fork MR, verify one grant
covers both canonical target and source repositories and that the execution
credential can push the source branch; do not combine separate grants to make
the test pass. Force an accepted-but-unverifiable apply only in a disposable
setup and confirm the unsafe-to-retry 409 contract.

Confirm GitLab rich-content writes reject command-like quick-action lines
outside fences before the request, including `/approve` and `  /assign @me`,
without rejecting the same text inside fenced code or suggestion blocks,
inline prose, URLs, `/usr/bin`, or `/docs/readme.md`. With attribution enabled,
verify the fixed review subset is
exactly inline add, reply add, draft add, publish-all summary, and review-submit
summary; draft update remains unattributed.

Then mutate a throwaway issue:

The typed GitLab CLI uses the user-facing word `comment`; the canonical broker
actions surfaced by JSON `invoke`, JSON `send`, policy, and audit use GitLab's
REST term `note`, for example `issue.note.add` and `issue.note.update`.

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab issue create "$GITLAB_REPOSITORY" \
  --title "Agent Access Smoke Issue" \
  --content-file "$SMOKE_DIR/attribution-gitlab-issue-create.md" \
  --content-format markdown \
  --read-content-format markdown \
  > "$SMOKE_DIR/gitlab-issue-create.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab issue update "$GITLAB_REPOSITORY" <issue-iid> \
  --content-file "$SMOKE_DIR/attribution-gitlab-issue-update-with-old-footer.md" \
  --content-format markdown \
  > "$SMOKE_DIR/gitlab-issue-update.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab issue comment "$GITLAB_REPOSITORY" <issue-iid> \
  --content-file "$SMOKE_DIR/gitlab-issue-comment.md" \
  --content-format markdown \
  > "$SMOKE_DIR/gitlab-issue-comment.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab issue update-comment "$GITLAB_REPOSITORY" <issue-iid> <note-id> \
  --content-file "$SMOKE_DIR/gitlab-issue-comment-updated.md" \
  --content-format markdown \
  > "$SMOKE_DIR/gitlab-issue-comment-update.out.json"
```

Close or delete only throwaway artifacts according to the grant under test.

### GitLab Project Webhook Smoke

Use only an explicitly disposable project, receiver, and hook. The operator
must configure `[providers.gitlab.webhooks]` in TOML before startup or reload;
destination rules are not grant or portal configuration. Grant the ten
`webhook.*` actions individually as needed. Keep hook tokens and custom-header
values in env/file/stdin sources and disable shell tracing.

```bash
export GITLAB_WEBHOOK_TOKEN_FILE=/secure/path/gitlab-webhook-token
export GITLAB_WEBHOOK_HEADER_FILE=/secure/path/gitlab-webhook-authorization

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab webhook create "$GITLAB_REPOSITORY" \
  --destination-url https://hooks.example.com/gitlab/events \
  --event push --event merge_requests \
  --secret-token-file "$GITLAB_WEBHOOK_TOKEN_FILE"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab webhook view "$GITLAB_REPOSITORY" <hook-id>

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab webhook custom-header set "$GITLAB_REPOSITORY" <hook-id> Authorization \
  --value-file "$GITLAB_WEBHOOK_HEADER_FILE"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab webhook test "$GITLAB_REPOSITORY" <hook-id> --event push

"$AAB_BIN" --config "$AGENT_CONFIG" \
  gitlab webhook event list "$GITLAB_REPOSITORY" <hook-id> --max-results 20
```

Confirm delivery rows omit GitLab's upstream URL, redact sensitive and custom
header values, and mark payload/body truncation. Test/resend cause delivery;
never retry an `applied_unverified` result until current delivery state is
inspected. Resend only to a receiver designed to tolerate duplicates.

In an isolated Broker, remove the destination rule and reload to prove that
URL-preserving update, test, event list/resend, and delete remain available
under their action grants, while create/URL change return
`webhook_destination_denied`. Do not use a shared production hook for this
check. Delete the custom header, then the disposable hook, at the end. Evidence
may contain hook/event IDs, fixed action outcomes, introduced URL scheme, and
matched-pattern index; exclude destination host/path/query, secrets, delivery
content, receiver headers, and custom-header keys from ambiguous failures.

## Attachment And Send Smoke

For Jira and Confluence page attachments, confirm both typed upload/download
and representative generated `send` variants. Add the corresponding blog or
draft attachment actions when the grant under test includes those surfaces.

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue attach "$JIRA_ISSUE" "$SMOKE_DIR/jira-attachment.txt" \
  --content-type text/plain

"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue attachment list "$JIRA_ISSUE"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  jira issue attachment download "$JIRA_ISSUE" <attachment-id> \
  --output "$SMOKE_DIR/jira-attachment.download.txt"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page attach "$CONFLUENCE_PAGE_ID" "$SMOKE_DIR/confluence-attachment.txt" \
  --content-type text/plain

"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page attachment list "$CONFLUENCE_PAGE_ID"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  confluence page attachment download "$CONFLUENCE_PAGE_ID" \
  --attachment-id <attachment-id> \
  --output "$SMOKE_DIR/confluence-attachment.download.txt"
```

For `send`, the generated schema requires each upload file to declare
`role = "attachment"`. Upload metadata such as `attachments[].field`,
`attachments[].size`, and `attachments[].sha256` is generated by the CLI from
`files[]`; do not hand-write it in `inputs`.

```json
{
  "version": "agent-access.send.v1",
  "kind": "invoke",
  "service": "jira",
  "action": "attachment.add",
  "inputs": { "issue": "PROJ-123" },
  "files": [
    {
      "role": "attachment",
      "path": "/secure/path/jira-attachment.txt",
      "contentType": "text/plain"
    }
  ]
}
```

Run upload request files with:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  send --request-file "$SMOKE_DIR/send-jira-attachment-add.json" \
  > "$SMOKE_DIR/send-jira-attachment-add.out.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  send --request-file "$SMOKE_DIR/send-confluence-attachment-add.json" \
  > "$SMOKE_DIR/send-confluence-attachment-add.out.json"
```

Raw download through `send` uses `responseMode = "stream"` plus an explicit
output target and optional metadata output. Jira uses the `issue` locator:

```json
{
  "version": "agent-access.send.v1",
  "kind": "invoke",
  "service": "jira",
  "action": "attachment.download",
  "responseMode": "stream",
  "inputs": {
    "issue": "PROJ-123",
    "attachmentId": "10001"
  },
  "output": {
    "type": "file",
    "path": "/secure/path/jira-attachment.download.txt"
  },
  "metadataOutput": {
    "type": "file",
    "path": "/secure/path/jira-attachment.download.metadata.json"
  }
}
```

Confluence page attachments use the same stream shape with `pageId`:

```json
{
  "version": "agent-access.send.v1",
  "kind": "invoke",
  "service": "confluence",
  "action": "attachment.download",
  "responseMode": "stream",
  "inputs": {
    "pageId": "123456",
    "attachmentId": "att10001"
  },
  "output": {
    "type": "file",
    "path": "/secure/path/confluence-attachment.download.txt"
  },
  "metadataOutput": {
    "type": "file",
    "path": "/secure/path/confluence-attachment.download.metadata.json"
  }
}
```

Run stream download request files with:

```bash
"$AAB_BIN" --config "$AGENT_CONFIG" \
  send --request-file "$SMOKE_DIR/send-jira-attachment-download.json"

"$AAB_BIN" --config "$AGENT_CONFIG" \
  send --request-file "$SMOKE_DIR/send-confluence-attachment-download.json"
```

Compare downloaded bytes with the uploaded fixture. If an upload fails, inspect
existing upstream attachments and its mutation receipt before retrying. After confirming that the failed file was not created,
use a unique smoke filename to distinguish filename collisions from Broker
failures. Never replay a partially applied batch or an uncertain upload.
Attachment delete is not currently implemented for Jira or Confluence.

## Cleanup

Retain a private list of created IDs and the before/after state of edited test
objects. Restore edited objects where supported, delete disposable objects through
the upstream UI/API when the Broker offers no delete action, and verify each
cleanup outcome. Revoke temporary Broker tokens, remove temporary grants, and
revoke upstream test credentials that are no longer needed. Remove signed URL,
token and curl-auth files; retain only the protected evidence needed for review.
Do not remove shared credentials or grants used by other workloads.

## What To Record

For each smoke pass, record:

- date, branch/commit, binary path, and broker config source;
- whether attribution was enabled;
- principal and grant IDs, but not raw token values;
- services/actions tested;
- upstream object classes created, updated, published, discarded, or deleted;
- response artifact filenames;
- observed limitations or bugs.

Known behavior to check during manual smoke:

- Draft page and blog create/view/update flows are available.
- New-draft attachments are supported; staged-draft attachments fail closed.
- Publish actions publish the draft body and do not add attribution themselves.
- Jira comments and replies can be added and updated; attribution dedupes across
  update paths.
- GitLab REST smoke requires a configured GitLab upstream token and repository
  grant.
