# GitLab bot provisioning

Broker can provision either a project access token (which creates its bot user)
or a project service account with separately managed personal access tokens.
These are canonical `gitlab` provider actions, available through typed CLI,
`invoke`, JSON `send`, and HTTP. Each action requires an authorized
`git_repository` resource and the selected upstream user's GitLab permissions.
Group and instance service accounts are outside this project-scoped contract.

## Enable and authorize

Provisioning is disabled by default. The operator enables it and sets issuance
limits in TOML:

```toml
[providers.gitlab.provisioning]
enabled = true
max_access_level = 30
max_token_lifetime_days = 30
allowed_token_scopes = ["api", "read_api", "read_repository"]
```

Defaults are shown except for `enabled`, which defaults to `false`. Disabling
provisioning denies all operations in this document, including metadata reads
and revocation. Revocation remains available directly in GitLab.

`max_access_level` accepts GitLab project roles 10, 15, 20, 25, 30, or 40, and
caps both project token roles and service-account membership changes. Role 30
is Developer. The allowed token scopes are a nonempty subset of `api`,
`read_api`, `read_repository`, `write_repository`, `read_registry`,
`write_registry`, and `self_rotate`. Scopes are explicit, nonempty, and unique.
A token's `expiresAt` is required on both creation and rotation; it must be a
future UTC calendar date within `max_token_lifetime_days` (1–365). GitLab's own
licensing, role, scope, and lifetime restrictions also apply.

Grant each required action explicitly to the provisioning principal, with an
exact project resource or an intentionally selected resource group. Existing
review grants do not imply permission to create identities or export tokens.
For delegation on behalf of a person, select `credential_mode = "per_user"`.
A dedicated service credential is also supported. Service-mode lookup paths use
the separate read-only lookup credential to resolve the canonical repository;
per-user-only paths use the principal's selected credential. The execution
credential performs provisioning requests and must resolve that same project ID.

Example grant for TOML policy authority, referencing an existing project resource.
For managed policy, create the equivalent grant in the portal or management CLI;
inline TOML grants are rejected. Include the intended configured execution contexts:

```toml
[[policy.grants]]
subjects = ["user:alice@example.com"]
service = "gitlab"
actions = [
  "project.access_token.list", "project.access_token.view",
  "project.access_token.create", "project.access_token.rotate",
  "project.access_token.revoke",
]
resources = { resource_ids = ["review-project"] }
credential_mode = "per_user"
execution_contexts = ["default"]
```

## Project access token workflow

Creating a project access token creates its associated bot; the token name is
the bot display name. Its project role and scopes are supplied together.
GitLab requires a personal access token to create a project access token, and
requires Maintainer or Owner project permissions. Creating a token cannot grant a
higher role than the issuing actor. On GitLab.com, project access tokens
require Premium or Ultimate; self-managed GitLab supports them on all tiers.
See the [project access token API](https://docs.gitlab.com/api/project_access_tokens/)
and [project token requirements](https://docs.gitlab.com/user/project/settings/project_access_tokens/).

Choose a future date within the operator's limit in place of `YYYY-MM-DD`:

```bash
agent-access gitlab project access-token create team/repo \
  --name code-review-bot --access-level 30 --scopes api \
  --expires-at YYYY-MM-DD --token-output ./review-bot.token

agent-access gitlab project access-token list team/repo --max-results 20
agent-access gitlab project access-token view team/repo 123
agent-access gitlab project access-token rotate team/repo 123 \
  --expires-at YYYY-MM-DD --token-output ./review-bot-next.token
agent-access gitlab project access-token revoke team/repo 124
```

The role and `api` scope allow the review system to perform GitLab API writes
within that role. They are not a restriction to review comments alone. A
project access token's bot cannot be added to other projects. GitLab documents
an additional visibility caveat: a project token created by an internal user
can read projects with Internal visibility. Use the service-account path if
that distinction matters; GitLab marks service accounts as external users.

## Project service account workflow

A service account has an identity independent of individual tokens. Create it,
set its membership role, then issue one or more separately revocable tokens.
Project service accounts became generally available in GitLab 18.11; the
installed version must support the documented project service-account and
membership endpoints. Broker does not emulate them on older GitLab versions.
The upstream actor needs Maintainer or Owner project permissions (or the
applicable self-managed instance administrator authority). Subscription and
instance account limits also apply. See the
[service accounts API](https://docs.gitlab.com/api/service_accounts/#project-service-accounts)
and [service account membership rules](https://docs.gitlab.com/user/profile/service_accounts/).

```bash
agent-access gitlab service-account create team/repo \
  --name code-review-bot --username code-review-bot
# Use the returned result.serviceAccount.id in subsequent commands.
agent-access gitlab service-account member-set team/repo 70 --access-level 30
agent-access gitlab service-account token create team/repo 70 \
  --name reviewer-tool --scopes api --expires-at YYYY-MM-DD \
  --token-output ./reviewer-tool.token

agent-access gitlab service-account list team/repo
agent-access gitlab service-account view team/repo 70
agent-access gitlab service-account token list team/repo 70
agent-access gitlab service-account token rotate team/repo 70 123 \
  --expires-at YYYY-MM-DD --token-output ./reviewer-tool-next.token
agent-access gitlab service-account token revoke team/repo 70 124
agent-access gitlab service-account delete team/repo 70
```

Every operation with `userId` first retrieves that ID through the project's
service-account endpoint. Membership changes cannot target ordinary users or
accounts belonging to another project. `member.set` adds direct membership if
absent or changes the existing direct role. Token issuance and rotation require
an existing direct project membership within the operator's role cap. They do
not silently change membership. A higher-role account can still have its tokens
revoked. Account deletion uses GitLab's ordinary deletion behavior; destructive
`hard_delete` is not exposed.

Creation, membership, and issuance are separate writes, each independently
grantable and auditable. If a later step fails, the earlier successful steps
remain. Use the returned account ID to inspect and continue or delete it; do not
repeat account creation blindly.

## Canonical action contract

All inputs use `project` (the full repository path). IDs are positive integers;
`self` is not accepted as a token ID. Extra input keys are rejected.

| Action | Additional required inputs | Optional inputs |
| --- | --- | --- |
| `project.access_token.list` | — | `maxResults`, `pageToken` |
| `project.access_token.view` | `tokenId` | — |
| `project.access_token.create` | `name`, `accessLevel`, `scopes`, `expiresAt` | — |
| `project.access_token.rotate` | `tokenId`, `expiresAt` | — |
| `project.access_token.revoke` | `tokenId` | — |
| `service_account.list` | — | `maxResults`, `pageToken` |
| `service_account.view` | `userId` | — |
| `service_account.create` | `name` | `username` |
| `service_account.delete` | `userId` | — |
| `service_account.member.set` | `userId`, `accessLevel` | — |
| `service_account.token.list` | `userId` | `maxResults`, `pageToken` |
| `service_account.token.create` | `userId`, `name`, `scopes`, `expiresAt` | — |
| `service_account.token.rotate` | `userId`, `tokenId`, `expiresAt` | — |
| `service_account.token.revoke` | `userId`, `tokenId` | — |

Lists return `items`, `count`, `maxResults`, `isLast`, and `nextPageToken`.
Pagination is bounded by `providers.gitlab.search.max_results` and uses signed,
expiring cursors bound to the caller, credential mode, action, project, account,
provider configuration, and page size. Account token rotation locates the old
token through the account's paginated token list, capped at 100 pages of 100
entries; an exhausted lookup fails before rotation.

Rotation checks the old token's active/revoked state, scopes, and role against
current operator limits before requesting a replacement. It preserves the
identity and permissions and requires a new explicit expiry. A revoked or
inactive token cannot be rotated through Broker. GitLab's token-family reuse
detection still applies if a token changes concurrently; do not retry rotation
automatically. Revocation is separately grantable and does not require issuance
limits to match the old token.

For HTTP, use `POST /v1/invoke/gitlab/<action>` with `{"inputs": {...}}`.
For JSON `send`, use the normal request document:

```json
{
  "version": "agent-access.send.v1",
  "kind": "invoke",
  "service": "gitlab",
  "action": "project.access_token.create",
  "inputs": {
    "project": "team/repo",
    "name": "code-review-bot",
    "accessLevel": 30,
    "scopes": ["api"],
    "expiresAt": "YYYY-MM-DD"
  }
}
```

`agent-access invoke gitlab.project.access_token.create --input-file request-inputs.json`
uses the same canonical inputs. Inspect `agent-access spec catalog` for the live,
caller-filtered schema. All provisioning results use JSON presentation.

## Issued secret delivery and MCP integration

Only token creation and rotation return `result.issuedToken`. Metadata is in
`result.accessToken`; account operations use `result.serviceAccount`, membership
changes use `result.member`. Metadata reads and audit records do not include raw
tokens. Unexpected upstream fields are discarded. Execution and lookup
credentials are never returned.

This is deliberate issuance of a new credential for downstream use. The
canonical HTTP, `invoke`, and `send` responses deliver that new secret to the
authorized caller. Without `--token-output`, the typed CLI also prints it in its
JSON response. With `--token-output`, it writes only the new token plus a newline
to a new file, created with mode 0600 on Unix, and prints metadata with
`tokenWritten: true`. Existing files and symlinks are rejected before the
upstream call. The parent directory must already exist. A failed call may leave
an empty reserved file when the outcome is uncertain; inspect the outcome before
removing it and retrying. A definitive Broker denial removes the unused reservation. If local cleanup fails,
the CLI warns and preserves the denial response and exit code.

The runtime catalog advertises `sensitiveOutputPointers: ["/result/issuedToken"]`
for these four actions. OpenAPI operations and JSON send variants publish
`x-agent-access-sensitive-output-pointers` with the same envelope-relative
pointer. This marker describes sensitivity; it does not hide results from a
client, model, transcript, or downstream MCP tool. MCP adapters must preserve
this deliberate output contract and decide how their client will receive the
secret. HTTP responses containing issued tokens carry `Cache-Control: no-store`.
No server-side secret destination, automatic managed-credential import, or
external secret-manager write is part of this feature.

A downstream token acts directly under GitLab permissions. Broker grants and
broker-token restrictions govern its issuance, not its later use. Revoking a
Broker grant or disabling provisioning does not revoke an already issued
GitLab token. Revoke it through the appropriate token action or GitLab itself.

Successful mutations report `mutationStatus: "applied"` and `retrySafe: false`.
A malformed successful response, transport failure, timeout, oversized/invalid
response, or server error after a write attempt uses the canonical
`mutation_verification_failed` error (HTTP 409, CLI exit 2):
`mutationStatus: "applied_unverified"`, `retrySafe: false`,
`verificationStage: "mutation_response"`, and numeric IDs under `safeLocators`.
The write may have applied; this status does not prove it succeeded.
Rotation always identifies the old token as `previousTokenId`; `tokenId` is
present only when a different new ID was returned. These IDs and the available
upstream status/duration are also audited. Upstream 400/422 validation responses
produce a sanitized `input_invalid` denial without echoing GitLab's message. The token cannot be retrieved again by a metadata read.
If delivery fails or the client loses the response, inspect the account/token
list and revoke or reconcile the issued token before trying again. Broker does
not automatically replay issuance, rotate again, or roll back a successful
upstream write.
