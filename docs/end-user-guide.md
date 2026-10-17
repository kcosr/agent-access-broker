# End-user guide

For a portal walkthrough with screenshots, start with
[user self-service](portal-guide/user.md).

Use this guide to connect your account, store an upstream credential, and give an
agent a Broker invocation token. Your administrator must first configure the
integration, create your account, and grant access. Ask them for the broker HTTPS
URL, your login method or finite setup token, the available execution contexts,
the services/resources you may use, and the credential connections you set up.
Administrator setup is in the
[administrator guide](administrator-guide.md).

A Broker token authenticates to the broker. An upstream credential authenticates
the broker to Jira, Confluence, GitLab, or another service. Keep them separate.
The agent receives only its Broker invocation token; the broker retains your
upstream execution credential. Your current grants and upstream permissions still
control every call.

## Sign in and check access

Open `https://<broker-host>/ui`. Sign in with the local username/password your
administrator supplied or choose Microsoft sign-in when available. Change a
temporary local password before continuing. Microsoft linking uses the immutable
directory identity, not email matching; contact your administrator if it opens an
unexpected account.

In **My access > Access**, review your services, actions, resources, and contexts.
Select an action for its complete resource alternatives and exclusions. Filters
only change this view. Account roles do not create invocation grants, and an
empty access page needs administrator action before an agent token can be issued.

The **Account** page shows account settings and service limits. Personal
**Credentials**, **Tokens**, and **Activity** require self-service to be enabled.
If it is disabled, ask an administrator to manage your credentials/tokens.
Account and password settings remain available.

Press **Ctrl+K / ⌘K** to jump to pages, your available services and actions, your
tokens, and the credential connections you have stored a token for. Search uses
connection and service names and IDs, profiles, and credential IDs; secret
values are never searched. Selecting a service action opens its authorized access view.
See [portal search](portal-guide/index.md#search-and-jump-with-ctrlk--k).

Microsoft groups refresh on successful Microsoft login and expire after the
configured TTL. Logging out of the broker does not end Microsoft SSO. A new
Microsoft login refreshes membership evidence; local groups and direct grants
remain independent. Microsoft-only users change their password at Microsoft.

## Store a credential or connect OAuth

Your personal upstream credentials are organized as **credential
connections**. A connection is one credential that one or more services use:
for example, one GitLab token can serve both GitLab REST and Git. Your
administrator decides how each connection authenticates. When it uses OAuth,
you connect your upstream account; otherwise you store a token. You do not
choose between them, and a stored token is never used in place of a connection
that uses OAuth.

**My access > Credentials** lists one row per connection, naming the services you
are granted that use it and counting any others. Select a connection, enter the
requested fields, save, and verify when supported. Use the token form the broker
offers. Verification probes as you through one of those services; a Git gateway
needs a repository you can fetch. A connection that uses OAuth is one row per
OAuth registration, with **Connect account**, **Reconnect** and **Disconnect**.
Rows marked **Not used** are stored credentials the configuration no longer
selects, for example a token you stored before two services began sharing a
connection; no service reads them, and you can delete them.
Storing a credential does not create a grant: each service that uses the
connection still needs its own grant. Service-mode actions use the configured
shared identity and may not require a personal credential. Teams destination
URLs are managed by administrators.

For Gmail and other supported OAuth-backed services, your administrator enables
self-service, configures the connection's OAuth registration, and grants you or
one of your current groups an active `per_user` action grant on a service that
uses it. No separate
credential rights are required. Choose **Connect account** on its row, complete upstream
consent, and confirm the connection status. You can prepare an account even when
its resources or execution contexts are not currently available; each invocation
still needs its own authorization.

An existing connection stays visible and disconnectable after you lose its grant,
while self-service remains enabled and a credential connection still uses the
registration. Connect/reconnect remains unavailable until you have a matching
grant. Disconnecting a shared connection affects every service using that
registration.
See [administrator OAuth setup](administrator-guide.md#enable-personal-oauth-connections).
Do not paste an OAuth access token into a generic API-token field. OAuth consent requires a
signed-in browser session; the CLI setup token alone cannot authorize it. See
[Gmail](providers-gmail.md), [OAuth connections](oauth.md), and
[imported OAuth](imported-oauth.md).

An imported MCP connection may show **Server-default permissions**. Its
authorization server chooses the permissions for that service. **Known scopes**
lists currently known scope details. These may come from a token response or
OAuth's rules for retaining or inferring scopes when a response omits them; they
are not necessarily what the latest response reported. **Scope details
unavailable** means the Broker has no scope details, not that your connection has
no permissions. Your Broker action and execution-context grants still determine
which tools agents may invoke.

To do the same work with the CLI, use a short-lived `user_manage` setup token.
An `agent_invoke` token cannot manage credentials or issue tokens. Configure a
separate setup client file so the management credential is kept distinct from the
agent's credential:

```toml
# ~/.config/agent-access/setup.toml
[service]
url = "https://broker.example"

[identity]
header = "Authorization"
scheme = "Bearer"
disabled = false
token_file = "~/.config/agent-access/setup.token"
```

Replace the URL with your deployment. Save the token your administrator supplied
using the interactive prompt, then check identity:

```bash
agent-access --config ~/.config/agent-access/setup.toml config validate
agent-access --config ~/.config/agent-access/setup.toml auth token set
agent-access --config ~/.config/agent-access/setup.toml auth status
agent-access --config ~/.config/agent-access/setup.toml credentials list
```

`auth token set` saves the token locally without putting it in the command line.
`auth token status` checks only the file; `auth status` contacts the broker.
Additional HTTPS trust anchors can be configured in `[service.tls]`; keep
certificate verification enabled. See [CLI transport security](cli.md).

The following credential examples assume upstream secret values have already
been loaded securely into the named environment variables. Use `--field-env`
with the variable's name, not its expanded secret value. You can instead use
`--field-file token=/secure/path` or `--field-stdin token`.

`credentials targets` lists the connections you can store a token for, with
their fields. Each command names the connection, which may be shared: the
`atlassian` connection's one account email and API token serves Jira and
Confluence, and the `gitlab` connection's one token serves GitLab REST and Git,
when your administrator shares them. Use the connection IDs `credentials
targets` shows.

```bash
agent-access --config ~/.config/agent-access/setup.toml credentials targets

agent-access --config ~/.config/agent-access/setup.toml credentials put atlassian \
  --username-env ATLASSIAN_USERNAME --field-env token=ATLASSIAN_API_TOKEN \
  --display-name "My Atlassian account" --verify

agent-access --config ~/.config/agent-access/setup.toml credentials put cloudbees_ci \
  --username-env CLOUDBEES_CI_USERNAME --field-env token=CLOUDBEES_CI_API_TOKEN \
  --display-name "My CloudBees CI account"

agent-access --config ~/.config/agent-access/setup.toml credentials put gitlab \
  --field-env token=GITLAB_ACCESS_TOKEN --display-name "My GitLab account" --verify
```

Managed browser sessions and `user_manage` bearers manage these connection
tokens through their configured per-user policy visibility. Explicit
credential rights remain required for intentionally enabled classless static
credential management. You can always inspect and delete your own token, and
delete retained rows, even after losing the grant; OAuth owner cleanup after
grant removal follows its own rules. Administrative credential commands act
through a separate role-gated authority path.

Run only the commands for connections `credentials targets` or `credentials
list` shows. `--token-file`/`--token-env` select the **Broker** token;
`--field-file`/`--field-env` select the **upstream** credential field. They are
not interchangeable.

```bash
agent-access --config ~/.config/agent-access/setup.toml credentials inspect atlassian
agent-access --config ~/.config/agent-access/setup.toml credentials verify atlassian
agent-access --config ~/.config/agent-access/setup.toml credentials verify atlassian \
  --service confluence
agent-access --config ~/.config/agent-access/setup.toml credentials verify gitlab \
  --service gitlab_git --repository group/project
```

Without `--service`, verification probes through a service that can identify
your upstream account, or checks the token locally. Verifying through a Git
gateway service requires a repository. Metadata reads never return the stored
secret. `lastVerificationAttemptAt` records attempts, `lastVerifiedAt` records
success, and `verificationStatus` distinguishes local verification, upstream
verification, and failure. Check the sanitized error code after a failed attempt.

## Issue a token for the agent

In **My access > Tokens**, choose **Issue token** to open the token creation
page. Set a descriptive name, finite lifetime, and one or more effective execution
contexts. **Follow current grants** follows your grants within those contexts.
**Restrict to selected** adds service, action, and resource/group restrictions as
a ceiling. Choose the smallest useful boundary for dedicated automation.

Each service uses the same **Read-only** and **Write-capable** action columns as
the grant builder. Filter actions, then use **All** or **None** within a column
to change only matching actions; other selections remain. Actions without
reviewed read-only metadata are write-capable. A selected action that is no
longer available stays visible so you can remove it.

Each restricted service has its own collapsible section. Its resource choices
list only the resource types the service's actions use.

Check **Summary** and the **Effective access** preview on the page before
choosing **Issue token** in the persistent action bar. While a name, lifetime,
context, service, or action is missing, the bar counts the issues and links to
the first one, and the preview shows guidance. An explicit empty resource
selection is valid but allows no resources. **Cancel** returns to the
token list or the page that opened the form, after confirming discard of any
changes. Drafts are not saved across a refresh.

Successful issuance opens **Token created** over the owner's token list with
the new token selected. The raw token is shown once; save it to the agent's
protected secret location before closing the dialog. Keep the page open while
issuance is pending: closing or refreshing it can lose the one-time response.

When the deployment offers [remote HTTP MCP](mcp.md#http-endpoint) with Bearer
tokens, the **Token created** dialog also shows **Connect an MCP client**: the
server URL, a line that sets `AGENT_ACCESS_TOKEN` to the new token (macOS/Linux
or Windows PowerShell), and setup for Pi, OpenCode, Claude Code, Codex, or Cursor.
Pi, OpenCode, and Codex get a command and a configuration file, and Cursor an
install link and a configuration file. Claude Code gets only a user-scope
command, which adds the server for all your projects. The client snippets name
the variable, never the token; the portal remembers the chosen client in the
browser. Management tokens have no MCP setup.

Token issuance requires an effective invocation grant. It never creates access.
The lifetime must be one of the choices configured by the operator. A nonexpiring
token is available only if the operator explicitly permits it.

The production baseline uses the concrete `default` execution context. Replace it
in these examples with your effective context when your deployment uses another
value. Selecting a context narrows the token; it does not tell ingress which
context to attest.

```bash
agent-access --config ~/.config/agent-access/setup.toml tokens issue \
  --name engineering-reader --execution-context default --ttl 30d
```

For a restricted Jira token, assuming `jira-eng` is an accessible catalog resource:

```bash
agent-access --config ~/.config/agent-access/setup.toml tokens issue \
  --name jira-eng-reader --execution-context default --ttl 30d \
  --service jira --action jira=issue.view --action jira=search \
  --resource-id jira=jira-eng
```

Resource flags are repeatable `--resource-id SERVICE=ID` and
`--resource-group-id SERVICE=ID`. A resource restriction also needs the service
and actions selected. Omitted resource restrictions follow grants; an explicitly
empty restriction allows no resources for that service. Resource groups retain
live membership, and broad all/namespace selectors can cover newly created
upstream targets. The selected IDs cannot be edited on a token; issue a
replacement to change them. Catalog/group/grant edits still affect subsequent
requests. See [resources](resources.md).

## Connect the CLI or MCP client

Create a separate invocation client config:

```toml
# ~/.config/agent-access/agent.toml
[service]
url = "https://broker.example"

[identity]
header = "Authorization"
scheme = "Bearer"
disabled = false
token_file = "~/.config/agent-access/agent.token"
```

Save the newly issued `agent_invoke` token using the prompt. Do not save the
setup token here:

```bash
agent-access --config ~/.config/agent-access/agent.toml auth token set
agent-access --config ~/.config/agent-access/agent.toml auth status
agent-access --config ~/.config/agent-access/agent.toml broker status
agent-access --config ~/.config/agent-access/agent.toml services list
agent-access --config ~/.config/agent-access/agent.toml spec catalog
```

Confirm the expected principal and version. Discovery is caller-filtered;
resources permitted by broad selectors may not be individually listed. Test a
read within your grant, for example:

```bash
agent-access --config ~/.config/agent-access/agent.toml jira issue search \
  --project ENG --text "deployment checklist"
```

For local stdio MCP, configure your client to launch:

```bash
agent-access --config ~/.config/agent-access/agent.toml mcp serve
```

Use `mcp serve --service jira` for one service. For authenticated remote HTTP MCP,
use your administrator's `/mcp` or `/mcp/<canonical-service-id>` URL and invocation
token; the portal shows `/mcp` client setup when it issues the token. A
service-specific connection changes tool presentation; it does not narrow the
token. [MCP setup](mcp.md) documents complete client examples and transfers.

Use the broker base URL for your intended ingress. There is no CLI flag to assert
`X-Agent-Access-Context`; protected context/identity headers require an approved
trusted caller. For workspaces with opt-in proxy-attested identity, follow
[managed workspace identity](managed-identity.md) with your administrator.

## Connect Git

Use the separate gateway hostname supplied by your administrator, not the public
`/v1` API URL. Git can prompt for username `agent-access` (unless your deployment
specifies another username) and the invocation token as password. To read the same
saved token automatically, configure the helper only for that gateway host:

```bash
git config --global --replace-all \
  credential.https://git.example.com.helper ""
git config --global --add \
  credential.https://git.example.com.helper \
  '!agent-access --config ~/.config/agent-access/agent.toml auth git-credential'
git clone https://git.example.com/group/project.git
```

Replace `git.example.com` with the exact brokered hostname first. The empty entry
clears inherited helpers for that URL. The next reads the current Broker token
without storing another copy in Git. Never register this host-agnostic helper for
all HTTPS hosts: URL scoping prevents offering your Broker token elsewhere.
Updating the saved invocation token affects later Git commands. Git `store` and
`erase` do not change the Agent Access token file.

## Rotate, pause, and revoke

Use your browser session or `user_manage` client for management:

```bash
agent-access --config ~/.config/agent-access/setup.toml tokens list
agent-access --config ~/.config/agent-access/setup.toml tokens inspect "<token-id>"
agent-access --config ~/.config/agent-access/setup.toml tokens pause "<token-id>"
agent-access --config ~/.config/agent-access/setup.toml tokens resume "<token-id>"
agent-access --config ~/.config/agent-access/setup.toml tokens revoke "<token-id>"
```

Pause disables an agent token temporarily and preserves its secret and boundary.
Revoke permanently when it is no longer needed or may have been disclosed. To
rotate, issue a replacement, update the agent secret/file, verify a read, and
revoke the old token. Ask your administrator to revoke the setup token after onboarding; use a fresh
finite setup token or browser session for later management.

```bash
agent-access --config ~/.config/agent-access/setup.toml credentials delete atlassian
agent-access --config ~/.config/agent-access/setup.toml credentials delete-retained "<credential-id>"
```

Deleting a credential removes the broker's encrypted copy; it does not revoke
the upstream credential. `credentials list` shows the IDs of retained rows. Revoke it upstream when needed. Disabled/expired/revoked
records can remain visible for administration; they are not proof of active access.

## Review activity and get help

With a SQLite audit store, **My access > Activity** shows your requests and token,
credential, and login activity. Select a record for its request timeline and use
token **View activity** to filter. Successful routine metadata reads are not
recorded; changes, invocations, sign-ins, and denied/failed requests are.

```bash
agent-access --config ~/.config/agent-access/setup.toml audit events list \
  --since 7d --service jira
agent-access --config ~/.config/agent-access/setup.toml audit requests inspect "<broker-request-id>"
```

JSONL audit is not queryable through the portal/CLI. When asking for support,
include the reason code, `agentRequestId`, `brokerRequestId`, service/action, and
time. Keep tokens, cookies, upstream credentials, and private payloads out of the
report.

| Symptom | Next step |
| --- | --- |
| `broker_token_class_denied` during management | Use your browser session or `user_manage` token; the agent token is invocation-only |
| `self_service_disabled` | Ask an administrator to manage your credentials/tokens or enable personal self-service |
| OAuth Connect/Reconnect unavailable | Ask the administrator to check self-service, your active direct/group `per_user` grant on a service using the connection, and the connection's OAuth registration; an existing owned connection can still be disconnected after grant loss |
| `right_missing` during classless static credential management | Ask the administrator to inspect the scoped right on the connection, its expiry, and revocation; these rights do not govern OAuth |
| No visible service or no context to select | Ask the administrator to review active grants, group membership, and contexts |
| `credential_not_found` | Store your token for the service's credential connection, or reconnect OAuth |
| `credential_not_provisioned` | The service's credential connection offers no personal credential for your account type, or the service has none; ask the administrator |
| `service_action_denied` | Compare the requested action/resource with current grants and the token's immutable restrictions |
| `execution_context_denied` | Use the correct ingress and a token/grant authorized for that context; token selection cannot attest context |
| `broker_token_paused` | Resume only if the secret remains trusted; otherwise replace and revoke it |
| `rate_limited` | A Broker limit rejected the request; wait its reported retry interval before trying again |
| `upstream_rate_limited` | The provider/OAuth server throttled it; wait and inspect any mutation outcome first |
| `mutation_verification_failed` or `applied_unverified` | A write may have applied; inspect the safe result locators before deciding whether to repeat it |
| Output-file save failure after operation success | Preserve the receipt and recover output if possible; do not replay a mutation to save its response |
| `encryption_key_missing` / `credential_decrypt_failed` | Ask the operator to repair the key ring or matched backup; replacing a user token will not fix decryption |
| Microsoft login unavailable or incomplete group claim | Use an existing local login if available and contact the operator; do not repeatedly retry enrollment |

Exact command contracts and exit codes are in the [CLI reference](cli.md).
