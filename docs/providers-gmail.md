# Gmail

Gmail uses a per-user Google OAuth connection. One Google web application belongs
to the Broker deployment; each Broker user separately authorizes their own mailbox.
A personal deployment with one user uses exactly the same model. Consumer Gmail
accounts need not belong to a common organization. Workspace accounts can use the
same flow, subject to their administrator's app-access policies; this integration
does not use domain-wide delegation or service-account impersonation.

## Setup

Create a Google Cloud project, enable the Gmail API, and create a **Web application**
OAuth client with an External audience for a consumer account. Register the exact
callback URI below. Keep its secret outside the repository using an env/file secret
reference. Enable the Broker's managed store, managed identity, credential encryption,
management and browser authentication as described in [OAuth](oauth.md) and the
[operator guide](operator-guide.md). Google connection consent is separate from
logging into the Broker.

Add this fragment to that managed configuration:

```toml
[providers.gmail]

[oauth.registrations.google]
adapter = "google"
base_url = "https://accounts.google.com"
redirect_uri = "http://127.0.0.1:8787/v1/oauth/callback/google"
client_id = "YOUR_CLIENT_ID.apps.googleusercontent.com"
client_secret_ref = "env:GOOGLE_CLIENT_SECRET"
client_auth = "client_secret_post"
encoding = "form"
rotation = "preserve_old"
allow_insecure_loopback = true

[oauth.registrations.google.permission_profiles.mail]
scopes = ["openid", "https://www.googleapis.com/auth/gmail.modify"]
audience = "https://gmail.googleapis.com/"
target = "me"

[credentials.connections.gmail]
display_name = "Gmail"
oauth = { registration = "google", profile = "mail" }

[credentials.per_user.gmail]
type = "connection"
connection = "gmail"
```

The [credential connection](configuration.md#credential-connections) sets only
`oauth`, so people connect their mailbox; service accounts and `system`
principals have no Gmail credential.

Create the mailbox grant in the managed Policies dashboard or management CLI;
managed policy rejects inline TOML grants. For example, run as an administrator
and replace the principal and context with configured values:

```bash
agent-access admin policy grants create \
  --subject user:YOUR_BROKER_PRINCIPAL --service gmail \
  --credential-mode per_user --execution-context default \
  --action account.view --action label.list \
  --action message.search --action message.view --action thread.view \
  --action message.archive --action thread.archive \
  --action message.trash --action thread.trash \
  --action message.restore --action thread.restore
```

Omit mutations from this grant when only mail reads are needed. Do not add
resource selectors: Gmail grants authorize actions on the connected mailbox.

Use `browser_auth.public_origin = "http://127.0.0.1:8787"` for this example.
The public origin and registered callback must agree exactly. A browser accessing
that literal loopback address can use HTTP with the explicit opt-in, including
through an SSH local port forward to a remote Broker. Google redirects the browser
back; Google does not need inbound network access to the Broker. A normal hosted
origin needs HTTPS with a certificate trusted by the browser. The Broker listener
serves HTTP; terminate TLS at your deployment's reverse proxy.

Enable the owner's self-service setting. The Gmail credential connection's OAuth
binding and an active `per_user` action grant, assigned directly or through a current group,
permit connect/reconnect; no separate credential rights are required. The owner
can still inspect and disconnect an existing connection after grant removal while
self-service remains enabled. See the
[administrator guide](administrator-guide.md#enable-personal-oauth-connections).
Log into the portal and,
under **My access > Credentials**, select **Connect account**
on the Google registration's Gmail row. The connection uses PKCE, state and the browser session. Reconnect requires
the same Google `sub`; an explicit account replacement through the management API
is a separate intent. Tokens stay encrypted in the Broker and are never sent to
CLI/MCP agents. Disconnect is local; remove Google's app consent separately if desired.

Google's `gmail.modify` consent permits more than these Broker actions, including
sending. The Broker exposes only the actions listed here and enforces each caller's
grants before acquiring a token. There are no send, draft, arbitrary label-edit or
permanent-delete actions. Permissions are mailbox-wide; message IDs and Gmail
queries are not Broker policy resources. Configure explicit action grants. Resource selections on these grants are rejected; the portal offers action restrictions for Gmail.

Google's External Testing status expires Gmail authorizations/refresh tokens after
seven days. For durable personal use, review Google's production publishing and
personal-use verification exception. Publishing status and verification are separate;
this implementation does not imply approval to run a shared public OAuth service.
See [Google's web-client flow](https://developers.google.com/identity/protocols/oauth2/web-server),
[audience settings](https://support.google.com/cloud/answer/15549945), and
[personal-use exception](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification#personal-use).

## Actions

| Canonical action | Typed CLI |
|---|---|
| `gmail.account.view` | `agent-access gmail account` |
| `gmail.label.list` | `agent-access gmail labels` |
| `gmail.message.search` | `agent-access gmail message search --query 'in:inbox' --max-results 20` |
| `gmail.message.view` | `agent-access gmail message view MESSAGE_ID` |
| `gmail.thread.view` | `agent-access gmail thread view THREAD_ID` |
| `gmail.message.archive` | `agent-access gmail message archive MESSAGE_ID` |
| `gmail.thread.archive` | `agent-access gmail thread archive THREAD_ID` |
| `gmail.message.trash` | `agent-access gmail message trash MESSAGE_ID` |
| `gmail.thread.trash` | `agent-access gmail thread trash THREAD_ID` |
| `gmail.message.restore` | `agent-access gmail message restore MESSAGE_ID` |
| `gmail.thread.restore` | `agent-access gmail thread restore THREAD_ID` |

Thread actions operate on a Gmail conversation's current messages. Archive removes
`INBOX`; it creates no rule for later replies. Message actions affect only the
named message. Trash is reversible using restore, which invokes Gmail's `untrash`
operation. Restore does not promise to reconstruct prior labels or Inbox placement.
No action expands a search into a bulk mutation.

Search supports Gmail query syntax, `maxResults` (default 20, maximum 50),
`pageToken` (CLI `--page-token`) and `includeSpamTrash` (CLI `--include-spam-trash`).
Use `--query 'in:trash' --include-spam-trash` to find mail to restore. Each invocation
fetches exactly one page and bounded metadata for that page; callers request each
continuation by passing the response's `nextPageToken` as `pageToken` with the
same query, `maxResults` and `includeSpamTrash`. Omitted values count as their
defaults, so a continuation may state them explicitly or omit them.

`nextPageToken` is a Broker-signed envelope of at most 2,786 characters around
Gmail's own page token, which the Broker accepts up to 2,048 bytes and never
truncates; a longer Gmail token fails the search with `upstream_protocol_failed`.
The envelope is bound to the action, execution context, caller and credential
mode, the Broker's connection to the mailbox, and the query settings above. It
is not bound to grants: every page is authorized again. Routine access-token
refresh keeps it valid. Reconnecting or replacing the account, a Broker reload
or restart, 15 minutes after issue, or any changed setting makes it fail with
`input_invalid` before Gmail is contacted; restart the search without
`pageToken`. Message IDs apply to the current mailbox, so discard saved IDs when
deliberately changing accounts.

Reads project useful headers, label IDs, snippets, decoded text parts and attachment
metadata. Content is marked `contentTrust: "untrusted"`; mail may contain malicious
instructions. HTML is returned as text data, never rendered or fetched. Attachment
file downloads, compose/send, permanent deletion and background synchronization
are not supported. Responses are bounded by the lower of the configured
upstream response byte limit and 4 MiB across all requests, a 30-second total deadline,
100 MIME parts per message, depth 16, 256 KiB decoded body text across the invocation,
and 100 messages per thread. Part, depth and decoded-text limits preserve message
metadata and explicitly report `bodyTruncated` and `bodyOmissions` on affected
messages. Projected headers are limited to 200 values of 16 KiB each, with
`headersTruncated` when needed; unprojected headers are skipped. Attachment filenames
are limited to 4 KiB with `filenameTruncated`; MIME types over 256 bytes omit that
part with `bodyOmissions: ["part_metadata_limit"]`. The upstream byte
limit, malformed JSON/base64 and excessive thread message counts still fail the read.
MIME charsets decode to UTF-8. Unknown labels use UTF-8 with `charsetFallback: true`;
invalid byte sequences become replacement characters with `decodeErrors: true`.

All actions use fixed `users/me` routes and the invocation's original connection.
Consent changes, disconnect and account replacement fence in-flight revalidation.
Google reusable refresh material survives transient failures and interrupted attempts
with persisted exponential cooldown (up to five minutes, or longer when a Google
HTTP 429 names a longer `Retry-After`, bounded to one day). Three consecutive malformed
responses discard unusable refresh material and report reconnect required. The owner
must reconnect to clear this state; ordinary retries, reloads and client-secret rotation do not clear
it. Invocations report `oauth_reconnect_required`. Invalid grants also require reconnect. A successful refresh may omit a replacement refresh token or scope;
existing **granted** scope evidence is retained when scope is omitted. Initial consent
must supply scope evidence and fresh refresh material. Requested or callback scopes
are never treated as proof of authorization.

A 401 permits one credential recovery after explicit authentication rejection.
Transport errors, 403, 429 and server failures never replay mutations. A failed or
timed-out mutation can have an unknown outcome: inspect the mail before retrying.
Such a mutation keeps its error and reports what Gmail may have applied:

- after a timeout or transport failure once the request may have been sent, a
  redirect, which the Broker never follows, or a 5xx response (both
  `upstream_failed`), or the 30-second operation deadline:
  `mutationStatus: "unknown"`, `retrySafe: false`;
- when Gmail answered with a success status but its response could not be read
  or parsed: `mutationStatus: "applied_unverified"`, `retrySafe: false`,
  `verificationStage: "mutation_response"` and `safeLocators` naming the
  `message` or `thread` ID from the request.

A 400, 401, 403 or 404 rejection and throttling carry no receipt.
A mutation the Broker proves was never sent, because no connection to Gmail was
established, instead fails with its ordinary `upstream_connection_failed` or
`upstream_timeout`, the message `Gmail request failed` and a result of
`mutationStatus: "not_applied"`, `retrySafe: true`: nothing changed, and it can
be repeated.
Google HTTP 429 and the 403 rate-limit reasons `rateLimitExceeded`,
`userRateLimitExceeded` and `dailyLimitExceeded` map to `upstream_rate_limited`,
separately from permission denial, with the bounded `Retry-After` wait when Google
sends one. A Google token refresh throttled with HTTP 429, and the cooldown that
follows it, report the same code. Google 5xx and `server_error` token responses are
failures, not throttling: the cooldown after one reports `upstream_connection_failed`
with `retryAfterSeconds` and `retryAt`.
See [http-api.md](http-api.md#reason-code-table).
Audit records include operation/outcome and opaque message or thread IDs for direct reads and mutations, including failures; they never include bodies, headers, subjects or search text.

## Other agent interfaces

The descriptor drives caller-filtered catalog, OpenAPI, JSON send schema, and both
stdio and HTTP MCP. `readOnly` classifies the five reads for grant selection.
Local CLI and stdio MCP can save both read and mutation JSON responses. A file
save failure after a successful mutation is reported separately and never causes
an automatic replay.

```bash
agent-access invoke gmail.thread.archive --input-json '{"id":"THREAD_ID"}'
agent-access send --request-json '{"version":"agent-access.send.v1","kind":"invoke","service":"gmail","action":"message.search","inputs":{"query":"in:trash","includeSpamTrash":true,"maxResults":10}}'
```

Direct HTTP uses `POST /v1/invoke/gmail/thread.restore` with
`{"inputs":{"id":"THREAD_ID"}}` and the normal Broker identity/context headers.
Discover MCP tool names and schemas through `tools/list`; OAuth credentials are
never MCP arguments. Existing grants apply equally on every surface.

## Validation and live smoke

The bounded `requestAudit` records supplied message/thread IDs, the Gmail search
query, requested result limit and spam/trash flag. Page tokens record presence
only; omitted controls remain absent even when execution uses defaults. The
argument-free account and label reads have no request snapshot. Returned mail
snippets, subjects, headers, bodies and account data are not request inputs and
are never added to this capture.

Automated tests use a local Google-shaped server with production dialect logic,
managed login, consent callback, encrypted connections, refresh and real Gmail routes.
Test endpoint injection is available only in test support; production configuration
cannot change Google endpoints.

For a live smoke, configure your own client and connect in the browser. Read the
account, labels and a small search page; read one designated disposable message and
thread. Archive, Trash, search Trash, and restore only that designated mail. Verify
resulting labels in Gmail. Repeat a read after token expiry and after Broker restart,
then check disconnect blocks access. Live smoke needs the owner's browser consent
and designated test mail; automated success does not substitute for this test.
