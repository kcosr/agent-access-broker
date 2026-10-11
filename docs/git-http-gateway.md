# Git HTTP Gateway

For opt-in proxy-attested authentication using a trusted identity fingerprint,
including administrator identity inventory and token-free Git access, see
[managed workspace identity](managed-identity.md). Explicit Broker access tokens
retain their existing authorization boundaries.
Normal Basic Broker-token requests can use the same gateway without trusted-caller headers.
Any context or fingerprint header requires a valid authorized caller credential,
even if token-free Git access is disabled. Header-free direct requests use the
configured conservative default or fail when context is required. Asserted callers
must supply context; fixed callers receive their configured context. A caller
credential alone does not replace a Git user's authentication. See
[trusted callers](trusted-callers.md) for the shared admission contract.
`X-Agent-Access-User` is rejected on Git; username assertions are HTTP MCP only.
The shared identity-access gate controls fingerprint Git access. Inventory removal
disables the fingerprint, while shared pause also blocks the human's username MCP
bindings. Direct-only caller secrets are invalid in the dedicated carrier here.

This document owns `[gateways]` entries with `kind = "git_http"`. Git HTTP
gateways are host-matched protocol surfaces on the gateway listener and are
used by ordinary Git clients. Shared provider concepts are in
[providers.md](providers.md); CLI credential and normal Git usage examples are in
[cli.md](cli.md).

Each `gateways.<name>` entry with `kind = "git_http"` becomes a host-matched
gateway service whose service name is the config key. It is not invoked through
`POST /v1/invoke` and there is no `agent-access git ...` wrapper. Users run
normal Git commands against a remote URL whose host matches one of the gateway's
`broker_hosts`, and the broker classifies the Git smart HTTP request into the
same service/action/scope policy model used by providers.

## Access surfaces and examples

Git HTTP gateways are used through ordinary Git smart HTTP clients, not
`agent-access invoke`, JSON `send`, or direct `/v1/invoke` HTTP calls. The broker
still advertises gateway actions in discovery so agents and operators can see
policy-grantable `repo.fetch` and `repo.push` actions.

Gateway discovery and credential verification use the CLI. Gateway services
appear in `services` and `actions` output, but they are intentionally omitted
from invoke/send runtime specs because they are not `/v1/invoke` actions.

```bash
agent-access services list
agent-access actions list --service gitlab_git
agent-access --url http://127.0.0.1:8787 credentials verify gitlab_git default --repository team/project
```

Git clients point at the gateway listener host. When prompted for HTTP Basic
credentials, use the configured username (`agent-access` by default) and an
`agent_invoke` broker token as the password:

```bash
git ls-remote https://git.example.com/team/project.git
git clone https://git.example.com/team/project
git -C project fetch origin
git -C project push origin HEAD:refs/heads/work/docs
```

Clone and remote URLs may include or omit the trailing `.git`. Both forms use
the same repository authorization and work for clone, fetch, and push. The broker
adds `.git` to the upstream repository path when needed; no configuration option
or Git `http.followRedirects` setting is required.

For normal unattended use, configure the native Agent Access credential helper
for the exact gateway host:

```bash
agent-access auth token set --token-stdin
git config --global --replace-all \
  credential.https://<brokered-git-host>.helper ""
git config --global --add \
  credential.https://<brokered-git-host>.helper \
  "!agent-access auth git-credential"
```

Replace `<brokered-git-host>` with the exact gateway hostname before running
these commands.

This is equivalent to:

```gitconfig
[credential "https://<brokered-git-host>"]
	helper =
	helper = "!agent-access auth git-credential"
```

The empty value resets helpers inherited for that URL. The Agent Access CLI then
returns username `agent-access` and resolves the password from its normal broker
identity-token sources. Git does not store a separate copy, so replacing the
token through `agent-access auth token set --token-stdin` takes effect on the
next Git command. Git requests to `store` or `erase` are consumed but do not
create, revoke, or clear Agent Access tokens; use `agent-access auth token clear`
to clear the configured token file. Because the helper's username is fixed, the
gateway must use `basic_broker_token_username = "agent-access"` (the default).

Never install this as a global unscoped helper:

```gitconfig
[credential]
	helper = "!agent-access auth git-credential"
```

The helper intentionally has no deployment hostname compiled into it. URL
scoping is therefore Git's boundary that prevents the broker token from being
offered to another HTTPS host. The helper still requires Git to supply nonempty
`protocol` and `host` fields so malformed requests fail closed.

The gateway listener is its own trusted-ingress surface. Its edge proxy must be a
[named trusted caller](trusted-callers.md). An asserted caller sends its private
`X-Agent-Access-Caller-Authorization` credential and replaces client context values
with one approved `X-Agent-Access-Context`. A fixed caller sends its credential and
omits the context header. Configure this separately from public `/v1` ingress;
that ingress does not protect the gateway port. The broker resolves
context before Basic-token lookup and policy planning, consumes the header
locally, and never forwards it to the upstream Git server. A token must allow
the resolved context as well as the gateway service, and the matching grant
must include that context.

An immutable token boundary may further limit the gateway to `repo.fetch` or
`repo.push` and to resource/group reference selections. The broker checks
the action before consuming a request body and checks the canonical repository
before opening the upstream connection. Current policy must
still independently authorize the operation; the token selector never creates
a grant or selects credentials.

## Actions and authentication

The gateway advertises these actions when enabled in `[gateways.<name>.git]`:

| Action | Required scope type | Enabled by |
| --- | --- | --- |
| `repo.fetch` | `repository` | `allow_fetch = true` |
| `repo.push` | `repository` | `allow_push = true` |

Git clients authenticate with HTTP Basic auth. The username must equal
`basic_broker_token_username` (default `agent-access`), and the password must be
a broker `agent_invoke` token. That broker token identifies the caller and is
checked before any upstream credential is selected. Discovery through the
public listener is context-specific too, so use the public trusted entrypoint
for the same execution context when checking whether `repo.fetch` or
`repo.push` is visible.

Every gateway response, including denials and upstream failures, carries
`Cache-Control: private, no-store` and `Pragma: no-cache`. The broker discards
upstream cache directives and `Expires`: repository discovery and other Git
responses must reach the broker for each caller's authorization decision.

## Paths, queries, and scopes

Supported Git smart HTTP routes are listed below. Each also accepts the
repository path without its trailing `.git`:

| Git request | Broker action |
| --- | --- |
| `GET /<repo>.git/info/refs?service=git-upload-pack` | `repo.fetch` |
| `POST /<repo>.git/git-upload-pack` | `repo.fetch` |
| `GET /<repo>.git/info/refs?service=git-receive-pack` | `repo.push` |
| `POST /<repo>.git/git-receive-pack` | `repo.push` |

The inbound `<repo>` path is decoded segment by segment, any trailing `.git` is
removed for policy matching, and the canonical repository fact is the
slash-joined path such as `team/project`. Encoded slash, encoded backslash, control
characters, dot segments, literal `%`, ambiguous interior `.git` repository
segments, malformed encoding, and invalid repository selector shapes are rejected
before upstream forwarding. Safe encoded characters are canonicalized before the
upstream URL is built, and discovery queries are reconstructed as exactly
`service=git-upload-pack` or `service=git-receive-pack`.

Upstream repository paths always end in `.git`, for discovery GETs and both
upload-pack and receive-pack POSTs. Any path prefix from `upstream_base_url` is
preserved: with `https://gitlab.example.com/git` as the base, either
`/team/project/info/refs` or `/team/project.git/info/refs` forwards to
`https://gitlab.example.com/git/team/project.git/info/refs`. This is the canonical
upstream format for every `git_http` gateway; the upstream must serve `.git`
smart HTTP endpoints. Redirects remain disabled (`redirect_policy = "none"`).

The gateway authorizes the canonical `repository` target through the same
`git_repository` resource entries used by GitLab REST. Exact selectors match one
path, namespace selectors match complete path segments including nested
subgroups, and all selectors match every repository. A selector for
`engineering/platform` covers `engineering/platform/api` but not
`engineering/platform-tools/api`. Group exclusions and token references use the
shared policy rules described in [resources.md](resources.md).

## Push validation

For receive-pack POSTs, the broker parses the command prefix before resolving or
sending upstream credentials. It rejects malformed pkt-lines, unsupported
capabilities, tag updates, delete-ref updates when `deny_delete_refs = true`
(the default), and configured `deny_ref_patterns`. The broker buffers only the
receive-pack command prefix; after authorization, the remaining pack body is
streamed upstream with the configured request-body cap and idle timeout.

Shallow clones may send leading `shallow` declarations before ref updates. The
broker validates their nonzero object IDs, includes them in the same prefix
limit, and forwards their original bytes unchanged. Malformed declarations,
declarations after a ref update, and prefixes without ref updates are rejected.

## Request representation headers

Upload-pack POSTs may carry a single `Content-Encoding: gzip` header. The broker
forwards that header upstream as canonical `gzip` and treats the request body as
opaque Git protocol bytes; it does not decompress, inspect, or rewrite the
upload-pack body. The configured request-body cap applies to the transmitted
compressed bytes, and any upstream decoded-size limits remain the upstream
server's responsibility.

Discovery GET requests and receive-pack POSTs reject `Content-Encoding` after
the gateway request is authenticated and action-scoped, but before credentials
are resolved. Receive-pack compression is not supported because push bodies must
be parsed for ref and capability policy before upstream credentials can be used.
Any gateway request with a `Trailer` header is rejected before forwarding.

## Credentials, limits, and audit

Credential mode comes from the matched grant, as with providers. A `service`
gateway credential is shared for the gateway service. A `per_user` gateway
credential is selected from the calling principal's managed credentials; the
self-service credential verifier requires a repository that the principal can
fetch and uses `streaming_idle_timeout_ms` for stalled upstream discovery
headers or body reads.

Gateway responses are raw Git smart HTTP streams, not broker JSON envelopes.
That protocol passthrough behavior is unchanged by the Jira, Confluence, and
GitLab REST validation-message policy: upstream Git HTTP responses remain
bounded protocol responses and are not parsed into sanitized REST validation
messages. Broker-generated classifier and policy denials remain the plain-text
gateway errors described in this document. An upstream HTTP 429 is passed through
with its status; the Broker forwards the upstream `Retry-After` only as bounded
whole seconds (at most one day) and drops invalid values. The request's
terminal audit record reports `decision = "error"`,
`reasonCode = "upstream_rate_limited"`, `upstreamStatus = 429`, and
`providerAudit.gateway.phase = "failed"` rather than a completed allow.
Self-service credential verification that the upstream throttles returns
`upstream_rate_limited` with the same bounded wait.

Request and response byte caps inherit the global limits unless overridden on
the gateway. Inbound pack uploads have a total body deadline of
`limits.request_body_timeout_ms` (default five minutes), measured from admission;
continued progress does not extend it. Both uploads and downloads remain bounded
by `streaming_idle_timeout_ms` for stalled request uploads, upstream response
header waits, and response body streaming, plus byte caps, rate limits, and
concurrency limits. Downloads have no total transfer deadline.

`git-upload-pack` and `git-receive-pack` POSTs are service invocations: each
POST is counted once against the caller's per-principal limit for the gateway's
service name (for example `gitlab_git`), after gateway authentication and
before token caveats, policy, credential selection, or any upstream request.
Only ref discovery (`GET .../info/refs`) is not counted. Every pack POST
counts, so one Git command usually costs more than one request:

- A protocol v2 fetch or clone (the default for current Git) sends a
  `command=ls-refs` POST, then one `command=fetch` POST per negotiation round.
  A protocol v2 `git ls-remote` sends the `ls-refs` POST.
- A protocol v0 or v1 fetch sends one upload-pack POST per negotiation round;
  its `git ls-remote` uses only discovery and is not counted.
- A push sends its receive-pack POST, preceded by a small probe POST when the
  request is larger than the client's `http.postBuffer`.

Size gateway limits for several POSTs per Git command. The built-in default
(100 per `1m`) leaves room; when lowering it, allow at least three or four
POSTs for each fetch, clone, or push expected in one window, plus more for
repositories whose fetches need several negotiation rounds. A limit of 1 makes
protocol v2 fetches impossible: the `ls-refs` POST spends the window before
the fetch POST. Set a gateway-specific value with
`[limits.invocations.services.<gateway>]`; see
[configuration](configuration.md#service-invocation-limits). A limited pack
POST returns HTTP 429 with `Retry-After` in whole seconds,
`X-Agent-Access-Reason-Code: rate_limited`, and a plain-text body such as
`Rate limit reached for service "gitlab_git": 30 requests per 1m. Retry after
12s (at 2026-09-25T14:03:12Z). The request was not executed.` The rejection is
audited with the resolved principal, the real gateway action, and
`providerAudit.rateLimit`.

Credentialed gateway forwarding is audit-gated with
`providerAudit.gateway.phase = "started"` before upstream credentials are sent,
followed by a terminal audit record containing upstream status, duration, and
response byte metadata. Classifier denials before a gateway action is known use
the synthetic non-grantable action `gateway.classify`.

## Deployment validation

Validate discovery and fetch against an authorized disposable repository through
the actual gateway ingress, using its URL-scoped credential helper. Check denial
for another repository and, when configured, a token or context outside its grant.
An authorized push test needs a throwaway branch: verify its ref changes, the
configured protected/delete/tag restrictions and terminal audit outcome, then
remove the branch through an authorized upstream cleanup path.

Exercise the installed proxy/TLS chain and invocation limits with ordinary Git,
since one command can issue multiple pack requests. A REST provider smoke cannot
validate this dedicated listener. Record whether fetch, push, trusted-caller and
token-free identity paths were tested; enable only the intended gateway actions.
