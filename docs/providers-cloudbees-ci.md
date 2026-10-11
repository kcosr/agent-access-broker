# CloudBees CI provider

The built-in `cloudbees_ci` provider calls the Jenkins REST API on configured
CloudBees CI controllers. An operations center manages controllers; a controller
holds folders, jobs, queues, builds, and archived artifacts. Configure each
controller once under a stable alias. Agents address a job by alias and full
job name, or pass a Jenkins job or build URL that the Broker maps onto a
configured controller without fetching it.

## Configuration

```toml
[providers.cloudbees_ci]
allowed_upstream_hosts = ["https://ci.example.com/team-ci/**"]
max_log_scan_bytes = 16777216 # 16 MiB per log-read request

[providers.cloudbees_ci.controllers.team-ci]
base_url = "https://ci.example.com/team-ci/"
# web_base_url = "https://ci-public.example.com/team-ci/"

[credentials.service.cloudbees_ci]
type = "basic_api_token"
username_ref = "env:CLOUDBEES_CI_USERNAME"
token_ref = "env:CLOUDBEES_CI_API_TOKEN"
```

Both controller URLs must be normalized absolute URLs ending in `/`; their paths
may be controller context paths. `base_url` is the Broker-reachable API root.
Optional `web_base_url` identifies the public Jenkins root URL when it differs
from the API endpoint. It validates returned links and queue `Location` headers
and is accepted as a root for `url` inputs; the Broker never sends requests to
that URL and omits rejected links from results.
The allowlist must cover every job, build, queue, and artifact API path used
under it. If artifact storage redirects to a different HTTPS host, that
destination must also be explicitly allowlisted. The Broker sends Basic
authentication and correlation headers only to the configured controller
artifact path. Same-origin redirects to other paths are rejected. The
controller's resolved egress proxy is reused for artifact storage redirects;
its `NO_PROXY` decision also governs those hops.
The usual broker egress proxy rules apply. A CloudBees service account or user
API token authenticates with HTTP Basic. Upstream role permissions still apply.
The managed per-user profile is `cloudbees-ci-api-token`.

CloudBees actions do not perform pre-authorization metadata lookup and do not
require a `credentials.lookup.cloudbees_ci` credential. The Broker resolves the
controller/job scope from the action inputs, authorizes it, and uses the selected
service or per-user credential for execution.

The global [`network.outbound_tls`](configuration.md#networkoutbound_tls) policy
applies to both controller API requests and artifact downloads, including
allowlisted storage redirects. The default trusts the Broker process's native
system CA store; use `system_plus_custom` to add an internal CA bundle while
retaining public system roots.

## Resource permissions

Each action resolves a single `job` scope of resource type
`cloudbees_ci_job`. The value is `controller-alias/full/job/name`; for
example, `team-ci/payments/build-api`. Input fields remain separate:
`{"controller":"team-ci","job":"payments/build-api"}`.

| Selector | Example | Coverage |
| --- | --- | --- |
| `exact` | `team-ci/payments/build-api` | One job. |
| `namespace` | `team-ci/payments` | Every descendant job in that folder. |
| `namespace` | `team-ci` | Every job on that controller. |
| `all` | no value | All jobs on configured controllers. |

Namespace matching is strictly below the selected path on complete
slash-separated segments. Thus `namespace team-ci/payments` covers
`team-ci/payments/build-api`, but does not cover the folder item
`team-ci/payments` itself. It has no glob syntax. Broad selectors include
future jobs. The broker does not inventory CI.

Resource discovery (`resources_list`) shows the action inputs for each
selector, so callers need not split resource values themselves:

| Selector | Discovery `inputs` |
| --- | --- |
| `exact team-ci/payments/build-api` | `{"controller":"team-ci","job":"payments/build-api"}` |
| `namespace team-ci` or `namespace team-ci/payments` | `{"controller":"team-ci"}` |
| `all` | none; coverage names each configured controller alias the caller's grant reaches |

Registered exact entries appear as resources. Namespace and `all` grants appear
as caller coverage, with `all` reported per reachable controller alias. Neither
lists jobs. See [resources](resources.md) for the coverage fields.

The `job` input is the Jenkins `fullName`, not its display name. A folder path
uses `/` between item names. A literal `%` in a multibranch job name is valid:
`feature%2Ffoo` is sent as URL path segment `feature%252Ffoo` and checked
against the returned `fullName`. Empty or traversal segments, forbidden Jenkins
name characters, and edge whitespace are rejected. A controller alias uses the
broker service-name grammar (`^[a-z][a-z0-9_-]{0,62}$`).

## Locating jobs and builds

Every action takes exactly one locator: `url`, or `controller` and `job`.
`controller` is the first segment of a `cloudbees_ci_job` resource value and
`job` is the rest; `job` never repeats the alias. Folders and multibranch
projects contain jobs: address a job inside them, such as `payments/build-api`
or a branch `payments/build-api/main`.

`url` accepts a classic Jenkins job or build URL, for example
`https://ci.example.com/team-ci/job/payments/job/build-api/42/console`. The
Broker parses it locally and never requests it:

- The scheme, host, port, and leading path segments must match a configured
  controller's `base_url` or `web_base_url`. The longest matching root wins;
  two aliases with the same matching root fail closed.
- After the root, `view/<name>` pairs are skipped and one or more
  `job/<name>` pairs form the full job name. Each name is percent-decoded once,
  so `job/feature%252Ffoo` is the item `feature%2Ffoo`. A decoded `/`,
  malformed encoding, or an invalid item name is rejected.
- The next segment, if any, may be a build number or a Jenkins permalink
  (`lastBuild`, `lastCompletedBuild`, `lastFailedBuild`, `lastSuccessfulBuild`,
  `lastStableBuild`, `lastUnstableBuild`, `lastUnsuccessfulBuild`). Other job
  pages are ignored, as are later segments such as `console`, `testReport`,
  `artifact/...`, or `display/redirect`, the query, and the fragment. Matrix
  configuration segments (`label=linux`) are rejected.
- Blue Ocean (`/blue/...`) and queue item (`/queue/item/N/`) URLs, URLs
  without a `job/` segment, and URLs under no configured root are rejected.
  Errors never list configured hosts or aliases.

The derived controller and job are authorized exactly like explicit inputs and
results echo them, so later calls can use the canonical fields. Job-level
actions (`job.view`, `build.list`, `build.trigger`) ignore a build in the URL.
`queue.view` takes `url` plus `queueId`.

Build-level actions take the build from exactly one of `buildNumber`,
`buildSelector`, or a build URL. `buildSelector` is one of the permalinks
above. After authorization the provider resolves it with one projected read,
`job/api/json?tree=fullName,_class,builds[number]{0,0},<selector>[number]`,
which also confirms the job's `fullName`. A job without that build returns
`resource_not_found` (`CloudBees CI job has no lastFailedBuild`, with
`result.buildSelector`). Results echo the numeric `buildNumber` (alongside
`number` in `build.view`) and, when a selector was used, `buildSelector`; audit
records both. Log cursors bind to the numeric build: continue a
`build.log.read` page with the returned `buildNumber`. A `cursor` with
`buildSelector` or a permalink URL is rejected.

## Actions

Every action takes `url` or `controller` and `job` as described above. In the
table, *build* means one of `buildNumber` (a positive integer up to
4294967295), `buildSelector`, or a build URL. Queue IDs are positive signed
64-bit integers. Additional inputs are:

| Action | Additional inputs | Result |
| --- | --- | --- |
| `job.view` | none | Job kind, details, buildability, and parameter names/types; never child inventory or parameter defaults. |
| `build.list` | `maxResults` (1–50, default 20) | Recent build numbers, results, timing, and validated web URLs when available. |
| `build.view` | build | One build's `number`/`buildNumber`, state, timing, and validated web URL when available. |
| `build.log.read` | build, `mode` (`head`, `tail`, `search`; default `tail`), `maxBytes` (1024–65536; default 16384), optional `cursor`; search requires `query`, optional `maxMatches` (1–100; default 20) | Bounded text or literal matches, source ranges, scan coverage, and opaque continuation. |
| `build.log.download` | build | Full console text currently available, streamed as a file. |
| `build.pipeline.view` | build | Pipeline stages, status, and timing. |
| `build.pipeline.node.view` | build, `nodeId` (positive integer string) | Stage/step details and flow nodes. |
| `build.pipeline.node.log.read` | build, `nodeId` | Bounded Pipeline node log JSON, including upstream completeness indicators. |
| `build.pending-inputs.list` | build | Pending Pipeline input prompts; no proceed or abort operation. |
| `build.tests.details` | build, `maxResults` (1–100, default 20) | Detailed test cases, failures, stack traces, captured output, and truncation status. |
| `build.tests.download` | build | Detailed projected Jenkins test report streamed as JSON. |
| `build.tests.view` | build | Test counts/duration (fields absent upstream are `null`) or `reportAvailable:false`; no test case names or messages. |
| `build.artifact.list` | build | `{controller,job,buildNumber,artifacts:[{artifactPath,fileName}]}` for up to 1000 archived artifacts. |
| `build.artifact.download` | build, `artifactPath` | Raw bytes plus result metadata `{controller,job,buildNumber,artifactPath,fileName,contentType,size}`; `size` may be null. |
| `queue.view` | `queueId` | Queue state only if the queue task identifies the authorized job. |
| `build.trigger` | none | Requests a buildable, non-parameterized job; returns a queue ID and validated URL when supplied. |

Core Jenkins JSON reads request explicit `tree` projections; Pipeline REST
reads use fixed endpoints and project the returned fields. Upstream JSON responses apply
a 1 MiB response-size cap; console text has the separate scan budget below. Job views never include `jobs[]` or parameter defaults;
build views omit parameter values and causes. A folder or multibranch parent
can be viewed with an exact grant, but its children are not disclosed. Queue
reads require the returned queue ID and task `fullName` to match the requested
ID and authorized job. A missing or mismatched queue item returns the same
`scope_unresolved` error. No job inventory or search action is available.
An artifact list above 1000 entries fails rather than silently truncating.
Downloads from such a build also fail because complete list membership cannot
be verified.
Artifact downloads require their own action grant and an exact path returned by
`build.artifact.list`. The provider checks that the requested path appears in
the current archived-artifact list before it downloads and does not expose
arbitrary controller URLs. The global `limits.max_download_bytes` caps the
stream, including when the upstream response omits its length. Its default is
100 MiB (104,857,600 bytes); operators can change it under `[limits]` in the
Broker TOML.
When Content-Length is present, the Broker also verifies the final byte count.
An over-cap declared or streamed size returns `attachment_size_denied`.
The CLI and stdio MCP accept a null size and replace the destination only after
the complete broker stream succeeds. They add no separate download size cap.
Download response headers use the Broker request timeout, and each body chunk
uses its streaming idle timeout; a progressing transfer has no total deadline.

Console and test report downloads use the same streaming limits and atomic
local destination handling as artifacts. Console text comes from Jenkins
`consoleText`, not archived artifacts; it contains the output available when
read and does not provide a follow mode. Test report downloads use a fixed
projection of suites and cases from `testReport/api/json`; they are JSON,
not original JUnit XML or an archive. Before opening the report stream, the
broker requests `tree=suites{0,0}` to check that the endpoint exposes the
supported JUnit-style shape. Use `build.tests.view` for Maven module-set and
matrix aggregate summaries. Summary fields absent upstream are `null`,
including `passCount` and `duration` on aggregate reports. Their child
module/configuration paths are not supported by this provider. A missing `suites` field returns
`response_format_unsupported` with a hint to use the summary action
`build.tests.view`; a malformed `suites` value is `upstream_protocol_failed`.
Both are rejected before opening the download stream.
Console and report downloads reject redirects.

Pipeline stage, node, node-log, and pending-input reads require the controller's
Pipeline REST API plugin. Node logs retain the plugin's own truncation and
completeness semantics and reject text over 65536 bytes with
`cloudbees_ci_log_chunk_exceeded`. They are not
full-console downloads. Stage/block nodes often have no log of their own. Use
`build.pipeline.node.view` to obtain `stageFlowNodes`, then read a step node's
log. A matching node with no log returns empty text and its completeness
indicators; missing text with a nonempty length is reported as unavailable.

Detailed test previews select `FAILED` and `REGRESSION` cases first, then fill
remaining slots in report order. `report.returnedCount` and
`report.returnedFailedCount` count the returned cases and failures;
`report.truncated` indicates omitted cases. `maxResults` bounds returned cases,
not the upstream report size. An oversized preview returns
`attachment_size_denied` with `result.downloadAction:"build.tests.download"`. Both actions require an available
JUnit-style report with top-level `suites`. Detailed reports and logs may
contain secrets; grant their actions separately from summary reads.

Historical build reads on a disabled job remain available when its controller
serves them. Only `build.trigger` requires `buildable:true`.

### Errors

Input mistakes are rejected before authorization with `input_invalid`.
`result.inputCategory` names the problem and `result.field`, when present,
names the input:

| `inputCategory` | Meaning |
| --- | --- |
| `unknown_field` | An input the action does not accept; the message lists accepted inputs. |
| `locator_missing` / `locator_conflict` | Neither or both of `url` and `controller`/`job`. |
| `controller_not_configured` | Not a configured alias; use resource discovery or a job URL. |
| `controller_not_alias` | A host name, URL, or resource value passed as `controller`. |
| `job_is_url` | A URL passed as `job`. |
| `job_invalid` | Empty, leading, trailing, or repeated `/`, edge whitespace, traversal segments, or characters Jenkins item names cannot use. |
| `url_invalid` / `url_not_configured` / `url_ambiguous` / `url_no_job` / `url_blue_ocean` / `url_queue_item` | The URL rules above. |
| `build_missing` / `build_conflict` | No build, or more than one of `buildNumber`, `buildSelector`, and a URL build. |
| `field_missing` / `value_invalid` | A missing required field, or a wrong type or out-of-range value such as a string `buildNumber` or integer `nodeId`. |
| `option_conflict` | Log read options that cannot be combined, including `cursor` with a selector. |
| `job_is_container` | After authorization: the job is a folder or multibranch project with no builds; `result.kind` carries its Jenkins class. |

`job_is_container` is detected by the `build.list` and selector reads, and for
a numeric build read that the controller answers with 404 by one further
`api/json?tree=fullName,_class,builds[number]{0,0}` read of the authorized
job. Other upstream 404s keep `resource_not_found`; when `job` begins with
`<controller>/`, the message adds that `job` must not repeat the alias, and when
it has the `job/a/job/b` shape of a Jenkins URL path, the message suggests the
full name `a/b` or the `url` input. That shape is not rejected up front because
a folder can be named `job`.

The provider rejects redirects for JSON reads or build triggers. Artifact
downloads can follow up to three explicitly allowlisted redirects, with
controller credentials omitted off the configured controller base. It maps
upstream 401/403 to
`upstream_unauthorized`/`upstream_forbidden` and a controller HTTP 429 to
`upstream_rate_limited` with the bounded `Retry-After` wait when the controller
sends one (see [http-api.md](http-api.md#reason-code-table)); request and
response-body timeouts
return `upstream_timeout`, while other connection failures return
`upstream_connection_failed`. Redirects on JSON actions,
malformed JSON, unexpected content types, and oversized JSON responses are
`upstream_protocol_failed`, except the detailed-test preview overflow described
above. Job identity mismatches fail as `scope_unresolved`.

The build trigger does not accept parameters or automatically retry after an
uncertain POST. A successful POST without a usable queue `Location` returns
`mutationStatus:"applied_unverified"`, `retrySafe:false`,
`verificationStage:"mutation_response"`, and
`safeLocators:{"controller":...,"job":...}`, which can be passed back as
inputs. When the POST may have reached the controller but no response
confirmed it (a timeout or connection failure after sending, or a 5xx), the
action fails with `mutation_verification_failed` (HTTP 409) carrying the same
receipt fields instead of a retryable upstream error. A connection that was
never established, a 401/403/404/409/429 response, or a redirect keeps its
ordinary error. Even a valid queue ID may identify an already queued item: it
does not prove a new build was created. Check `job.view` (`inQueue`,
`lastBuild`), `build.list`, or `queue.view` before considering another trigger.

### Bounded console reads

`build.log.read` reads the plain `consoleText` endpoint. Use `mode: "head"` for
the beginning, `"tail"` (the default) for the end, or `"search"` with a nonempty
literal `query` of at most 256 UTF-8 bytes. Search is case-sensitive and returns
non-overlapping matches in source order, with at most 256 source bytes of
context on either side. Excerpts may split lines; even newline-free logs use
bounded memory. `maxMatches` controls search result count only.

`maxBytes` limits returned UTF-8 text, including replacement characters, across
all excerpts. It defaults to 16 KiB and accepts 1–64 KiB. Source ranges refer to
the plain console response before decoding; they are not Jenkins
progressive-log offsets.

Head/search can return `nextCursor`. Pass it as `cursor` with the same mode,
query, output limits, job, and build. Cursors expire after 15 minutes and are
bound to the caller, credential mode, execution context, and provider
configuration. Each page is authorized again and rereads its consumed prefix
to verify that the log has not changed. Appending text is supported; rewriting
or truncating the consumed prefix invalidates the cursor. Without a configured
stable signing key, restart or reload also invalidates cursors. Tail has no cursor.
Do not derive cursor positions from displayed text or decode/edit tokens.
Cursor prefix fingerprints are keyed and bound to the request so a leaked cursor
cannot be used to test guesses of log content offline. A broker signing-key failure returns
`cursor_signing_unavailable` (HTTP 503); restarting the read cannot repair an
unavailable broker key.

The provider's `max_log_scan_bytes` defaults to 16 MiB and must be positive and
no larger than `limits.max_upstream_response_bytes`. It counts consumed source
bytes, including replayed prefixes and lookahead. Each read has a total deadline
of 20 seconds or the configured request timeout, whichever is shorter; streaming
idle limits also apply. Increasing `maxBytes` does not increase the scan budget.
Stateless paging rereads earlier bytes, so it cannot traverse beyond that budget.

Results include `sourceStart`/`sourceEnd` for the returned head/tail text or
searched range. Search entries also identify `matchStart`/`matchEnd`, excerpt
source ranges, and `contextBeforeClipped`/`contextAfterClipped`.
Inspect `scannedBytes`, `reachedEnd`, `stopReason`, and `nextCursor`. An output or
match limit may allow another page. A scan limit means coverage is incomplete:
zero search matches does not prove the whole log has no match. A tail request
that cannot reach EOF fails with `cloudbees_ci_log_scan_exceeded` (HTTP 413)
instead of returning the end of a scanned prefix. An unknown-length response
that exactly fills the scan budget is conservatively incomplete when EOF has
not been observed.
Use a head excerpt, an applicable Pipeline step log, an operator-adjusted scan
budget, or a separately authorized download. Repeating the same request or
increasing its output budget does not resolve a scan limit.

`reachedEnd` means EOF of this HTTP response, not build completion or an immutable
snapshot. Incomplete trailing UTF-8 bytes are withheld and reported as
`pendingUtf8Bytes` with `stopReason: "pending_text"`; do not automatically loop on
that result. A continuation is issued only if new valid content was consumed.
Definitively malformed interior bytes are replaced for display. A permanently
incomplete final sequence remains pending; a raw download preserves the bytes.

The same tool works through HTTP and stdio MCP, invoke, and JSON send. Normal
serialized-response limits still apply in addition to the text budget. Console
logs can contain secrets, so grant `build.log.read` and `build.log.download`
separately. Artifacts may also contain sensitive data; grant
`build.artifact.download` separately from
`build.artifact.list`. No script execution, job editing, replay, cancellation,
or controller administration is exposed.

## CLI

```bash
agent-access cloudbees-ci build log-download team-ci payments/build-api 42 --output ./build-42.log
agent-access cloudbees-ci build pipeline view team-ci payments/build-api 42
agent-access cloudbees-ci build pipeline node team-ci payments/build-api 42 --node-id 7
agent-access cloudbees-ci build pipeline log team-ci payments/build-api 42 --node-id 7
agent-access cloudbees-ci build pending-inputs team-ci payments/build-api 42
agent-access cloudbees-ci build tests-details team-ci payments/build-api 42 --max-results 50
agent-access cloudbees-ci build tests-download team-ci payments/build-api 42 --output ./tests-42.json
agent-access cloudbees-ci job view team-ci payments/build-api
agent-access cloudbees-ci build list team-ci payments/build-api --max-results 10
agent-access cloudbees-ci build view team-ci payments/build-api 42
agent-access cloudbees-ci build log team-ci payments/build-api 42 --mode head --max-bytes 8192
agent-access cloudbees-ci build log team-ci payments/build-api 42 --mode tail
agent-access cloudbees-ci build log team-ci payments/build-api 42 --mode search --query ERROR --max-matches 20
agent-access cloudbees-ci build tests team-ci payments/build-api 42
agent-access cloudbees-ci build artifact list team-ci payments/build-api 42
agent-access cloudbees-ci build artifact download team-ci payments/build-api 42 --artifact-path reports/results.zip --output ./results.zip
agent-access cloudbees-ci build trigger team-ci payments/build-api
agent-access cloudbees-ci queue view team-ci payments/build-api --queue-id 51
agent-access cloudbees-ci build list --job-url https://ci.example.com/team-ci/job/payments/job/build-api/
agent-access cloudbees-ci build log --job-url https://ci.example.com/team-ci/job/payments/job/build-api/ --build-selector lastFailedBuild
agent-access cloudbees-ci build log --job-url https://ci.example.com/team-ci/job/payments/job/build-api/42/console --mode search --query ERROR
agent-access cloudbees-ci build tests-details team-ci payments/build-api --build-selector lastFailedBuild
```

`--job-url` sends the `url` input instead of `CONTROLLER` and `JOB`; it is separate
from the global `--url` broker option. With `--job-url`, give the build in the URL
or with `--build-selector`. `--build-selector` replaces the build number.

JSON actions are available through `agent-access invoke`, JSON `send`, HTTP
invoke, and MCP discovery. Raw artifact, console log, and test-report bytes use the typed CLI download
command, a JSON `send` download sink, direct HTTP download, or local stdio MCP.
HTTP MCP `tools/list` includes JSON reads but excludes raw downloads;
its discovery helper can still describe the download action. For example:

```bash
agent-access invoke cloudbees_ci.job.view --input-json '{"controller":"team-ci","job":"payments/build-api"}'
agent-access invoke cloudbees_ci.build.log.read --input-json '{"url":"https://ci.example.com/team-ci/job/payments/job/build-api/42/console","mode":"tail"}'
agent-access invoke cloudbees_ci.build.tests.details --input-json '{"controller":"team-ci","job":"payments/build-api","buildSelector":"lastFailedBuild"}'
```

Each action's catalog `documentation` repeats the locator, URL, build
selector, and cursor rules for agents.

CloudBees CI reference: [service-account REST access](https://docs.cloudbees.com/docs/cloudbees-ci/latest/secure/service-accounts-rest-api),
[Jenkins remote API](https://www.jenkins.io/doc/book/using/remote-access-api/),
[Pipeline REST API](https://plugins.jenkins.io/pipeline-rest-api/).

## Deployment validation

Use the deterministic controller fixtures in [testing](testing.md) before a live
check. Against an explicitly authorized test controller/job, verify `job.view`,
one build summary, a small console excerpt, and a disposable artifact download;
compare the downloaded bytes and inspect the corresponding audit records. Test
Pipeline or detailed test-report actions only when their required plugins/report
shapes are installed. An allowed summary read does not imply a log or artifact
permission.

Run `build.trigger` only for a dedicated, non-parameterized test job approved for
execution. Inspect its queue receipt and subsequent job state; an uncertain
response must not be retried automatically. Record the controller/plugin versions
and any untested actions. Local fixtures do not validate a particular production
controller, plugin set, artifact-storage redirect or TLS chain.
