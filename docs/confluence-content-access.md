# Confluence content access

Confluence grants can cover spaces, exact pages or blogs, and page or folder
subtrees. The same resources can restrict agent tokens. This applies to all
published Confluence actions; an action still needs its own grant and supported
content-format configuration. Upstream permissions remain an additional limit.

## Resources and URL entry

| Resource type | Selector | Coverage |
| --- | --- | --- |
| `confluence_space` | `exact` space key | Content in that space, including new content |
| `confluence_space` | `all` | All spaces accessible to the selected credential |
| `confluence_content` | `exact` page identity | That page and separately granted owner-bound comment/attachment operations |
| `confluence_content` | `exact` blog identity | That blog and separately granted owner-bound operations |
| `confluence_content` | `subtree` page identity | That page and its current descendants |
| `confluence_content` | `subtree` folder identity | Pages currently below that folder |

Content selectors use these canonical identity values:

```text
https://example.atlassian.net/wiki/content/page/12345
https://example.atlassian.net/wiki/content/folder/67890
https://example.atlassian.net/wiki/content/blog/24680
```

They bind the site, root kind and immutable content ID. Coverage is the separate
exact/subtree selector kind. A page rename or an external cross-space move does
not change that identity. A subtree follows its root and covers its current
descendants; a descendant moved outside loses that subtree's coverage. Changing
the configured tenant never rebinds an existing content resource to another site.
Content resources do not support `all`, `namespace`, exact folders or blog
subtrees. Page/folder selectors cannot cover blogs.

These identity values are not browser links or action URL inputs. To use a
discovered page or blog, pass its ID to the action's `pageId` or `blogId` field;
creation uses the documented typed parent input. For example, the first identity
above addresses `page.view` with `{"pageId":"12345"}`. Inspect the selected
action's schema and documentation for its locator. An identity value supplied as
`url`, `parentUrl` or `targetUrl` fails with `locator_invalid`. Ordinary browser
action URLs still require their space key or alias to match the current content
location. After an external move, use the ID or a current browser URL; a stale
browser URL can fail even though its saved content grant still applies.

In the Resources editor, paste a page, folder or blog browser URL. The configured
service and resource kind are inferred. A page immediately offers **This page
only** or **This page and descendants**; choose explicitly. Folder and blog
coverage is fixed. **Save** normalizes the current entry and creates or updates
the resource; no separate preview is needed. A failed normalization keeps the
draft and saves nothing. Name, execution contexts and enabled state remain ordinary
resource fields. Existing content resources can keep their identity while editing
those fields, and a saved page can switch exact/subtree coverage without a URL.
**Change location** starts a new URL entry.

Content URL entry also saves the pasted browser URL as optional navigation
metadata. Resource details and the editor show the link and let you open it in
Confluence. The editor can add, correct or clear a saved link without replacing
the resource. A replacement link must normalize to the same site, content kind
and immutable ID; changing the target requires **Change location** instead.
An existing resource without a saved browser URL has no link until one is added.
The grant builder shows the resource name and coverage, with its saved browser
URL on a separate line. The link opens Confluence in a new tab without changing
the resource selection. Its resource filter also matches saved URLs.

The link can become stale after a rename or move. Paste the current browser URL
into the editor to correct it. Saving and correcting links are offline: they do
not contact Confluence, verify accessibility or automatically follow redirects.
The link's title and space path do not control authorization, so a stale or
cleared link does not alter grant coverage. The browser uses your own Confluence
session when you open it.

HTTP resource writes use optional `browserUrl`; TOML uses `browser_url`. The
value is a trimmed browser URL of at most 4096 UTF-8 bytes. PATCH omission keeps
the current link and `null` clears it. The CLI accepts `--browser-url` on create
or update and `--clear-browser-url` on update. This metadata is supported for
Confluence content resources, not whole-space resources. Audit records identify
`browserUrl` as a changed field without recording its URL or title.
Agent resource discovery and token options omit saved browser links.

For content URL normalization, the browser space segment, title and date do not
enter identity. Folder URLs accept an optional title segment, such as
`/wiki/spaces/ENG/folder/67890/Operations+Runbooks`, including for nested folders.
The space segment must still have the supported key-or-alias
syntax. Unsupported paths, queries, fragments, credentials, ports, IP hosts,
encoded delimiters and dot segments are rejected. There is no editable
content-space or identity override. Normalization accepts browser URLs; direct
API/TOML resource writes require the strict canonical identity shown above.

Whole-space resources retain **By space key**, **From space URL** and **All
spaces** entry. By key uses the actual case-sensitive key, including the leading
`~` for personal spaces. Space URLs show the exact key that will be saved; a
browser alias is not necessarily that key. Use By space key when the URL contains
an alias. The editor does not resolve aliases upstream. Switching from URL to key
starts empty, and switching all to exact requires an explicit key or URL. An
exact space URL never implies all spaces.

Normalization and saving are offline. They require no administrator Atlassian
connection, do not verify existence or permissions, and do not acquire or refresh
credentials. The response reports `verification: "not_checked"`. Missing service
capability prevents new/replacement URL entry but does not prevent metadata-only
edits or the standalone space-key path. The global catalog can retain a valid
content entry for an unconfigured site; it cannot match another site's service.

Administrators and policy readers can use:

```sh
agent-access admin policy resources locations
agent-access admin policy resources normalize-location \
  --service confluence \
  --url https://example.atlassian.net/wiki/spaces/ENG/folder/67890 \
  --coverage subtree
```

The management routes are `GET /v1/admin/policy/resource-locations` and
`POST /v1/admin/policy/resource-locations/normalize`. The POST body contains
`service`, `url` and `coverage` (`space`, `exact` or `subtree`). Both require a
management credential and policy-read access to the selected service. Auditors
can normalize but cannot save. An administrator's agent token cannot call these
routes. Browser normalization requires ordinary CSRF protection; normalization
grants no resource-write permission.

Save the returned selector through the usual resource API or CLI:

```sh
agent-access admin policy resources create \
  --id runbooks --resource-type confluence_content \
  --selector-kind subtree \
  --selector-value https://example.atlassian.net/wiki/content/folder/67890 \
  --execution-context default --display-name Runbooks
```

Exact and subtree selectors of the same page are distinct resources. Different
browser space segments, titles or display names do not make the same canonical
identity and coverage distinct. Creation and patch validate the returned selector
independently and retain normal duplicate and version-conflict handling.

## Overlap, exclusions and precedence

Selections within a grant form a union. Its selected resource-group exclusions
subtract from that union, including disabled or context-ineligible excluded
entries. Another grant can independently restore the excluded coverage.
Token restrictions form an additional intersection with every selected grant.
Empty selections authorize nothing.

Resource specificity gives no priority. Ordinary requests first find grants
covering the complete operation, then prefer direct-user grants to group grants
and higher priority to lower priority. Equally ranked matching grants with
different credential modes deny as ambiguous. An unusable winning credential
does not permit a lower-grant fallback.

An exact space and a content root have a conditional overlap until current
location is known. Same-subject, same-priority grants using different credential
modes may therefore publish, then deny an overlapping request with ambiguous
credential mode precedence. Proven mixed-mode overlaps, such as identical roots
or exact/subtree on the same root, are rejected at publication. Use consistent
modes or explicit priorities to resolve an intended overlap.

| Grants | Result |
| --- | --- |
| Space reads plus folder writes | Broad reads, folder-limited writes |
| Space writes plus exact-page writes | Space-wide writes remain allowed |
| Space and folder selected in one grant | The space selection remains broad |
| Space minus folder in one grant, folder allowed by another | The other grant may restore folder access under ordinary precedence |
| Space grant with a folder-only token | Every allowed request must also fit the token's folder boundary |
| Separate source-only and destination-only move grants | Neither authorizes the whole move |

To narrow existing writes, remove the broader action permission, exclude the
region from that grant, or impose an appropriate token restriction. Adding a
narrower grant by itself does not narrow a broader one.

## Actions and compound operations

Point reads, updates and verification use the current location of the page or
blog. Comments, replies and attachments use their verified owner and membership;
an exact owner grant can cover them when their actions are separately granted.
Existing-content proofs accept current or archived spaces; creation and
`space.list` require current spaces. The content's own required lifecycle and
upstream permissions still apply.
Folder grants confer no `space.list` permission. Blog creation needs a space
resource; an exact existing blog cannot authorize a new blog.

`page.create` and `page.draft.create` authorize prospective child placement.
Supply `parent: {"kind":"page"|"folder","id":"…"}` or `parentUrl`, or omit
both to resolve the space homepage. An exact parent resource cannot authorize
creating a child; a covering subtree or space is required. The CLI uses
`--parent-kind page|folder --parent-id ID` or `--parent-url URL`.

`page.move` requires one grant, and the token boundary, to cover the whole moved
subtree at its current and proposed locations, plus the destination placement and
ordering anchor. It retains its page-only, same-space target contract. An exact
page does not prove subtree authority. Relevant exclusions need current readable
root evidence; a permission-filtered child list cannot prove an excluded
descendant absent. Missing, stale or unreadable evidence prevents the move. Content grants do not
need a separate space or ancestor grant. Source, destination and anchor must still
be in the same current space; following an externally moved root does not enable
a cross-space `page.move`.

For an unresolved move-exclusion relation, protected audit records
`confluence_move_relation_unresolved`, a bounded category and the configured
resource/group IDs for the specific required root that failed. A
`root_budget_exhausted` category distinguishes unfinished bounded proof work;
operation-wide exhaustion may have no individual root. The audit never substitutes
unrelated root IDs. A missing response does not distinguish deletion from lack of
visibility. An excluded root can legitimately be unreadable to a per-user
credential and can block affected moves anywhere on the site because its current
space is unknown. Check visibility or deliberately adjust the policy; removing
an exclusion changes access. Offline previews cannot verify a root's existence
or readability. Foreign-space disjointness itself requires current bounded
observations, retained through the final execution-credential check.

Draft handles preserve identity and placement facts; they grant no lasting
permission. Every handle action checks current grants, current parent/location
evidence and the actual draft using the admitted execution credential. Local
invalid, obsolete or wrong-owner handles retain `invalid_draft_handle` before
credential or upstream access. Handle version 5 carries typed page/folder parents.
Before upgrading, finish or explicitly discard drafts using the old Broker;
version 4 handles cannot be reused. A visible staged draft may need upstream
resolution before staging again.

## Search and discovery

Page and blog search select one winning grant band and credential mode for the
whole collection. Same-mode ties form a union; a higher band's empty result does
not fall back to a lower band. This can differ from individual point reads.

Before dispatch, Broker compiles every selected inclusion and exclusion plus
the independent token restriction into CQL, then adds the caller's filter and
requested spaces as further constraints. Exact content uses its ID; page subtree
uses self-or-ancestor, and folder subtree uses ancestor for page search. These
content predicates carry no inferred space. Space resources and explicit space
filters keep their own predicates. Too-large or unrepresentable authority fails
with `scope_unresolved`; no constraint is dropped or broadened.

A collection whose complete winning grant and token boundaries contain only
scalar space selectors retains the indexed-row path: one search request per page,
without per-candidate metadata reads. Its space/lifecycle observation is indexed
and can lag upstream changes. It checks requested-space admission, constrains CQL,
and checks canonical indexed-row authority; upstream CQL may resolve a browser
alias. Any content selector, including an exclusion or
token restriction, requires fresh candidate metadata. Container-only proof reads
the content and its actual space; hierarchy-dependent proof also walks current
ancestry. Broker checks current authority and requested spaces, rejects stale
indexed space, and repeats the required proof before release. Stable identity
never excuses a location change during the admitted request.

A valid observed boundary mismatch or changed final placement filters that row.
A failed initial or final proof, including not found/not visible, wrong kind or
lifecycle, hidden ancestry, malformed metadata, budget or credential failure,
fails the whole response without partial rows or a token. A stale deleted or
restricted indexed item can therefore prevent a content-constrained search until
the index or visibility changes. No weaker query or credential is tried.

Fresh proof costs at least two metadata reads per candidate per pass, with
separate initial and final passes. Each candidate/pass has its own space lookup;
reads are sequential and count toward request, byte and deadline limits. Plan
service/client timeouts and upstream rate capacity accordingly. Proof reservation
may return fewer rows than `maxResults`; a budget too small to complete one
candidate fails instead of returning a zero-progress cursor.

A scan that stops before starting a later candidate can return already checked
rows and a continuation, including an empty page after actual scanning progress.
Counts describe released rows, not upstream totals or skipped rows. Confidential
search tokens bind stable authority and query, retain their original expiry, and
reauthorize each resumed call. A changed mid-page result commitment requires a
restart. Root movement alone does not rewrite the policy identity or guarantee
complete results while the index converges. Owner-bound comment/attachment
cursors and draft handles retain operational placement bindings; movement can
invalidate an old token while a fresh request remains authorized.

Ordinary resource-access discovery remains offline. Location entries use
`scope: "location"`, `resourceTypes`, `domain`,
`containmentVerification: "at_invocation"`, and safe positive coverage with
`restricted` and `conditional` flags. They withhold excluded and competing
private roots. An exact space does not establish arbitrary content-root membership
offline. A caller-known positive root can remain visible as a conditional
intersection; current location is proved at invocation. Authorized management and token previews retain full conditions.
`projectionStatus: "too_complex"` means the coverage preview is unavailable;
it must not be interpreted as unrestricted or empty access. Explicit selections
remain intact, and final issuance evaluates policy independently.

## Current evidence and limits

Space-only and exact-only point authorization needs validated container facts.
Hierarchy-dependent selectors, exclusions and relevant competitors require
complete current lineage. Evidence validates kinds, immutable IDs, space identity,
parent edges, lifecycle, root termination and cycles. Hidden intermediates,
unsupported shapes and exhausted limits fail closed. Service-mode initial lookup
can use its read-only lookup account; execution checks use the selected execution
credential without fallback. Per-user-only policy needs no shared credential.

Point operations check location again before writes or releasing protected results.
Searches involving content selectors check each retained candidate again; scalar-only
space searches keep the indexed-space contract described above.
Complete-lineage checks detect ancestor movement even without a page-version
change. Container-only checks tolerate same-space placement changes. These are
observations around a request, not an atomic lock with Confluence: a change after
the final observation can still race the operation. The search index can lag, and
timing is not constant.

Metadata and scan budgets are operation-wide, including retries and final checks.
Move proofs also have independent per-pass ceilings of 256 logical metadata reads,
64 potentially overlapping roots and 256 unique content nodes. These are separate
ceilings, not a promise that every combination below the root/node limits fits the
read budget. Classifying a root and then obtaining stronger parent evidence can
require a second read; both count, as do current-space reads. Foreign-space roots
need only the evidence establishing disjointness. The read ceiling can be reached
before the node ceiling, and the protected audit identifies budget exhaustion.
See [configuration](configuration.md#providersconfluence) for defaults and bounds.
The encoded request-target ceiling is an operator limit, defaulting to 4096 bytes;
the HTTP client's absolute-URI limit also applies. Qualify the selected ceiling
on each direct/gateway route. A length rejection fails without broadening or
replaying the query with fewer constraints.

## Upgrade and qualification

Back up the managed database and keys before migrations
`038_confluence_content_resources` and `039_resource_browser_urls`. They add
stored subtree selectors and optional browser links while preserving existing
resources, memberships and encrypted attributes. Existing resources start with
no browser link; the canonical identity alone cannot reconstruct the original
URL. Upgrade
Broker, CLI and portal together, and restart searches without an old continuation
token after upgrading. A rollback needs the matching pre-upgrade database and
binaries. Provider SDK consumers must adopt the explicit scalar or
containment scope contracts; subtree selectors cannot be converted to scalar
search authority.

Local fixtures establish Broker behavior, not live tenant compatibility. Before
production use, qualify the selected direct and gateway credentials against
mixed page/folder trees, restricted intermediates, drafts, comments, attachments,
v2 page update/create, move exclusions, CQL ancestor/negation semantics, index
convergence and encoded request limits. Use separately authorized disposable
content for mutation checks. Retain the tested route, scopes and limitations.
