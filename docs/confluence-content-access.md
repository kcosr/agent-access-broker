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
| `confluence_content` | `exact` page URL | That page and separately granted owner-bound comment/attachment operations |
| `confluence_content` | `exact` blog URL | That blog and separately granted owner-bound operations |
| `confluence_content` | `subtree` page URL | That page and its current descendants |
| `confluence_content` | `subtree` folder URL | Pages currently below that folder |

Content selectors use these canonical forms:

```text
https://example.atlassian.net/wiki/spaces/ENG/pages/12345
https://example.atlassian.net/wiki/spaces/ENG/folder/67890
https://example.atlassian.net/wiki/spaces/ENG/blog/24680
```

They pin the site, case-sensitive space key, root kind and immutable content ID.
Content resources do not support `all`, `namespace`, exact folders or blog
subtrees. Page/folder selectors cannot cover blogs. Moving a root within its
configured space preserves its identity; a different site or space key requires
an explicit resource edit. Renaming a page does not change its identity.

The Resources editor offers URL entry for configured services. Select the
service and coverage, paste the URL, and inspect the normalized selector before
saving. Normalization removes only supported title/date decorations. It rejects
query strings, fragments, credentials, ports, IP hosts, encoded delimiters and
unsupported paths. An optional canonical space-key override is an administrator
assertion, checked against current upstream facts when the resource is used.
Personal-space keys retain their leading `~` and exact case.

Normalization and saving are offline. They require no administrator Atlassian
connection, do not verify existence or permissions, and do not acquire or refresh
credentials. The response explicitly reports `verification: "not_checked"`.
An API or TOML write must already contain the strict canonical value; it does
not silently normalize a title, trailing slash or alternate URL. The global
catalog can retain a valid entry for an unconfigured site, but that entry cannot
match a different site's service.

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
`service`, `url`, `coverage` (`space`, `exact` or `subtree`) and optional
`spaceKey`. Both routes require a management credential and policy-read access
to the selected service. Auditors can preview but cannot save. An administrator's
agent token cannot call these routes. Browser normalization requires the ordinary
CSRF protection. Preview grants no resource-write permission.

Save the returned selector through the usual resource API or CLI:

```sh
agent-access admin policy resources create \
  --id runbooks --resource-type confluence_content \
  --selector-kind subtree \
  --selector-value https://example.atlassian.net/wiki/spaces/ENG/folder/67890 \
  --execution-context default --display-name Runbooks
```

Exact and subtree selectors of the same page are distinct resources. Different
titles or display names do not make duplicate canonical selectors distinct.

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
descendant absent. Missing, stale or unreadable evidence prevents the move.

For an unresolved move-exclusion relation, protected audit records
`confluence_move_relation_unresolved`, a bounded category such as
`not_visible_or_absent`, and configured resource/group IDs. A missing response
does not distinguish deletion from lack of visibility. Authorized policy readers
can inspect those entries and explicitly correct or remove them. Management
previews warn that runtime root visibility is required; offline previews do not
check whether a root still exists or is readable.

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
requested spaces as further constraints. A content selector includes its pinned
space as well as its ID or ancestor predicate. The caller CQL grammar is
unchanged. Too-large or unrepresentable authority fails with `scope_unresolved`;
no constraint is dropped or broadened.

The upstream index is only a prefilter. Returned candidates still pass current
identity, status, space and required hierarchy checks. Denied candidates are
removed before metadata, presentation, object IDs and counts are released.
Unknown evidence fails the request. Counts describe released rows, not upstream
totals or skipped rows. A bounded scan may return an empty page with continuation;
continue until exhaustion. Confidential tokens bind current authority and query,
retain their original expiry, and do not grant access independently.

Ordinary resource-access discovery remains offline. Location entries use
`scope: "location"`, `resourceTypes`, `domain`,
`containmentVerification: "at_invocation"`, and safe positive coverage with
`restricted` and `conditional` flags. They withhold excluded and competing
private roots. Authorized management and token previews retain full conditions.
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

The provider checks location again before writes or releasing protected results.
Complete-lineage checks detect ancestor movement even without a page-version
change. Container-only checks tolerate same-space placement changes. These are
observations around a request, not an atomic lock with Confluence: a change after
the final observation can still race the operation. The search index can lag, and
timing is not constant.

Metadata and scan budgets are operation-wide, including retries and final checks.
See [configuration](configuration.md#providersconfluence) for defaults and bounds.
The encoded request-target ceiling is an operator limit, defaulting to 4096 bytes;
the HTTP client's absolute-URI limit also applies. Qualify the selected ceiling
on each direct/gateway route. A length rejection fails without broadening or
replaying the query with fewer constraints.

## Upgrade and qualification

Back up the managed database and keys before migration
`038_confluence_content_resources`. It adds stored subtree selectors while
preserving existing resources, memberships and encrypted attributes. Upgrade
Broker, CLI and portal together. A rollback needs the matching pre-upgrade
database and binaries. Provider SDK consumers must adopt the explicit scalar or
containment scope contracts; subtree selectors cannot be converted to scalar
search authority.

Local fixtures establish Broker behavior, not live tenant compatibility. Before
production use, qualify the selected direct and gateway credentials against
mixed page/folder trees, restricted intermediates, drafts, comments, attachments,
v2 page update/create, move exclusions, CQL ancestor/negation semantics, index
convergence and encoded request limits. Use separately authorized disposable
content for mutation checks. Retain the tested route, scopes and limitations.
