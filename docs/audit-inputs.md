# Recorded request details

Native providers and accepted command actions can declare which original inputs
the Broker records. The host places these requested facts in the optional
top-level `requestAudit` envelope. They are independent of provider outcomes,
resolved scopes, credentials and provider-supplied `providerAudit` metadata.
External MCP/OpenAPI/Swagger imports, Git smart HTTP and management requests keep
their own audit contracts and do not acquire argument capture through this feature.

## What is recorded

Reviewed native declarations retain target and relationship identifiers, paths,
refs, supplied short titles, query text, account references and email addresses,
operational controls, and admitted upload filename/type/size metadata. Known
record arrays preserve their source indices and the association between fields.
Undeclared inputs are omitted; adding a provider input requires an explicit
classification in that provider's checked-in inventory.

Bodies, file bytes, arbitrary property values and payload objects, credentials,
private attributes, opaque continuations/draft handles, and secret-bearing raw
URLs are excluded from value capture. A reviewed declaration may record an exact
supplied flag, array count or UTF-8 text byte count instead. A secret or opaque
token receives no length or hash. Raw locator URLs have presence-only rules;
resolved identities remain separate provider facts. Existing observed download
receipts and hashes keep their own transfer-verification contract.

Queries and short titles can contain confidential business text. Any retained
string, including an identifier or enum-like control, could contain a mistakenly
pasted secret. This is reviewed data selection, not DLP or anonymization. Every
authorized reader sees the complete matching record, including raw-only fields.
Service policy managers can read these facts for their services without upstream
resource grants. Existing row visibility, retention and encryption are unchanged.
The values are not added to traces, metrics, logs or filter URLs.

## Bounds and interpretation

The encoded envelope is limited to 16,384 bytes, including metadata and JSON
escaping. Native strings normally retain at most 1,024 UTF-8 bytes; queries and
the shared engine permit up to 4,096. Text/query prefixes carry explicit
truncation information; overlong identifiers, paths, dates and emails are omitted
whole. Arrays inspect only their first 20 positions and never substitute later
items for invalid or omitted positions. Record rows are retained atomically.
Supplied primary facts have budget priority, followed by detail and raw facts;
absent placeholders cannot displace supplied information.

Capture checks the declared scalar/list shape and basic runtime kind. It does
not enforce schema enum membership, patterns, ranges or cross-field conditions,
and does not change ordinary provider validation. A malformed but correctly
shaped identifier can therefore be recorded before the provider rejects it.
Null, false, zero, empty text, empty lists and absent properties stay distinct.
Requested values never imply authorization for a target or successful execution.

The capture point is successful invocation preparation, after initial credential
and lookup selection. Earlier failures and preparation timeouts retain existing
audit information without request details. Later credential, execution or owned
operation failures retain the prepared snapshot. An action declared as multipart
upload defers its whole snapshot until body metadata admission succeeds, on every
transport. It never captures body bytes or local spool paths. JSON/HTTP-MCP calls
that bypass body admission receive no upload snapshot.

Existing owned operations and terminal stream owners retain the snapshot on their
error and interruption paths. Inline upload/required-download futures that are
dropped before finalization still have no supervisor guaranteeing a terminal
record. This feature does not change that transport lifecycle.

## Stored version 1

`requestAudit` contains `version: 1`, `declarationSha256`, `status`, `fields`,
`budgetOmittedFields` and `absentOmittedFields`. The digest binds the actual input
schema and ordered declaration, with canonical object keys. It is not a request
hash or proof of provider input validity. Labels and presentation metadata are
event-time facts; rendering never consults today's catalog.

Each field carries `key`, `label`, `display` (`primary`, `detail`, `raw`), `role`
(`target`, `change`, `fact`), `kind`, `capture`, `state`, and nullable `supplied`.
Value fields additionally require `shape` (`scalar` or `list`). States are
`captured`, `absent`, `null`, `invalid`, `tooLarge`, and `budget`. A malformed
ancestor makes `supplied` null rather than asserting absence. Prefixes use
`truncated: true` and `originalBytes`; the stored prefix contains no added ellipsis.

Integer-backed i64/u64 values outside JavaScript's safe integer range use a
canonical decimal string with `encoding: "decimalInteger"`. Copy/render that
text directly. Ordinary strings have no encoding tag. Floating-point forms such
as `1.0`, `-0`, or an out-of-u64 parsed literal are not identifier integers.
Number-kind values permit finite floats without promising preservation of the
original JSON decimal spelling.

Lists contain `items` with original `index`, state and retained value. Records
contain `columns` once and `rows` with original index and statically keyed
`cells`. Both carry `totalCount`, `limitedCount`, `invalidCount` and
`budgetOmittedCount`. Total equals retained positions plus limited and budget-
omitted positions; invalid positions are a subset of retained positions. Samples
do not establish validity of an unvisited suffix.

`partial` means capture lost supplied information through invalid shape,
truncation, limits or budget. Policy omissions and omitted absent placeholders
do not make a record partial. `unavailable` has empty fields, zero counters and
fixed `reason: "projectionFailed"`; it cannot contain dynamic error text. Missing
declarations, all-omit declarations and unreached capture points have no envelope.
Historical records are unchanged and are not backfilled.

JSONL, SQLite, management/self-service APIs and JSON copy/download preserve the
same envelope. SQLite search explicitly indexes retained strings and identifier
values after identity/authority facts and before verbose provider audit. Labels,
digests, states, booleans, numeric controls, counts and byte sizes are not new
search terms. Search uses unicode61 tokens, not arbitrary substrings; the existing
32 KiB index budget can leave some retained text unindexed.

## SDK and command declarations

SDK authors attach `AuditInputProjection` through `ActionDescriptor::audit_inputs`.
Use `AuditInputRule::value` or `values` with explicit kind, cap and overflow for
string-bearing kinds; summary builders are `presence`, `item_count` and
`utf8_byte_count`. `records` contains explicit relative child rules, and `omit`
records an inventory decision without creating an event entry. There is no
automatic capture by field name. The public rule model serializes as `auditInputs`.

Publication validates options, unique keys/selectors, strict RFC 6901 pointers,
named schema paths and sensitive-path vetoes. Selectors are bounded to 16 segments,
1 KiB text and 64 rules including record children. Only records traverse object
arrays; no arbitrary map enumeration, JSONPath or recursive selector is supported.
One record-iterator level is permitted. Local references and schema applicators
are traversed conservatively for sensitivity, within fixed work limits; unresolved
or unsupported applicable traversal rejects value/count declarations. Root
header-name sensitivity and explicit `x-agent-access-sensitive` annotations cannot
be bypassed by a malformed input shape. Presence/omit copy no opaque value.
Normal catalog sensitive-input pointers remain unchanged.

Full action catalogs and detail/describe responses publish these declarations;
MCP tools/list and invocation schemas stay compact and unchanged. Commands use
the same strict model, persisted in accepted `annotations.command.auditInputs`.
Capture or presentation changes require discovery, review and acceptance, and
quarantine changed actions. Invalid accepted contracts fail publication or make
the retained service unavailable; they never silently disable capture while
leaving execution enabled. See [command imports](command-imports.md).

## Portal

Audit and Activity show Request details before Outcome and Identity. Additional
details retain less prominent fields; raw-only fields appear exclusively in Raw.
Fields supplied describes recorded requested changes, not applied changes. Long
text and lists expand; copying returns the exact stored text, with truncation
warnings outside the clipboard payload. Unknown versions or failed projections
show unavailable details while Raw preserves the stored record.

Upload outcomes remain visible even when their associated metadata was outside
the sample or budget. The portal explicitly labels that missing metadata rather
than substituting a different row or a current filename. Uncertain mutation
outcomes remain warnings, and Allowed means admission, not successful application.
