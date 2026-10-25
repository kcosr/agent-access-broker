// Pure helpers for the Audit and Activity views: filter and drawer URL state,
// paging session ranges, suggestions, and presentation of stored audit records
// (no JSX).
import type { AuditInputValue, AuditOptions, AuditRecord, BrokerTokenRecord, PolicyCatalogSubject } from "../types";
import { formatBytes, uniqueSortedOptions } from "./helpers";
import type { ResourceTypes } from "./resource-types";

/** `admin` reads `/v1/admin/audit/*` (Audit); `self` reads `/v1/audit/*` (Activity). */
export type AuditScope = "admin" | "self";

export const AUDIT_PAGE_SIZE = 50;
export const AUDIT_AUTO_REFRESH_MS = 15_000;
export const AUDIT_SEARCH_MAX_CHARS = 256;

/** A filter suggestion: the raw identifier is the label (it is what the filter sends and shows). */
export type AuditSuggestion = { value: string; label: string; description?: string; keywords?: string[] };

/** Broker records cover sign-in, tokens, and administration. */
export const AUDIT_BROKER_DESCRIPTION = "Sign-in and management";

/**
 * Service suggestions: Broker first (selectable even when this caller has no
 * retained broker records), then configured and recorded services by ID.
 */
export function auditServiceSuggestions(
  configured: { service: string; displayName?: string | null }[],
  brokerOptions: AuditOptions["services"]
): AuditSuggestion[] {
  const names = new Map<string, string>();
  for (const item of configured) if (item.displayName && item.displayName !== item.service) names.set(item.service, item.displayName);
  const ids = uniqueSortedOptions([...configured.map((item) => item.service), ...brokerOptions.map((item) => item.service)]).filter(
    (service) => service !== "broker"
  );
  return [
    { value: "broker", label: "broker", description: AUDIT_BROKER_DESCRIPTION, keywords: ["Broker"] },
    ...ids.map((service) => {
      const name = names.get(service);
      return name ? { value: service, label: service, description: name, keywords: [name] } : { value: service, label: service };
    })
  ];
}

/** Principal suggestions from catalog users: the principal ID, with the display name as a description. */
export function auditPrincipalSuggestions(users: { principalId?: string | null; displayName?: string | null }[]): AuditSuggestion[] {
  const names = new Map<string, string | null>();
  for (const user of users) {
    if (!user.principalId || names.has(user.principalId)) continue;
    names.set(user.principalId, user.displayName && user.displayName !== user.principalId ? user.displayName : null);
  }
  return [...names.keys()].sort().map((id) => {
    const name = names.get(id);
    return name ? { value: id, label: id, description: name, keywords: [name] } : { value: id, label: id };
  });
}

/** Include canonical broker/configured provider actions and supported prefix families. */
export function auditActionSuggestions(sources: AuditOptions["services"], service: string) {
  const actions = sources.filter((source) => !service || source.service === service).flatMap((source) => source.actions);
  return uniqueSortedOptions(actions.flatMap((action) => {
    const parts = action.split(".");
    return [action, ...parts.slice(1).map((_, index) => `${parts.slice(0, index + 1).join(".")}.*`)];
  }));
}

/** Drop an action known to belong elsewhere, but keep manual/historical filters. */
export function auditActionAfterServiceChange(action: string, service: string, sources: AuditOptions["services"]) {
  if (!service || !action) return action;
  const matches = (candidate: string) => action.endsWith("*") ? candidate.startsWith(action.slice(0, -1)) : candidate === action;
  const known = sources.some((source) => source.actions.some(matches));
  const available = sources.some((source) => source.service === service && source.actions.some(matches));
  return known && !available ? "" : action;
}

export const AUDIT_RANGE_PRESETS = [
  { value: "1h", label: "Last hour", ms: 3_600_000 },
  { value: "24h", label: "Last 24 hours", ms: 86_400_000 },
  { value: "7d", label: "Last 7 days", ms: 7 * 86_400_000 },
  { value: "30d", label: "Last 30 days", ms: 30 * 86_400_000 }
] as const;
export type AuditRangePreset = (typeof AUDIT_RANGE_PRESETS)[number]["value"];
export type AuditRange = AuditRangePreset | "custom";
export const DEFAULT_AUDIT_RANGE: AuditRangePreset = "24h";

export const AUDIT_DECISIONS = ["allow", "deny", "error"] as const;
export type AuditDecision = (typeof AUDIT_DECISIONS)[number];

/** The record phases the query API filters on. */
export const AUDIT_PHASES = ["started", "completed", "failed", "canceled", "preflight", "upstream_verification", "success"] as const;
export type AuditPhase = (typeof AUDIT_PHASES)[number];

export type AuditFilters = {
  range: AuditRange;
  /** Custom range bounds as RFC 3339 UTC instants; empty is unbounded. Unused for presets. */
  from: string;
  to: string;
  /** Admin scope only; Activity never sends it. */
  principal: string;
  service: string;
  action: string;
  decision: "" | AuditDecision;
  reasonCode: string;
  phase: "" | AuditPhase;
  tokenId: string;
  requestId: string;
  node: string;
  q: string;
};

export const DEFAULT_AUDIT_FILTERS: AuditFilters = {
  range: DEFAULT_AUDIT_RANGE,
  from: "",
  to: "",
  principal: "",
  service: "",
  action: "",
  decision: "",
  reasonCode: "",
  phase: "",
  tokenId: "",
  requestId: "",
  node: "",
  q: ""
};

/** Filters in the collapsed "More filters" sidebar section. */
export const AUDIT_MORE_FILTER_KEYS = ["phase", "reasonCode", "node", "tokenId", "requestId"] as const;

// Query-string order; the API parameter names double as the URL keys.
const FILTER_URL_KEYS = ["principal", "service", "action", "decision", "reasonCode", "phase", "tokenId", "requestId", "node", "q"] as const;

function isPreset(value: string): value is AuditRangePreset {
  return AUDIT_RANGE_PRESETS.some((preset) => preset.value === value);
}

function oneOf<T extends string>(values: readonly T[], value: string): T | "" {
  return (values as readonly string[]).includes(value) ? (value as T) : "";
}

/** An instant as an RFC 3339 UTC string, or "" when it is empty or unparsable. */
export function normalizeAuditInstant(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return "";
  const time = Date.parse(trimmed);
  return Number.isNaN(time) ? "" : new Date(time).toISOString();
}

/** Restores filters from a page query string; unknown or invalid values fall back to defaults. */
export function parseAuditFilters(search: string, scope: AuditScope): AuditFilters {
  const params = new URLSearchParams(search);
  const text = (key: string) => (params.get(key) ?? "").trim();
  const from = normalizeAuditInstant(text("from"));
  const to = normalizeAuditInstant(text("to"));
  const rangeParam = text("range");
  const range: AuditRange = isPreset(rangeParam)
    ? rangeParam
    : rangeParam === "custom" || from || to
      ? "custom"
      : DEFAULT_AUDIT_RANGE;
  return {
    range,
    from: range === "custom" ? from : "",
    to: range === "custom" ? to : "",
    principal: scope === "admin" ? text("principal") : "",
    service: text("service"),
    action: text("action"),
    decision: oneOf(AUDIT_DECISIONS, text("decision")),
    reasonCode: text("reasonCode"),
    phase: oneOf(AUDIT_PHASES, text("phase")),
    tokenId: text("tokenId"),
    requestId: text("requestId"),
    node: text("node"),
    q: text("q")
  };
}

/** The page query string for filters (with a leading `?`), or "" for the defaults. */
export function auditFiltersSearch(filters: AuditFilters, scope: AuditScope) {
  const params = new URLSearchParams();
  if (filters.range !== DEFAULT_AUDIT_RANGE) params.set("range", filters.range);
  if (filters.range === "custom") {
    if (filters.from) params.set("from", filters.from);
    if (filters.to) params.set("to", filters.to);
  }
  for (const key of FILTER_URL_KEYS) {
    if (key === "principal" && scope !== "admin") continue;
    const value = filters[key].trim();
    if (value) params.set(key, value);
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

export function auditListBasePath(scope: AuditScope) {
  return scope === "admin" ? "/ui/admin/audit" : "/ui/activity";
}

/** A link into the viewer with the given filters over the defaults. */
export function auditListPath(scope: AuditScope, filters: Partial<AuditFilters> = {}) {
  return `${auditListBasePath(scope)}${auditFiltersSearch({ ...DEFAULT_AUDIT_FILTERS, ...filters }, scope)}`;
}

/** "Last used" links open the viewer on the token, with a range that covers its last use. */
export function auditTokenPath(scope: AuditScope, record: Pick<BrokerTokenRecord, "tokenId" | "lastUsedAt">, now = Date.now()) {
  return auditListPath(scope, { tokenId: record.tokenId, ...auditRangeCovering(record.lastUsedAt, now) });
}

/** The record open in the drawer: its broker request (the timeline) and audit ID. */
export type AuditOpen = { request: string; record: string };

export const NO_AUDIT_OPEN: AuditOpen = { request: "", record: "" };

/** The drawer's URL parameters (`?request=<brokerRequestId>&record=<auditId>`). */
export function parseAuditOpen(search: string): AuditOpen {
  const params = new URLSearchParams(search);
  const request = (params.get("request") ?? "").trim();
  return { request, record: request ? (params.get("record") ?? "").trim() : "" };
}

/** The viewer's query string: filters, then the open record (with a leading `?`, or ""). */
export function auditPageSearch(filters: AuditFilters, scope: AuditScope, open: AuditOpen = NO_AUDIT_OPEN) {
  const params = new URLSearchParams(auditFiltersSearch(filters, scope));
  if (open.request) {
    params.set("request", open.request);
    if (open.record) params.set("record", open.record);
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

/**
 * A deep link to one record's drawer (and its request timeline). The list
 * filters default to a range that covers the record, so its row is visible too.
 */
export function auditRecordPath(
  scope: AuditScope,
  record: Pick<AuditRecord, "brokerRequestId" | "auditId"> & { timestamp?: string | null },
  filters: Partial<AuditFilters> = {},
  now = Date.now()
) {
  const base = { ...DEFAULT_AUDIT_FILTERS, ...auditRangeCovering(record.timestamp, now), ...filters };
  return `${auditListBasePath(scope)}${auditPageSearch(base, scope, { request: record.brokerRequestId, record: record.auditId })}`;
}

const UUID_RE = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$/i;

/** Broker request IDs are UUIDs; anything else cannot have a timeline. */
export function isAuditRequestId(value: string) {
  return UUID_RE.test(value);
}

/** The absolute bounds one paging session uses. */
export type AuditSessionRange = { from: string | null; to: string | null };

/**
 * Resolves a relative preset to an absolute UTC `from` at `now`, leaving `to` open so records
 * are not hidden when the browser clock lags the broker; custom bounds pass through.
 */
export function resolveAuditRange(filters: Pick<AuditFilters, "range" | "from" | "to">, now: number): AuditSessionRange {
  if (filters.range === "custom") return { from: filters.from || null, to: filters.to || null };
  const preset = AUDIT_RANGE_PRESETS.find((item) => item.value === filters.range) ?? AUDIT_RANGE_PRESETS[1];
  return { from: new Date(now - preset.ms).toISOString(), to: null };
}

/** The smallest preset that still covers an instant (with a minute to spare), else all time. */
export function auditRangeCovering(at: string | null | undefined, now: number): Pick<AuditFilters, "range" | "from" | "to"> {
  const time = at ? Date.parse(at) : Number.NaN;
  if (Number.isNaN(time)) return { range: DEFAULT_AUDIT_RANGE, from: "", to: "" };
  const age = now - time;
  const preset = AUDIT_RANGE_PRESETS.find((item) => age <= item.ms - 60_000);
  return preset ? { range: preset.value, from: "", to: "" } : { range: "custom", from: "", to: "" };
}

/** How many filters differ from the defaults (the time range counts when it is not the default). */
export function auditActiveFilterCount(filters: AuditFilters) {
  let count = filters.range === DEFAULT_AUDIT_RANGE ? 0 : 1;
  for (const key of FILTER_URL_KEYS) if (filters[key].trim()) count += 1;
  return count;
}

/** A problem that would make the server reject the filters, in words, or null. */
export function auditFiltersProblem(filters: AuditFilters) {
  if (filters.range === "custom" && filters.from && filters.to && Date.parse(filters.from) > Date.parse(filters.to)) {
    return "The start of the range must not be after its end.";
  }
  if (filters.q.length > AUDIT_SEARCH_MAX_CHARS) {
    return `Search text must be at most ${AUDIT_SEARCH_MAX_CHARS} characters.`;
  }
  return null;
}

/** First-page query parameters; empty filters are omitted (the API rejects empty values). */
export function auditListParams(filters: AuditFilters, range: AuditSessionRange, scope: AuditScope): Record<string, string> {
  const params: Record<string, string> = {};
  if (range.from) params.from = range.from;
  if (range.to) params.to = range.to;
  for (const key of FILTER_URL_KEYS) {
    if (key === "principal" && scope !== "admin") continue;
    const value = filters[key].trim();
    if (value) params[key] = value;
  }
  params.limit = String(AUDIT_PAGE_SIZE);
  return params;
}

/** Continuation parameters: the cursor already carries the first request's filters and bounds. */
export function auditContinuationParams(cursor: string): Record<string, string> {
  return { cursor, limit: String(AUDIT_PAGE_SIZE) };
}

/** A node column is useful only when the loaded records come from more than one node. */
export function showAuditNodeColumn(records: Pick<AuditRecord, "nodeId">[]) {
  return new Set(records.map((record) => record.nodeId)).size > 1;
}

function objectField(value: unknown, key: string): unknown {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>)[key] : undefined;
}

function stringField(value: unknown, key: string) {
  const field = objectField(value, key);
  return typeof field === "string" && field ? field : null;
}

/** The record phase, from the same fields (and order) the audit store indexes. */
export function auditRecordPhase(record: Pick<AuditRecord, "providerAudit">) {
  const audit = record.providerAudit;
  return (
    stringField(audit, "streamPhase") ??
    stringField(objectField(audit, "gateway"), "phase") ??
    stringField(audit, "gatewayPhase") ??
    stringField(objectField(audit, "management"), "phase")
  );
}

/** Bytes returned to a Git client by a gateway request, when the record has them. */
export function auditGatewayResponseBytes(record: Pick<AuditRecord, "providerAudit">) {
  const bytes = objectField(objectField(record.providerAudit, "gateway"), "responseBytes");
  return typeof bytes === "number" ? bytes : null;
}

/** `upstreamStatus · upstreamDurationMs` plus gateway response bytes, from present fields only. */
export function auditUpstreamSummary(record: Pick<AuditRecord, "upstreamStatus" | "upstreamDurationMs" | "providerAudit">) {
  const parts: string[] = [];
  if (typeof record.upstreamStatus === "number") parts.push(String(record.upstreamStatus));
  if (typeof record.upstreamDurationMs === "number") parts.push(`${record.upstreamDurationMs} ms`);
  const bytes = auditGatewayResponseBytes(record);
  if (bytes !== null) parts.push(formatBytes(bytes));
  return parts.join(" · ");
}

export type AuditGitRefUpdate = { ref: string; oldId: string; newId: string; create: boolean; delete: boolean };

/** Ref updates of a Git push, from `providerAudit.git.updates`. */
export function auditGitRefUpdates(record: Pick<AuditRecord, "providerAudit">): AuditGitRefUpdate[] {
  const updates = objectField(objectField(record.providerAudit, "git"), "updates");
  if (!Array.isArray(updates)) return [];
  return updates.flatMap((update) => {
    const ref = stringField(update, "ref");
    if (!ref) return [];
    return [{
      ref,
      oldId: stringField(update, "oldId") ?? "",
      newId: stringField(update, "newId") ?? "",
      create: objectField(update, "create") === true,
      delete: objectField(update, "delete") === true
    }];
  });
}

/** The management operation block of a `broker` record, when present. */
export function auditManagement(record: Pick<AuditRecord, "providerAudit">) {
  const management = objectField(record.providerAudit, "management");
  if (!management || typeof management !== "object") return null;
  return {
    operation: stringField(management, "operation"),
    target: objectField(management, "target") ?? null,
    targetService: stringField(management, "targetService")
  };
}

/** A stored value as one line of text: strings as is, anything else as compact JSON. */
export function compactJson(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

const KEY_ACRONYMS = new Map([["id", "ID"], ["iid", "IID"], ["url", "URL"], ["uuid", "UUID"], ["sha", "SHA"], ["api", "API"], ["ci", "CI"]]);

/**
 * An identifier as a sentence-case label: camelCase and `_`, `-` or `.`
 * separated words, with common acronyms in capitals (`mergeRequestIid` is
 * "Merge request IID", `jira_project` is "Jira project").
 */
export function auditKeyLabel(key: string): string {
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[\s_.-]+/)
    .filter(Boolean)
    .map((word) => word.toLowerCase());
  if (!words.length) return key;
  return words.map((word, index) => KEY_ACRONYMS.get(word) ?? (index === 0 ? word.charAt(0).toUpperCase() + word.slice(1) : word)).join(" ");
}

export type AuditLabeledValue = { key: string; label: string; value: string };

/** One row per resource scope type: the type's registry label (else its ID as words) and its comma-joined values. */
export function auditScopeRows(record: Pick<AuditRecord, "resourceScopes">, types: ResourceTypes): AuditLabeledValue[] {
  return Object.entries(record.resourceScopes ?? {}).map(([type, values]) => ({
    key: type,
    label: types.get(type)?.label ?? auditKeyLabel(type),
    value: values.join(", ")
  }));
}

/**
 * One row per top-level key of the provider-reported object IDs, labeled by
 * the key as words: scalars as text, nested values as compact JSON. A value
 * that is not an object is one "Object IDs" row.
 */
export function auditObjectIdRows(record: Pick<AuditRecord, "objectIds">): AuditLabeledValue[] {
  const ids = record.objectIds;
  if (ids == null) return [];
  if (typeof ids !== "object" || Array.isArray(ids)) return [{ key: "objectIds", label: "Object IDs", value: compactJson(ids) }];
  return Object.entries(ids).map(([key, value]) => ({ key, label: auditKeyLabel(key), value: compactJson(value) }));
}

const IDENTITY_SOURCE_TYPES = new Map([
  ["broker_tokens", "Broker token"],
  ["static_principals", "Static token"],
  ["trusted_user", "Trusted user"],
  ["forwarded_identity", "Forwarded identity"]
]);

const TOKEN_CLASSES = new Map([
  ["agent_invoke", "Agent invocation"],
  ["user_manage", "User management"],
  ["admin", "Administration"]
]);

/**
 * The record's identity source in words: its type and token class
 * ("Trusted user · Agent invocation"), or "Browser session" for a portal
 * sign-in. Unknown types and classes show as recorded.
 */
export function auditIdentitySourceLabel(source: NonNullable<AuditRecord["identitySource"]>): string {
  if (auditIsBrowserSession(source)) return "Browser session";
  const type = IDENTITY_SOURCE_TYPES.get(source.type) ?? source.type;
  const tokenClass = source.tokenClass ? TOKEN_CLASSES.get(source.tokenClass) ?? source.tokenClass : null;
  return tokenClass ? `${type} · ${tokenClass}` : type;
}

/** Group IDs to display names, from the policy catalog's subjects. */
export function auditGroupNames(groups: PolicyCatalogSubject[]): Map<string, string> {
  return new Map(groups.flatMap((group) => (group.groupId && group.displayName ? [[group.groupId, group.displayName] as const] : [])));
}

/** A display name that replaces an ID in the Summary: known, non-empty and different from the ID. */
export function auditDisplayName(names: ReadonlyMap<string, string>, id: string): string | null {
  const name = names.get(id);
  return name && name !== id ? name : null;
}

/**
 * The IDs that Request › Details repeats because display names replaced them
 * in the Summary (where an ID is otherwise only a hover title): the
 * principal's, and every group's when any group showed a name.
 */
export function auditReplacedIds(
  record: Pick<AuditRecord, "principal" | "groups">,
  principalNames: ReadonlyMap<string, string>,
  groupNames: ReadonlyMap<string, string>
): { principalId: string | null; groupIds: string[] } {
  const groups = record.groups ?? [];
  return {
    principalId: auditDisplayName(principalNames, record.principal) ? record.principal : null,
    groupIds: groups.some((group) => auditDisplayName(groupNames, group)) ? groups : []
  };
}

/**
 * The record's captured action inputs, in declaration order. Entries that are
 * not objects, lack a non-empty `input` or `label`, or have no `value` key are
 * skipped; `truncated` holds only when the record says `true`.
 */
export function auditInputs(record: Pick<AuditRecord, "auditInputs">): AuditInputValue[] {
  const entries: unknown = record.auditInputs;
  if (!Array.isArray(entries)) return [];
  return entries.flatMap((entry: unknown) => {
    const input = stringField(entry, "input");
    const label = stringField(entry, "label");
    if (!input || !label || !Object.hasOwn(entry as object, "value")) return [];
    const { value, truncated } = entry as Record<string, unknown>;
    return [{ input, label, value, truncated: truncated === true }];
  });
}

/** Visible notation for control, format (bidi) and line/paragraph separator characters, except newlines. */
export function auditDisplayText(text: string): string {
  return text.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (char) => (char === "\n" ? char : `\\u{${char.codePointAt(0)!.toString(16).toUpperCase()}}`));
}

function isFlatScalar(value: unknown): value is string | number | boolean {
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

/** How the Summary shows an audit input value; the hover text stays the stored compact JSON. */
export type AuditInputDisplay = {
  /** The text to preview. */
  text: string;
  /** A `{type, value}` search query's language in upper case ("JQL"), shown after the query; null for `text` queries and other values. */
  badge: string | null;
  /** The text is compact JSON: a number, boolean, null, object or nested value. */
  json: boolean;
};

/**
 * An audit input value for the Summary. Strings show as is. A `{type, value}`
 * search query (both strings, no other keys) shows its value, with its type as
 * a badge unless it is `text`. Arrays of strings, numbers and booleans are
 * joined with ", " ("(none)" when empty). Everything else is compact JSON.
 */
export function auditInputDisplay(value: unknown): AuditInputDisplay {
  if (typeof value === "string") return { text: value, badge: null, json: false };
  if (Array.isArray(value)) {
    if (!value.length) return { text: "(none)", badge: null, json: false };
    if (value.every(isFlatScalar)) return { text: value.map(String).join(", "), badge: null, json: false };
  } else if (value && typeof value === "object") {
    const { type, value: query } = value as Record<string, unknown>;
    if (Object.keys(value).length === 2 && typeof type === "string" && typeof query === "string") {
      return { text: query, badge: type && type !== "text" ? type.toUpperCase() : null, json: false };
    }
  }
  return { text: compactJson(value), badge: null, json: true };
}

/** Code points in an audit input's one-line preview, including the trailing ellipsis when cut. */
export const AUDIT_INPUT_PREVIEW_CHARS = 100;

/**
 * An audit input's one-line preview: whitespace runs (newlines included)
 * become one space, controls are escaped, and longer text is cut by code
 * point with a trailing "…".
 */
export function auditInputPreview(text: string): string {
  const chars = Array.from(auditDisplayText(text.replace(/\s+/g, " ")));
  return chars.length > AUDIT_INPUT_PREVIEW_CHARS ? `${chars.slice(0, AUDIT_INPUT_PREVIEW_CHARS - 1).join("")}…` : chars.join("");
}

/**
 * The policy grant reference of a matched grant (what the Policies drawer
 * opens): the grant ID for managed grants, `toml:<index>` for config grants.
 */
export function auditGrantRef(grant: AuditRecord["matchedGrant"]) {
  if (!grant) return null;
  if (grant.grantId) return grant.grantId;
  return typeof grant.configIndex === "number" ? `toml:${grant.configIndex}` : null;
}

/** A matched grant's name for display: its ID, or its config position. */
export function auditGrantName(grant: NonNullable<AuditRecord["matchedGrant"]>) {
  return grant.grantId ?? (grant.configIndex != null ? `config grant #${grant.configIndex}` : "matched grant");
}

const DAY_SUB = new Intl.DateTimeFormat("en-US", { weekday: "long", month: "short", day: "numeric" });
const DAY_SUB_YEAR = new Intl.DateTimeFormat("en-US", { weekday: "long", month: "short", day: "numeric", year: "numeric" });
const WEEKDAY = new Intl.DateTimeFormat("en-US", { weekday: "long" });
const SHORT_DATE = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" });
const SHORT_DATE_YEAR = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", year: "numeric" });

function localDayStart(date: Date) {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
}

/** A local calendar day's list heading: Today, Yesterday, the weekday within a week, else the date. */
export function auditDayTitle(date: Date, now: number) {
  const today = new Date(now);
  const sameYear = date.getFullYear() === today.getFullYear();
  const sub = (sameYear ? DAY_SUB : DAY_SUB_YEAR).format(date);
  const days = Math.round((localDayStart(today) - localDayStart(date)) / 86_400_000);
  if (days === 0) return { title: "Today", sub };
  if (days === 1) return { title: "Yesterday", sub };
  if (days > 1 && days < 7) return { title: WEEKDAY.format(date), sub };
  return { title: (sameYear ? SHORT_DATE : SHORT_DATE_YEAR).format(date), sub };
}

export type AuditDayGroup<T> = { key: string; title: string; sub: string; records: T[] };

/** Consecutive records grouped by local calendar day, in the order given (newest first). */
export function auditDayGroups<T extends Pick<AuditRecord, "timestamp">>(records: T[], now: number): AuditDayGroup<T>[] {
  const groups: AuditDayGroup<T>[] = [];
  for (const record of records) {
    const micros = auditTimestampMicros(record.timestamp);
    const date = new Date(micros === null ? Number.NaN : Math.floor(micros / 1000));
    const valid = !Number.isNaN(date.getTime());
    const key = valid ? `${date.getFullYear()}-${date.getMonth() + 1}-${date.getDate()}` : "unknown";
    let group = groups[groups.length - 1];
    if (!group || group.key !== key) {
      group = { key, ...(valid ? auditDayTitle(date, now) : { title: "Unknown time", sub: "" }), records: [] };
      groups.push(group);
    }
    group.records.push(record);
  }
  return groups;
}

/** Maps the caller's own token IDs to token names. */
export function auditTokenNames(tokens: Pick<BrokerTokenRecord, "tokenId" | "name">[]) {
  return new Map(tokens.map((token) => [token.tokenId, token.name]));
}

/** The identity source name the broker records for portal browser sessions. */
export const AUDIT_BROWSER_SESSION_SOURCE = "browser-session";

/**
 * Whether the record came through a portal browser session: the broker's
 * `browser-session` source of type `broker_tokens`, presented by cookie
 * (`tokenHeader` "Cookie", `tokenScheme` "cookie"). A configured token source
 * may share the name, so the name alone is not enough.
 */
export function auditIsBrowserSession(source: AuditRecord["identitySource"]): boolean {
  return (
    source?.type === "broker_tokens" &&
    source.name === AUDIT_BROWSER_SESSION_SOURCE &&
    source.tokenHeader === "Cookie" &&
    source.tokenScheme === "cookie"
  );
}

/** The record's token: its name when the caller's token list has it, otherwise only its ID.
 * `browserSession` marks records made through a portal sign-in rather than an issued token. */
export function auditTokenLabel(record: Pick<AuditRecord, "identitySource">, names: Map<string, string>) {
  const id = record.identitySource?.tokenId || null;
  if (!id) return { id: null, name: null, browserSession: false };
  return { id, name: names.get(id) ?? null, browserSession: auditIsBrowserSession(record.identitySource) };
}

/** An RFC 3339 timestamp as UTC epoch microseconds (sub-millisecond digits kept), or null. */
export function auditTimestampMicros(timestamp: string) {
  const match = /^(.+T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/i.exec(timestamp.trim());
  if (!match) {
    const time = Date.parse(timestamp);
    return Number.isNaN(time) ? null : time * 1000;
  }
  const [, head, fraction = "", zone] = match;
  const seconds = Date.parse(`${head}${zone}`);
  if (Number.isNaN(seconds)) return null;
  return seconds * 1000 + Number(fraction.padEnd(6, "0").slice(0, 6));
}

/** Microseconds between each record and the one before it (null for the first). */
export function auditTimelineGaps(records: Pick<AuditRecord, "timestamp">[]) {
  return records.map((record, index) => {
    if (index === 0) return null;
    const current = auditTimestampMicros(record.timestamp);
    const previous = auditTimestampMicros(records[index - 1].timestamp);
    return current === null || previous === null ? null : current - previous;
  });
}

export function formatAuditGap(micros: number) {
  const sign = micros < 0 ? "-" : "+";
  const value = Math.abs(micros);
  if (value < 1000) return `${sign}${(value / 1000).toFixed(3)} ms`;
  const ms = value / 1000;
  if (ms < 1000) return `${sign}${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${sign}${seconds.toFixed(seconds < 10 ? 2 : 1)} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${sign}${minutes} min ${Math.round(seconds % 60)} s`;
  return `${sign}${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

/** The UTC instant with microseconds (the stored precision). */
export function formatAuditUtc(timestamp: string) {
  const micros = auditTimestampMicros(timestamp);
  if (micros === null) return timestamp;
  const iso = new Date(Math.floor(micros / 1000)).toISOString();
  const fraction = String(((micros % 1_000_000) + 1_000_000) % 1_000_000).padStart(6, "0");
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)}.${fraction} UTC`;
}

/** A datetime-local input value (local wall time, seconds) for an instant, or "". */
export function auditInstantToLocalInput(value: string) {
  const time = Date.parse(value);
  if (!value || Number.isNaN(time)) return "";
  const date = new Date(time);
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/** A datetime-local input value (local wall time) as an RFC 3339 UTC instant, or "". */
export function auditLocalInputToInstant(value: string) {
  if (!value) return "";
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? "" : new Date(time).toISOString();
}
