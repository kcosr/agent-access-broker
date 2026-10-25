import { describe, expect, test } from "vitest";
import type { AuditRecord, Session } from "../src/types";
import { canViewActivity, canViewAudit } from "../src/lib/helpers";
import {
  AUDIT_INPUT_PREVIEW_CHARS,
  AUDIT_PAGE_SIZE,
  DEFAULT_AUDIT_FILTERS,
  auditActionAfterServiceChange,
  auditActionSuggestions,
  auditActiveFilterCount,
  auditContinuationParams,
  auditDayGroups,
  auditDisplayText,
  auditFiltersProblem,
  auditFiltersSearch,
  auditGitRefUpdates,
  auditGrantName,
  auditGrantRef,
  auditInputDisplay,
  auditInputPreview,
  auditInputs,
  auditInstantToLocalInput,
  auditListParams,
  auditListPath,
  auditLocalInputToInstant,
  auditPageSearch,
  auditPrincipalSuggestions,
  auditRangeCovering,
  auditRecordPath,
  auditRecordPhase,
  auditServiceSuggestions,
  auditTokenPath,
  auditTimelineGaps,
  auditTokenLabel,
  auditTokenNames,
  auditUpstreamSummary,
  formatAuditGap,
  formatAuditUtc,
  isAuditRequestId,
  parseAuditFilters,
  parseAuditOpen,
  resolveAuditRange,
  showAuditNodeColumn,
  type AuditFilters,
} from "../src/lib/audit";
import { ADVERSARIAL_SEARCH, GITLAB_ISSUE_SEARCH, GITLAB_ISSUE_VIEW, JIRA_COMMENT_VIEW, JIRA_ISSUE_CREATE, JIRA_PROJECT_LIST, JIRA_SEARCH, TRUNCATED_SUMMARY } from "./audit-inputs.fixture";

const admin: Session = { role: "admin", selfServiceEnabled: true, authenticated: true, principal: "admin",  auditQueryable: true };
const manager: Session = { role: "service_policy_manager", selfServiceEnabled: true, authenticated: true, principal: "owner", policyManagementServices: ["jira"], auditQueryable: true };
const user: Session = { role: "user", selfServiceEnabled: true, authenticated: true, principal: "alice", auditQueryable: true };

function record(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    auditId: "0192-a",
    nodeId: "node-a",
    timestamp: "2026-09-26T12:00:00.000000+00:00",
    agentRequestId: "agent-1",
    brokerRequestId: "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a3b",
    principal: "alice",
    service: "jira",
    action: "issue.view",
    decision: "allow",
    ...overrides,
  };
}

describe("audit visibility", () => {
  test("Activity needs a queryable audit store and a signed-in user", () => {
    for (const session of [admin, manager, user]) {
      expect(canViewActivity(session)).toBe(true);
      expect(canViewActivity({ ...session, auditQueryable: false })).toBe(false);
    }
    expect(canViewActivity({ authenticated: false, auditQueryable: true })).toBe(false);
  });

  test("Audit is for admins and service policy managers with a queryable store", () => {
    expect(canViewAudit(admin)).toBe(true);
    expect(canViewAudit(manager)).toBe(true);
    expect(canViewAudit(user)).toBe(false);
    expect(canViewAudit({ ...admin, auditQueryable: false })).toBe(false);
  });
});

describe("audit filter URL state", () => {
  test("defaults serialize to an empty query string", () => {
    expect(auditFiltersSearch(DEFAULT_AUDIT_FILTERS, "admin")).toBe("");
    expect(parseAuditFilters("", "admin")).toEqual(DEFAULT_AUDIT_FILTERS);
  });

  test("filters round-trip through the query string", () => {
    const filters: AuditFilters = {
      ...DEFAULT_AUDIT_FILTERS,
      range: "7d",
      principal: "alice",
      service: "jira",
      action: "admin.policy.*",
      decision: "deny",
      reasonCode: "service_action_denied",
      phase: "preflight",
      tokenId: "tok-1",
      requestId: "req-1",
      node: "broker-1",
      q: '"exact phrase" pre*',
    };
    const search = auditFiltersSearch(filters, "admin");
    expect(search).toBe(
      "?range=7d&principal=alice&service=jira&action=admin.policy.*&decision=deny&reasonCode=service_action_denied&phase=preflight&tokenId=tok-1&requestId=req-1&node=broker-1&q=%22exact+phrase%22+pre*"
    );
    expect(parseAuditFilters(search, "admin")).toEqual(filters);
  });

  test("Service filters the raw service column and never restores the old related-service key", () => {
    const filters = parseAuditFilters("?service=broker&scopeService=jira", "admin");
    expect(filters.service).toBe("broker");
    expect(auditListParams(filters, { from: null, to: null }, "admin")).toEqual({ service: "broker", limit: String(AUDIT_PAGE_SIZE) });
    expect(auditFiltersSearch(filters, "admin")).toBe("?service=broker");
    expect(parseAuditFilters("?scopeService=jira", "admin")).toEqual(DEFAULT_AUDIT_FILTERS);
  });

  test("custom ranges keep absolute UTC bounds and are implied by from/to", () => {
    const custom = { ...DEFAULT_AUDIT_FILTERS, range: "custom" as const, from: "2026-09-01T00:00:00.000Z", to: "2026-09-02T12:30:00.000Z" };
    const search = auditFiltersSearch(custom, "self");
    expect(search).toBe("?range=custom&from=2026-09-01T00%3A00%3A00.000Z&to=2026-09-02T12%3A30%3A00.000Z");
    expect(parseAuditFilters(search, "self")).toEqual(custom);
    expect(parseAuditFilters("?from=2026-09-01T02:00:00%2B02:00", "self")).toMatchObject({ range: "custom", from: "2026-09-01T00:00:00.000Z", to: "" });
    expect(parseAuditFilters("?range=custom", "self")).toMatchObject({ range: "custom", from: "", to: "" });
    // Presets ignore stray bounds.
    expect(parseAuditFilters("?range=1h&from=2026-09-01T00:00:00Z", "self")).toMatchObject({ range: "1h", from: "" });
  });

  test("invalid values fall back and Activity never restores a principal", () => {
    const parsed = parseAuditFilters("?range=2y&decision=maybe&phase=later&from=yesterday&principal=bob&q=%20%20", "self");
    expect(parsed).toEqual(DEFAULT_AUDIT_FILTERS);
    expect(auditFiltersSearch({ ...DEFAULT_AUDIT_FILTERS, principal: "bob" }, "self")).toBe("");
    expect(parseAuditFilters("?principal=bob", "admin").principal).toBe("bob");
  });

  test("viewer links combine filters over the defaults", () => {
    expect(auditListPath("admin", { principal: "alice" })).toBe("/ui/admin/audit?principal=alice");
    expect(auditListPath("self", { tokenId: "tok 1", range: "1h" })).toBe("/ui/activity?range=1h&tokenId=tok+1");
    const now = Date.parse("2026-09-26T12:00:00.000Z");
    expect(auditTokenPath("self", { tokenId: "tok-1", lastUsedAt: "2026-09-26T11:50:00.000Z" }, now)).toBe("/ui/activity?range=1h&tokenId=tok-1");
  });

  test("the open record lives next to the filters and needs its request", () => {
    const open = { request: "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a3b", record: "0192-a" };
    const search = auditPageSearch({ ...DEFAULT_AUDIT_FILTERS, service: "jira" }, "admin", open);
    expect(search).toBe("?service=jira&request=5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a3b&record=0192-a");
    expect(parseAuditOpen(search)).toEqual(open);
    expect(parseAuditFilters(search, "admin")).toEqual({ ...DEFAULT_AUDIT_FILTERS, service: "jira" });
    expect(parseAuditOpen("?record=0192-a")).toEqual({ request: "", record: "" });
    expect(parseAuditOpen("?request=abc")).toEqual({ request: "abc", record: "" });
    expect(auditPageSearch(DEFAULT_AUDIT_FILTERS, "self")).toBe("");
    expect(auditPageSearch(DEFAULT_AUDIT_FILTERS, "self", { request: "", record: "x" })).toBe("");
  });

  test("record links open the drawer with a range that covers the record", () => {
    const now = Date.parse("2026-09-26T12:00:00.000Z");
    const target = { brokerRequestId: "req-1", auditId: "a-1", timestamp: "2026-09-24T12:00:00.000Z" };
    expect(auditRecordPath("admin", target, {}, now)).toBe("/ui/admin/audit?range=7d&request=req-1&record=a-1");
    expect(auditRecordPath("admin", target, { principal: "alice", requestId: "req-1" }, now)).toBe(
      "/ui/admin/audit?range=7d&principal=alice&requestId=req-1&request=req-1&record=a-1"
    );
    expect(auditRecordPath("self", { ...target, timestamp: "2026-09-26T11:30:00.000Z" }, {}, now)).toBe("/ui/activity?range=1h&request=req-1&record=a-1");
  });

  test("active filters count every non-default facet and a non-default range", () => {
    expect(auditActiveFilterCount(DEFAULT_AUDIT_FILTERS)).toBe(0);
    expect(auditActiveFilterCount({ ...DEFAULT_AUDIT_FILTERS, range: "7d", decision: "deny", q: "x", node: " " })).toBe(3);
  });

  test("datetime-local values convert between local wall time and UTC instants", () => {
    const instant = auditLocalInputToInstant("2026-09-26T08:15:30");
    expect(instant).toBe(new Date(2026, 8, 26, 8, 15, 30).toISOString());
    expect(auditInstantToLocalInput(instant)).toBe("2026-09-26T08:15:30");
    expect(auditLocalInputToInstant("")).toBe("");
    expect(auditInstantToLocalInput("")).toBe("");
  });

  test("an inverted custom range is reported before querying", () => {
    expect(auditFiltersProblem({ ...DEFAULT_AUDIT_FILTERS, range: "custom", from: "2026-09-02T00:00:00.000Z", to: "2026-09-01T00:00:00.000Z" })).toMatch(/must not be after/);
    expect(auditFiltersProblem({ ...DEFAULT_AUDIT_FILTERS, range: "custom", from: "2026-09-01T00:00:00.000Z" })).toBeNull();
    expect(auditFiltersProblem({ ...DEFAULT_AUDIT_FILTERS, q: "x".repeat(257) })).toMatch(/256/);
  });
});

describe("audit suggestions", () => {
  const sources = [
    { service: "broker", actions: ["auth.local.login", "auth.logout", "admin.policy.grants.create", "tokens.issue"] },
    { service: "jira", actions: ["issue.view", "issue.comment.add"] },
  ];

  test("Broker is always the first suggestion, followed by configured services by raw ID", () => {
    expect(auditServiceSuggestions([], []).map((option) => option.value)).toEqual(["broker"]);
    const options = auditServiceSuggestions(
      [{ service: "jira", displayName: "Jira Cloud" }, { service: "confluence", displayName: "confluence" }, { service: "broker" }],
      sources.filter((source) => source.service === "broker")
    );
    expect(options.map((option) => option.value)).toEqual(["broker", "confluence", "jira"]);
    // Labels are the raw IDs the filter sends; display names describe them and match typed text.
    expect(options.map((option) => option.label)).toEqual(["broker", "confluence", "jira"]);
    expect(options[2]).toEqual({ value: "jira", label: "jira", description: "Jira Cloud", keywords: ["Jira Cloud"] });
    expect(options[1]).toEqual({ value: "confluence", label: "confluence" });
  });

  test("principal suggestions are raw principal IDs described by display names", () => {
    expect(
      auditPrincipalSuggestions([
        { principalId: "bob", displayName: "Bob Example" },
        { principalId: "alice", displayName: "alice" },
        { principalId: "bob", displayName: "Duplicate" },
        { principalId: null, displayName: "No ID" }
      ])
    ).toEqual([
      { value: "alice", label: "alice" },
      { value: "bob", label: "bob", description: "Bob Example", keywords: ["Bob Example"] }
    ]);
  });

  test("canonical broker and configured actions come from the selected raw service, with valid prefix families", () => {
    expect(auditActionSuggestions(sources, "broker")).toEqual([
      "admin.*", "admin.policy.*", "admin.policy.grants.*", "admin.policy.grants.create",
      "auth.*", "auth.local.*", "auth.local.login", "auth.logout", "tokens.*", "tokens.issue",
    ]);
    expect(auditActionSuggestions(sources, "jira")).not.toContain("admin.policy.grants.create");
    expect(auditActionSuggestions(sources, "")).toContain("issue.view");
    expect(auditActionSuggestions(sources, "retired")).toEqual([]);
  });

  test("service changes clear incompatible known actions but preserve manual values and matching prefixes", () => {
    expect(auditActionAfterServiceChange("auth.*", "jira", sources)).toBe("");
    expect(auditActionAfterServiceChange("issue.view", "broker", sources)).toBe("");
    expect(auditActionAfterServiceChange("auth.*", "broker", sources)).toBe("auth.*");
    expect(auditActionAfterServiceChange("issue.view", "", sources)).toBe("issue.view");
    expect(auditActionAfterServiceChange("unobserved.action", "broker", sources)).toBe("unobserved.action");
    expect(auditActionAfterServiceChange("historical.*", "retired", sources)).toBe("historical.*");
  });
});

describe("audit paging sessions", () => {
  const now = Date.parse("2026-09-26T12:00:00.000Z");

  test("presets resolve to absolute UTC bounds at the moment the session starts", () => {
    expect(resolveAuditRange({ range: "1h", from: "", to: "" }, now)).toEqual({ from: "2026-09-26T11:00:00.000Z", to: null });
    expect(resolveAuditRange({ range: "24h", from: "", to: "" }, now)).toEqual({ from: "2026-09-25T12:00:00.000Z", to: null });
    expect(resolveAuditRange({ range: "7d", from: "", to: "" }, now).from).toBe("2026-09-19T12:00:00.000Z");
    expect(resolveAuditRange({ range: "30d", from: "", to: "" }, now).from).toBe("2026-08-27T12:00:00.000Z");
    expect(resolveAuditRange({ range: "custom", from: "2026-09-01T00:00:00.000Z", to: "" }, now)).toEqual({ from: "2026-09-01T00:00:00.000Z", to: null });
  });

  test("the first page sends resolved bounds and non-empty filters; continuations send only the cursor", () => {
    const filters = { ...DEFAULT_AUDIT_FILTERS, principal: "alice", decision: "deny" as const, action: " ", q: "denied" };
    const range = resolveAuditRange(filters, now);
    expect(auditListParams(filters, range, "admin")).toEqual({
      from: "2026-09-25T12:00:00.000Z",
      principal: "alice",
      decision: "deny",
      q: "denied",
      limit: String(AUDIT_PAGE_SIZE),
    });
    expect(auditListParams(filters, range, "self")).not.toHaveProperty("principal");
    expect(auditListParams(DEFAULT_AUDIT_FILTERS, { from: null, to: null }, "self")).toEqual({ limit: String(AUDIT_PAGE_SIZE) });
    expect(auditContinuationParams("eyJ")).toEqual({ cursor: "eyJ", limit: String(AUDIT_PAGE_SIZE) });
  });

  test("token links pick the smallest preset that covers the last use", () => {
    const minutesAgo = (minutes: number) => new Date(now - minutes * 60_000).toISOString();
    expect(auditRangeCovering(minutesAgo(5), now)).toEqual({ range: "1h", from: "", to: "" });
    expect(auditRangeCovering(minutesAgo(90), now).range).toBe("24h");
    expect(auditRangeCovering(minutesAgo(3 * 24 * 60), now).range).toBe("7d");
    expect(auditRangeCovering(minutesAgo(20 * 24 * 60), now).range).toBe("30d");
    expect(auditRangeCovering(minutesAgo(40 * 24 * 60), now)).toEqual({ range: "custom", from: "", to: "" });
    expect(auditRangeCovering(null, now).range).toBe("24h");
  });
});

describe("audit record presentation", () => {
  test("token names come from the caller's token list; unknown IDs stay IDs", () => {
    const names = auditTokenNames([{ tokenId: "tok-1", name: "ci-agent" }]);
    expect(auditTokenLabel(record({ identitySource: { name: "broker", type: "broker_tokens", tokenId: "tok-1" } }), names)).toEqual({ id: "tok-1", name: "ci-agent", browserSession: false });
    expect(auditTokenLabel(record({ identitySource: { name: "broker", type: "broker_tokens", tokenId: "deleted" } }), names)).toEqual({ id: "deleted", name: null, browserSession: false });
    expect(auditTokenLabel(record({ identitySource: { name: "browser-session", type: "broker_tokens", tokenId: "session-1" } }), names)).toEqual({ id: "session-1", name: null, browserSession: true });
    expect(auditTokenLabel(record({ identitySource: null }), names)).toEqual({ id: null, name: null, browserSession: false });
  });

  test("the node column appears only for records from more than one node", () => {
    expect(showAuditNodeColumn([])).toBe(false);
    expect(showAuditNodeColumn([record(), record({ auditId: "b" })])).toBe(false);
    expect(showAuditNodeColumn([record(), record({ auditId: "b", nodeId: "node-b" })])).toBe(true);
  });

  test("phase uses the first present indexed field", () => {
    expect(auditRecordPhase(record())).toBeNull();
    expect(auditRecordPhase(record({ providerAudit: { streamPhase: "started", management: { phase: "success" } } }))).toBe("started");
    expect(auditRecordPhase(record({ providerAudit: { gateway: { phase: "completed" }, gatewayPhase: "failed" } }))).toBe("completed");
    expect(auditRecordPhase(record({ providerAudit: { gatewayPhase: "failed" } }))).toBe("failed");
    expect(auditRecordPhase(record({ providerAudit: { management: { phase: "preflight" }, failurePhase: "x" } }))).toBe("preflight");
  });

  test("upstream shows only fields the record has, including gateway response bytes", () => {
    expect(auditUpstreamSummary(record())).toBe("");
    expect(auditUpstreamSummary(record({ upstreamStatus: 200, upstreamDurationMs: 35 }))).toBe("200 · 35 ms");
    expect(auditUpstreamSummary(record({ upstreamStatus: 200, providerAudit: { gateway: { responseBytes: 2048 } } }))).toBe("200 · 2.0 KB");
  });

  test("git ref updates come from providerAudit.git.updates", () => {
    const updates = auditGitRefUpdates(record({ providerAudit: { git: { updates: [{ ref: "refs/heads/main", oldId: "a".repeat(40), newId: "b".repeat(40), create: false, delete: false }, { nope: true }] } } }));
    expect(updates).toEqual([{ ref: "refs/heads/main", oldId: "a".repeat(40), newId: "b".repeat(40), create: false, delete: false }]);
    expect(auditGitRefUpdates(record())).toEqual([]);
  });

  test("timeline gaps are computed from timestamps with microsecond precision", () => {
    const records = [
      record({ timestamp: "2026-09-26T12:00:00.000100+00:00" }),
      record({ timestamp: "2026-09-26T12:00:00.000600+00:00" }),
      record({ timestamp: "2026-09-26T12:00:01.250600Z" }),
      record({ timestamp: "2026-09-26T14:00:01.2506+02:00" }),
    ];
    expect(auditTimelineGaps(records)).toEqual([null, 500, 1_250_000, 0]);
    expect(formatAuditGap(500)).toBe("+0.500 ms");
    expect(formatAuditGap(4_200)).toBe("+4.2 ms");
    expect(formatAuditGap(1_250_000)).toBe("+1.25 s");
    expect(formatAuditGap(125_000_000)).toBe("+2 min 5 s");
    expect(formatAuditUtc("2026-09-26T14:03:12.123456789+02:00")).toBe("2026-09-26 12:03:12.123456 UTC");
  });

  test("matched grants open by grant reference: the grant ID, or toml:<index> for config grants", () => {
    expect(auditGrantRef({ grantId: "jira-readers", configIndex: 3 })).toBe("jira-readers");
    expect(auditGrantRef({ grantId: null, configIndex: 0 })).toBe("toml:0");
    expect(auditGrantRef({})).toBeNull();
    expect(auditGrantRef(null)).toBeNull();
    expect(auditGrantName({ configIndex: 2 })).toBe("config grant #2");
    expect(auditGrantName({})).toBe("matched grant");
  });

  test("records group by local calendar day, newest first", () => {
    const now = new Date(2026, 8, 28, 15, 0, 0).getTime();
    const at = (day: number, hour: number) => record({ auditId: `${day}-${hour}`, timestamp: new Date(2026, 8, day, hour, 30).toISOString() });
    const groups = auditDayGroups([at(28, 14), at(28, 1), at(27, 23), at(24, 9), at(12, 9), record({ auditId: "bad", timestamp: "nope" })], now);
    expect(groups.map((group) => [group.title, group.records.map((item) => item.auditId)])).toEqual([
      ["Today", ["28-14", "28-1"]],
      ["Yesterday", ["27-23"]],
      ["Thursday", ["24-9"]],
      ["Sep 12", ["12-9"]],
      ["Unknown time", ["bad"]]
    ]);
    expect(groups[0]!.sub).toBe("Monday, Sep 28");
    expect(auditDayGroups([record({ timestamp: new Date(2025, 11, 31, 12).toISOString() })], now)[0]).toMatchObject({ title: "Dec 31, 2025", sub: "Wednesday, Dec 31, 2025" });
  });

  test("timelines exist only for UUID request IDs", () => {
    expect(isAuditRequestId("5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a3b")).toBe(true);
    expect(isAuditRequestId("5f0c2c3e6a4b4a8e9a550d4c8e1f2a3b")).toBe(true);
    expect(isAuditRequestId("not-a-uuid")).toBe(false);
  });
});

describe("audit inputs", () => {
  const withInputs = (entries: unknown) => record({ auditInputs: entries as AuditRecord["auditInputs"] });

  test("each action's captured inputs keep declaration order and their stored JSON values", () => {
    expect(auditInputs(JIRA_SEARCH)).toEqual([
      { input: "query", label: "Query", value: { type: "jql", value: 'project = OPS AND status = "In Progress"' }, truncated: false },
      { input: "projects", label: "Projects", value: ["OPS"], truncated: false },
    ]);
    expect(auditInputs(JIRA_ISSUE_CREATE)).toEqual([
      { input: "project", label: "Project", value: "OPS", truncated: false },
      { input: "summary", label: "Summary", value: TRUNCATED_SUMMARY, truncated: true },
    ]);
    expect(new TextEncoder().encode(TRUNCATED_SUMMARY).byteLength).toBe(1024);
    expect(auditInputs(JIRA_COMMENT_VIEW).map((entry) => [entry.label, entry.value])).toEqual([["Issue", "OPS-42"], ["Comment ID", "18446744073709551615"]]);
    expect(auditInputs(GITLAB_ISSUE_SEARCH).map((entry) => [entry.label, entry.value])).toEqual([["Project", "platform/api"], ["Search", ADVERSARIAL_SEARCH], ["State", "opened"], ["Milestone", null]]);
    // The record's two malformed entries are skipped.
    expect(auditInputs(GITLAB_ISSUE_VIEW)).toEqual([
      { input: "project", label: "Project", value: "platform/api", truncated: false },
      { input: "iid", label: "Issue", value: 42, truncated: false },
    ]);
    expect(auditInputs(JIRA_PROJECT_LIST)).toEqual([]);
  });

  test("records without inputs, or with malformed ones, show none", () => {
    expect(auditInputs(record())).toEqual([]);
    expect(auditInputs(withInputs({ input: "project", label: "Project", value: "OPS" }))).toEqual([]);
    expect(auditInputs(withInputs([
      null, "project", 7, ["project", "Project", "OPS"],
      { label: "Project", value: "OPS" },
      { input: "", label: "Project", value: "OPS" },
      { input: 1, label: "Project", value: "OPS" },
      { input: "project", value: "OPS" },
      { input: "project", label: "", value: "OPS" },
      { input: "project", label: ["Project"], value: "OPS" },
      { input: "project", label: "Project" },
    ]))).toEqual([]);
  });

  test("only a literal true marks a value truncated", () => {
    const flags = auditInputs(withInputs([true, "true", 1, null].map((truncated, index) => ({ input: `field${index}`, label: "Field", value: "x", truncated }))));
    expect(flags.map((entry) => entry.truncated)).toEqual([true, false, false, false]);
  });

  test("search queries show their value, with the language as a badge except for text", () => {
    expect(auditInputDisplay({ type: "jql", value: 'project = OPS AND status = "In Progress"' })).toEqual({ badge: "JQL", lines: ['project = OPS AND status = "In Progress"'], json: false });
    expect(auditInputDisplay({ type: "cql", value: 'space = DOCS AND title ~ "runbook"' })).toEqual({ badge: "CQL", lines: ['space = DOCS AND title ~ "runbook"'], json: false });
    expect(auditInputDisplay({ type: "text", value: "checkout timeout" })).toEqual({ badge: null, lines: ["checkout timeout"], json: false });
    expect(auditInputDisplay({ value: "project = OPS", type: "jql" })).toEqual({ badge: "JQL", lines: ["project = OPS"], json: false });
    expect(auditInputDisplay({ type: "", value: "checkout timeout" }).badge).toBeNull();
  });

  test("other flat objects show one key: value line per key, strings literal; nested values fall back to compact JSON", () => {
    expect(auditInputDisplay({ type: "jql", value: "project = OPS", validate: true })).toEqual({ badge: null, lines: ["type: jql", "value: project = OPS", "validate: true"], json: false });
    expect(auditInputDisplay({ type: "jql", value: 42 })).toEqual({ badge: null, lines: ["type: jql", "value: 42"], json: false });
    expect(auditInputDisplay({ state: "opened", count: 3, confidential: false, milestone: null, title: 'Fix "login"' }).lines).toEqual(["state: opened", "count: 3", "confidential: false", "milestone: null", 'title: Fix "login"']);
    expect(auditInputDisplay({ summary: "x".repeat(120), state: "opened" }).lines.map(auditInputPreview)).toEqual([`summary: ${"x".repeat(90)}…`, "state: opened"]);
    expect(auditInputDisplay({ type: "jql", filter: { project: "OPS" } })).toEqual({ badge: null, lines: ['{"type":"jql","filter":{"project":"OPS"}}'], json: true });
    expect(auditInputDisplay({ type: "jql", value: ["OPS"] }).lines).toEqual(['{"type":"jql","value":["OPS"]}']);
    expect(auditInputDisplay({}).lines).toEqual(["{}"]);
  });

  test("arrays of strings, numbers and booleans read as lists; empty arrays as (none); others as compact JSON", () => {
    expect(auditInputDisplay(["OPS", "SEC"])).toEqual({ badge: null, lines: ["OPS, SEC"], json: false });
    expect(auditInputDisplay(["OPS", 42, true, false]).lines).toEqual(["OPS, 42, true, false"]);
    expect(auditInputDisplay([])).toEqual({ badge: null, lines: ["(none)"], json: false });
    expect(auditInputDisplay(["OPS", { key: "SEC" }])).toEqual({ badge: null, lines: ['["OPS",{"key":"SEC"}]'], json: true });
    expect(auditInputDisplay(["OPS", ["SEC"]]).lines).toEqual(['["OPS",["SEC"]]']);
    expect(auditInputDisplay(["OPS", null]).lines).toEqual(['["OPS",null]']);
  });

  test("strings stay as stored; numbers, booleans and null read as JSON", () => {
    expect(auditInputDisplay('status = "In Progress"')).toEqual({ badge: null, lines: ['status = "In Progress"'], json: false });
    expect(auditInputDisplay(42)).toEqual({ badge: null, lines: ["42"], json: true });
    expect(auditInputDisplay(false).lines).toEqual(["false"]);
    expect(auditInputDisplay(null)).toEqual({ badge: null, lines: ["null"], json: true });
  });

  test("display text shows controls, bidi overrides and separators as escapes, keeping newlines", () => {
    expect(auditDisplayText(ADVERSARIAL_SEARCH)).toBe(`login timeout\n<script>alert("never")</script>\\u{1}\\u{202E}${"é".repeat(220)}`);
    expect(auditDisplayText("a\tb\r\u200Dc\u2028d\u2029e\u0000")).toBe("a\\u{9}b\\u{D}\\u{200D}c\\u{2028}d\\u{2029}e\\u{0}");
    expect(auditDisplayText("OPS-42 · ünïcödé 😀")).toBe("OPS-42 · ünïcödé 😀");
  });

  test("previews are one line of at most 100 code points, cut with an ellipsis", () => {
    expect(auditInputPreview("OPS")).toBe("OPS");
    expect(auditInputPreview("first line\n\n  second\tline\r\nthird")).toBe("first line second line third");
    expect(auditInputPreview("x".repeat(AUDIT_INPUT_PREVIEW_CHARS))).toBe("x".repeat(AUDIT_INPUT_PREVIEW_CHARS));
    expect(auditInputPreview("x".repeat(AUDIT_INPUT_PREVIEW_CHARS + 1))).toBe(`${"x".repeat(AUDIT_INPUT_PREVIEW_CHARS - 1)}…`);
    const emoji = auditInputPreview("😀".repeat(150));
    expect(emoji).toBe(`${"😀".repeat(AUDIT_INPUT_PREVIEW_CHARS - 1)}…`);
    expect(Array.from(emoji)).toHaveLength(AUDIT_INPUT_PREVIEW_CHARS);
    expect(auditInputPreview(ADVERSARIAL_SEARCH)).toBe(`login timeout <script>alert("never")</script>\\u{1}\\u{202E}${"é".repeat(41)}…`);
  });
});
