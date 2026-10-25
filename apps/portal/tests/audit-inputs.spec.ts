// Mocked API contract for the audit drawer's Summary tab: synthetic stored
// records, one per action, and no Broker. The Broker's own tests cover capture.
import { expect, test, type Locator, type Page } from "@playwright/test";
import type { AuditRecord } from "../src/types";
import {
  AUDIT_INPUT_RECORDS,
  BROKER_GRANT_UPDATE,
  CONFLUENCE_PAGE_VIEW,
  GITLAB_ISSUE_SEARCH,
  GITLAB_ISSUE_VIEW,
  JIRA_COMMENT_VIEW,
  JIRA_ISSUE_CREATE,
  JIRA_PROJECT_LIST,
  JIRA_SEARCH,
  JIRA_TEXT_SEARCH,
  TRUNCATED_SUMMARY
} from "../unit/audit-inputs.fixture";
import { RESOURCE_TYPES } from "../unit/resource-types.fixture";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

/** The adversarial search's preview: whitespace collapsed, controls escaped, 99 code points and an ellipsis. */
const SEARCH_PREVIEW = `login timeout <script>alert("never")</script>\\u{1}\\u{202E}${"é".repeat(41)}…`;

/** Each record's Inputs rows as [label, shown value]. */
const ROWS: [AuditRecord, [string, string][]][] = [
  [CONFLUENCE_PAGE_VIEW, [["Page ID", "123456789"]]],
  [JIRA_SEARCH, [["Query", 'project = OPS AND status = "In Progress" JQL'], ["Projects", "OPS"]]],
  [JIRA_TEXT_SEARCH, [["Query", "checkout timeout"], ["Projects", "OPS, SEC"]]],
  [JIRA_ISSUE_CREATE, [["Project", "OPS"], ["Summary", `${TRUNCATED_SUMMARY.slice(0, 99)}…Truncated in record`]]],
  [JIRA_COMMENT_VIEW, [["Issue", "OPS-42"], ["Comment ID", "18446744073709551615"]]],
  [GITLAB_ISSUE_SEARCH, [["Project", "platform/api"], ["Search", SEARCH_PREVIEW], ["State", "opened"], ["Milestone", "null"]]],
  [GITLAB_ISSUE_VIEW, [["Project", "platform/api"], ["Issue", "42"]]]
];

const DECISION_LABELS: Record<AuditRecord["decision"], string> = { allow: "Allowed", deny: "Denied", error: "Error" };

/** The catalog names one user and two groups; `sam.lee` and `ops-oncall` stay IDs. */
const CATALOG = {
  services: [],
  subjects: {
    users: [{ principalId: "alice", displayName: "Alice Example", status: "active" }],
    groups: [{ groupId: "users", displayName: "All users", status: "active" }, { groupId: "admins", displayName: "Administrators", status: "active" }],
    anonymous: false
  },
  resources: [],
  resourceGroups: [],
  executionContexts: { allowedValues: ["default"], contextRequired: false }
};

let assets: PortalAssets;
test.beforeAll(async () => { assets = await servePortalAssets(); });
test.afterAll(async () => { await assets.close(); });

/** Opens one record's drawer in Audit; every record has its own broker request. */
async function openRecord(page: Page, record: AuditRecord) {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/v1/**", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    const envelope = (result: unknown) => ({ ok: true, decision: "allow", requestId: "fixture", brokerRequestId: "fixture", operation: "fixture", principal: "alice", result });
    let body: unknown;
    if (pathname === "/v1/auth/session") body = envelope({ role: "admin", selfServiceEnabled: true, authenticated: true, principal: "alice", policyManagementServices: [], auditQueryable: true });
    else if (/\/audit\/options$/.test(pathname)) body = envelope({ services: [] });
    else if (/\/audit\/events$/.test(pathname)) body = envelope({ items: AUDIT_INPUT_RECORDS, nextCursor: null });
    else if (/\/audit\/requests\//.test(pathname)) {
      const id = decodeURIComponent(pathname.split("/").pop()!);
      body = envelope({ brokerRequestId: id, items: AUDIT_INPUT_RECORDS.filter((item) => item.brokerRequestId === id) });
    }
    else if (pathname === "/v1/resource-types") body = { resourceTypes: RESOURCE_TYPES };
    else if (pathname === "/v1/admin/policy/catalog") body = envelope(CATALOG);
    else if (pathname === "/v1/tokens/options") body = envelope({ policyGeneration: 1, resources: [], resourceGroups: [], executionContexts: [], services: [] });
    else if (pathname === "/v1/credentials") body = envelope({ connections: [], retained: [] });
    else body = envelope([]);
    await route.fulfill({ json: body });
  });
  await page.goto(`${assets.baseUrl}/ui/admin/audit?request=${record.brokerRequestId}&record=${record.auditId}`);
  const drawer = page.getByRole("complementary", { name: `${DECISION_LABELS[record.decision]}: ${record.action} on ${record.service}`, exact: true });
  await expect(drawer).toBeVisible();
  const section = (name: string) => drawer.getByRole("region", { name, exact: true });
  await expect(section("Request")).toBeVisible();
  return { drawer, section, inputs: section("Inputs"), errors };
}

/** The drawer's section headings, in order. */
function headings(drawer: Locator) {
  return drawer.getByRole("heading", { level: 3 }).allTextContents();
}

for (const [record, rows] of ROWS) {
  test(`${record.auditId}: Inputs come first with one row per recorded input`, async ({ page }, testInfo) => {
    const { drawer, inputs, errors } = await openRecord(page, record);
    expect((await headings(drawer))[0]).toBe("Inputs");
    await expect(inputs.getByRole("term")).toHaveText(rows.map(([label]) => label));
    await expect(inputs.getByRole("definition")).toHaveText(rows.map(([, value]) => value));
    await expect.poll(() => drawer.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
    await inputs.screenshot({ path: testInfo.outputPath(`inputs-${record.auditId}.png`) });
    expect(errors).toEqual([]);
  });
}

test("a search query shows its value with the language badge after it, while hover keeps the stored compact JSON", async ({ page }) => {
  const { inputs } = await openRecord(page, JIRA_SEARCH);
  const values = inputs.getByRole("definition");
  const query = values.nth(0).getByTitle('{"type":"jql","value":"project = OPS AND status = \\"In Progress\\""}', { exact: true });
  await expect(query.getByText("JQL", { exact: true })).toBeVisible();
  expect(await query.textContent()).toBe('project = OPS AND status = "In Progress" JQL');
  await expect(values.nth(1).getByTitle('["OPS"]', { exact: true })).toHaveText("OPS");
});

test("stored text is escaped, previewed without line breaks and complete on hover", async ({ page }) => {
  const { inputs } = await openRecord(page, GITLAB_ISSUE_SEARCH);
  const search = inputs.getByRole("definition").nth(1).getByTitle(/^login timeout/);
  await expect(search).toHaveAttribute("title", `login timeout\n<script>alert("never")</script>\\u{1}\\u{202E}${"é".repeat(220)}`);
  // toHaveText normalizes whitespace; textContent does not.
  expect(await search.textContent()).toBe(SEARCH_PREVIEW);
  await expect(inputs.locator("script")).toHaveCount(0);
});

test("a value cut to the 1 KiB bound is marked truncated and stored text is on hover", async ({ page }) => {
  const { inputs } = await openRecord(page, JIRA_ISSUE_CREATE);
  const summary = inputs.getByRole("definition").nth(1);
  await expect(summary.getByTitle(TRUNCATED_SUMMARY, { exact: true })).toBeVisible();
  await expect(summary.getByText("Truncated in record", { exact: true })).toBeVisible();
  await expect(inputs.getByText("Truncated in record", { exact: true })).toHaveCount(1);
});

test("records without inputs show no Inputs section", async ({ page }) => {
  const { drawer, inputs, errors } = await openRecord(page, JIRA_PROJECT_LIST);
  await expect(inputs).toHaveCount(0);
  await expect(drawer.getByRole("heading", { name: "Inputs", exact: true })).toHaveCount(0);
  expect(errors).toEqual([]);
});

test("Outcome follows Inputs with only what the header does not show", async ({ page }) => {
  const { drawer, section, errors } = await openRecord(page, CONFLUENCE_PAGE_VIEW);
  expect(await headings(drawer)).toEqual(["Inputs", "Outcome", "Identity", "Request"]);
  const outcome = section("Outcome");
  await expect(outcome.getByRole("term")).toHaveText(["Upstream", "Matched grant", "Credential mode"]);
  await expect(outcome.getByRole("definition")).toHaveText(["200 · 184 ms", "docs-readers", "per_user"]);
  await expect(outcome.getByRole("link", { name: "docs-readers", exact: true })).toBeVisible();
  // Decision, reason code and execution context are in the header only.
  await expect(drawer.getByRole("term").filter({ hasText: /^(Decision|Reason code|Execution context)$/ })).toHaveCount(0);
  expect(errors).toEqual([]);
});

test("a denial before any grant matched omits Outcome; the header carries decision, reason and context", async ({ page }) => {
  const { drawer, section } = await openRecord(page, JIRA_ISSUE_CREATE);
  expect(await headings(drawer)).toEqual(["Inputs", "Identity", "Request"]);
  await expect(section("Outcome")).toHaveCount(0);
  // Summary has no reason or context rows, so these come from the header.
  await expect(drawer.getByText("Denied", { exact: true }).first()).toBeVisible();
  await expect(drawer.getByText("grant_not_found", { exact: true })).toBeVisible();
  await expect(drawer.getByText("default", { exact: true })).toBeVisible();
});

test("Identity shows display names with IDs on hover and the identity source in words", async ({ page }) => {
  const { section } = await openRecord(page, CONFLUENCE_PAGE_VIEW);
  const identity = section("Identity");
  await expect(identity.getByRole("term")).toHaveText(["Principal", "Identity source", "Access path", "Groups"]);
  await expect(identity.getByRole("definition")).toHaveText(["Alice Example", "Trusted user · Agent invocation", "Read-only", "All users"]);
  await expect(identity.getByTitle("alice", { exact: true })).toHaveText("Alice Example");
  await expect(identity.getByTitle("trusted_user", { exact: true })).toHaveText("Trusted user · Agent invocation");
  await expect(identity.getByTitle("users", { exact: true })).toHaveText("All users");
  // The principal subject moved to Request › Details.
  await expect(identity).not.toContainText("alice@example.test");
});

test("issued tokens, browser sessions and unnamed principals or groups read as expected", async ({ page }) => {
  let { section } = await openRecord(page, JIRA_SEARCH);
  await expect(section("Identity").getByTitle("managed-agents", { exact: true })).toHaveText("Broker token · Agent invocation");
  await expect(section("Identity").getByRole("term")).toHaveText(["Principal", "Identity source", "Token", "Groups"]);

  ({ section } = await openRecord(page, JIRA_ISSUE_CREATE));
  const groups = section("Identity").getByRole("definition").last();
  await expect(groups).toHaveText("All users, ops-oncall");
  await expect(groups.getByTitle("users", { exact: true })).toHaveText("All users");
  await expect(groups.getByTitle("ops-oncall", { exact: true })).toHaveText("ops-oncall");

  ({ section } = await openRecord(page, BROKER_GRANT_UPDATE));
  const identity = section("Identity");
  await expect(identity.getByTitle("sam.lee", { exact: true })).toHaveText("sam.lee");
  await expect(identity.getByTitle("browser-session", { exact: true })).toHaveText("Browser session");
  await expect(identity.getByTitle("admins", { exact: true })).toHaveText("Administrators");
});

test("Request names each scope and object ID and keeps identifiers under a collapsed Details", async ({ page }) => {
  const { section, errors } = await openRecord(page, CONFLUENCE_PAGE_VIEW);
  const request = section("Request");
  await expect(request.getByRole("term")).toHaveText(["Time", "Confluence space", "Page ID"]);
  const values = request.getByRole("definition");
  await expect(values.nth(0).locator("time")).toHaveAttribute("title", "2026-10-25 18:36:20.518405 UTC");
  await expect(values.nth(1)).toHaveText("DOCS");
  await expect(values.nth(2)).toHaveText("123456789");
  await expect(request.getByTitle("Resource scope the request was authorized against", { exact: true })).toHaveText("Confluence space");
  await expect(request.getByTitle("Identifier the provider reported", { exact: true })).toHaveText("Page ID");

  await request.getByText("Details", { exact: true }).click();
  await expect(request.getByRole("term")).toHaveText([
    "Time", "Confluence space", "Page ID",
    "Exact time", "Broker request ID", "Agent request ID", "Audit ID", "Node", "Config generation", "Policy generation", "Principal subject"
  ]);
  await expect(values).toHaveText([
    /./, "DOCS", "123456789",
    "2026-10-25 18:36:20.518405 UTC", CONFLUENCE_PAGE_VIEW.brokerRequestId, "agent-confluence-page-view", "confluence-page-view",
    "broker-01.example.internal", "1", "150", "alice@example.test"
  ]);
  expect(errors).toEqual([]);
});

test("a management record keeps its target rows and shows its phase in Outcome", async ({ page }) => {
  const { drawer, section } = await openRecord(page, BROKER_GRANT_UPDATE);
  expect(await headings(drawer)).toEqual(["Outcome", "Identity", "Request"]);
  await expect(section("Outcome").getByRole("term")).toHaveText(["Phase"]);
  await expect(section("Outcome").getByRole("definition")).toHaveText(["completed"]);
  const request = section("Request");
  await expect(request.getByRole("term")).toHaveText(["Time", "Management target", "Target service"]);
  await expect(request.getByRole("definition").nth(1)).toHaveText('{"grantId":"ops-readers"}');
  await expect(request.getByRole("definition").nth(2)).toHaveText("jira");
});

// Whole-drawer captures for review: an allowed read (Details open), a JQL search, a denied create and a management change.
for (const [name, record] of [["allowed-read", CONFLUENCE_PAGE_VIEW], ["jql-search", JIRA_SEARCH], ["denied-create", JIRA_ISSUE_CREATE], ["management", BROKER_GRANT_UPDATE]] as const) {
  test(`drawer capture: ${name}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1280, height: 1400 });
    const { drawer, section, errors } = await openRecord(page, record);
    if (name === "allowed-read") await section("Request").getByText("Details", { exact: true }).click();
    await drawer.screenshot({ path: testInfo.outputPath(`drawer-${name}.png`) });
    expect(errors).toEqual([]);
  });
}
