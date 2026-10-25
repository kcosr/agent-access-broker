// Mocked API contract for the audit drawer's Inputs section: synthetic stored
// records, one per action, and no Broker. The Broker's own tests cover capture.
import { expect, test, type Page } from "@playwright/test";
import type { AuditRecord } from "../src/types";
import {
  AUDIT_INPUT_RECORDS,
  GITLAB_ISSUE_SEARCH,
  GITLAB_ISSUE_VIEW,
  JIRA_COMMENT_VIEW,
  JIRA_ISSUE_CREATE,
  JIRA_PROJECT_LIST,
  JIRA_SEARCH,
  JIRA_TEXT_SEARCH,
  TRUNCATED_SUMMARY
} from "../unit/audit-inputs.fixture";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

/** The adversarial search's preview: whitespace collapsed, controls escaped, 99 code points and an ellipsis. */
const SEARCH_PREVIEW = `login timeout <script>alert("never")</script>\\u{1}\\u{202E}${"é".repeat(41)}…`;

/** Each record's Inputs rows as [label, shown value]. */
const ROWS: [AuditRecord, [string, string][]][] = [
  [JIRA_SEARCH, [["Query", 'JQL project = OPS AND status = "In Progress"'], ["Projects", "OPS"]]],
  [JIRA_TEXT_SEARCH, [["Query", "checkout timeout"], ["Projects", "OPS, SEC"]]],
  [JIRA_ISSUE_CREATE, [["Project", "OPS"], ["Summary", `${TRUNCATED_SUMMARY.slice(0, 99)}…Truncated in record`]]],
  [JIRA_COMMENT_VIEW, [["Issue", "OPS-42"], ["Comment ID", "18446744073709551615"]]],
  [GITLAB_ISSUE_SEARCH, [["Project", "platform/api"], ["Search", SEARCH_PREVIEW], ["State", "opened"], ["Milestone", "null"]]],
  [GITLAB_ISSUE_VIEW, [["Project", "platform/api"], ["Issue", "42"]]]
];

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
    else if (pathname === "/v1/resource-types") body = { resourceTypes: [] };
    else if (pathname === "/v1/admin/policy/catalog") body = envelope({ services: [], subjects: { users: [], groups: [], anonymous: false }, resources: [], resourceGroups: [], executionContexts: { allowedValues: [], contextRequired: false } });
    else if (pathname === "/v1/tokens/options") body = envelope({ policyGeneration: 1, resources: [], resourceGroups: [], executionContexts: [], services: [] });
    else if (pathname === "/v1/credentials") body = envelope({ connections: [], retained: [] });
    else body = envelope([]);
    await route.fulfill({ json: body });
  });
  await page.goto(`${assets.baseUrl}/ui/admin/audit?request=${record.brokerRequestId}&record=${record.auditId}`);
  const drawer = page.getByRole("complementary", { name: `Allowed: ${record.action} on ${record.service}`, exact: true });
  await expect(drawer).toBeVisible();
  await expect(drawer.getByRole("region", { name: "Request", exact: true })).toBeVisible();
  return { drawer, inputs: drawer.getByRole("region", { name: "Inputs", exact: true }), errors };
}

for (const [record, rows] of ROWS) {
  test(`${record.auditId}: Inputs follow Request with one row per recorded input`, async ({ page }, testInfo) => {
    const { drawer, inputs, errors } = await openRecord(page, record);
    const headings = await drawer.getByRole("heading", { level: 3 }).allTextContents();
    expect(headings[headings.indexOf("Request") + 1]).toBe("Inputs");
    await expect(inputs.getByRole("term")).toHaveText(rows.map(([label]) => label));
    await expect(inputs.getByRole("definition")).toHaveText(rows.map(([, value]) => value));
    await expect.poll(() => drawer.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
    await inputs.screenshot({ path: testInfo.outputPath(`inputs-${record.auditId}.png`) });
    expect(errors).toEqual([]);
  });
}

test("a search query shows its language badge and value while hover keeps the stored compact JSON", async ({ page }) => {
  const { inputs } = await openRecord(page, JIRA_SEARCH);
  const values = inputs.getByRole("definition");
  const query = values.nth(0).getByTitle('{"type":"jql","value":"project = OPS AND status = \\"In Progress\\""}', { exact: true });
  await expect(query.getByText("JQL", { exact: true })).toBeVisible();
  await expect(query).toHaveText('JQL project = OPS AND status = "In Progress"');
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
