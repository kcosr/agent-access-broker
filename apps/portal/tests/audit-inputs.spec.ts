// Snapshot UI contracts use synthetic stored events and a mocked management API.
// They deliberately expose no current catalog action for these historical events.
import { expect, test, type Page } from "@playwright/test";
import type { AuditRecord } from "../src/types";
import { attachmentsField, auditEnvelope, auditField, AUDIT_REQUEST_ID, LARGE_IDENTIFIER, requestRecord, STORED_QUERY } from "../unit/audit-request.fixture";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

let assets: PortalAssets;
test.beforeAll(async () => { assets = await servePortalAssets(); });
test.afterAll(async () => { await assets.close(); });

async function fixture(page: Page, record = requestRecord(), self = false) {
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.addInitScript(() => Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (text: string) => { (window as unknown as { copied: string }).copied = text; } } }));
  await page.route("**/v1/**", async route => {
    const pathname = new URL(route.request().url()).pathname;
    const envelope = (result: unknown) => ({ ok: true, decision: "allow", requestId: "fixture", brokerRequestId: "fixture", operation: "fixture", principal: "alice", result });
    let body: unknown;
    if (pathname === "/v1/auth/session") body = envelope({ role: self ? "user" : "admin", selfServiceEnabled: true, authenticated: true, principal: "alice", policyManagementServices: [], auditQueryable: true });
    else if (/\/audit\/options$/.test(pathname)) body = envelope({ services: [] });
    else if (/\/audit\/events$/.test(pathname)) body = envelope({ items: [record], nextCursor: null });
    else if (/\/audit\/requests\//.test(pathname)) body = envelope({ brokerRequestId: AUDIT_REQUEST_ID, items: [record] });
    else if (pathname === "/v1/admin/config/status") body = envelope({ generation: 1, loadedAt: new Date().toISOString(), identityAuthority: "managed", policyAuthority: "managed" });
    else if (pathname === "/v1/resource-types") body = { resourceTypes: [] };
    else if (pathname === "/v1/admin/policy/catalog") body = envelope({ services: [], subjects: { users: [], groups: [], anonymous: false }, resources: [], resourceGroups: [], executionContexts: { allowedValues: [], contextRequired: false } });
    else if (pathname === "/v1/tokens/options") body = envelope({ policyGeneration: 1, resources: [], resourceGroups: [], executionContexts: [], services: [] });
    else if (pathname === "/v1/credentials") body = envelope({ connections: [], retained: [] });
    else body = envelope([]);
    await route.fulfill({ json: body });
  });
  await page.goto(`${assets.baseUrl}/ui/${self ? "activity" : "admin/audit"}?request=${AUDIT_REQUEST_ID}&record=${record.auditId}`);
  const drawer = page.getByRole("complementary", { name: `${record.decision === "allow" ? "Allowed" : record.decision === "deny" ? "Denied" : "Error"}: ${record.action} on ${record.service}`, exact: true });
  await expect(drawer).toBeVisible();
  return { drawer, errors };
}

for (const theme of ["light", "dark"] as const) for (const mobile of [false, true]) {
  test(`request details are compact and readable in ${theme} ${mobile ? "mobile Activity" : "desktop Audit"}`, async ({ page }, testInfo) => {
    if (mobile) await page.setViewportSize({ width: 390, height: 844 });
    const { drawer, errors } = await fixture(page, requestRecord(), mobile);
    await page.evaluate(theme => document.documentElement.dataset.theme = theme, theme);
    const details = drawer.getByRole("region", { name: "Request details", exact: true });
    await expect(details).toContainText(LARGE_IDENTIFIER);
    await expect(details).toContainText("Notify usersNo");
    await expect(details).toContainText("Requested offset0");
    await expect(details).toContainText("Empty text");
    await expect(details).toContainText("Explicit null");
    await expect(details).not.toContainText("raw-only-canary");
    await expect(details).not.toContainText("Raw change secret label");
    await expect(details).not.toContainText("Raw target secret label");
    await expect(details).not.toContainText("Absent value");
    await expect(details.getByText("Not recorded: unexpected input shape", { exact: true })).not.toBeVisible();
    const query = details.locator(".pt-audit-query");
    await expect(query).toContainText('<script>alert("never")</script>');
    await expect(query).toContainText('\\u{1}\\u{202E}');
    await expect(query).toContainText("Truncated at capture:");
    await expect(query.locator("script")).toHaveCount(0);
    await expect(query.getByRole("button", { name: "Show full text", exact: true })).toHaveAttribute("aria-expanded", "false");
    await expect.poll(() => drawer.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`request-${theme}-${mobile ? "mobile" : "desktop"}.png`) });
    await details.getByText("Additional request details", { exact: true }).click();
    await expect(details.getByText("Not recorded: unexpected input shape", { exact: true })).toBeVisible();
    await expect(details.getByText("Not recorded: exceeds audit limit", { exact: true })).toBeVisible();
    await expect(details.getByText("Not recorded: audit budget", { exact: true })).toBeVisible();
    expect(errors).toEqual([]);
  });
}

test("keyboard expansion and copy preserve stored query text and large integers exactly", async ({ page }) => {
  const { drawer } = await fixture(page);
  await drawer.getByRole("button", { name: "Copy Requested issue", exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as unknown as { copied: string }).copied)).toBe(LARGE_IDENTIFIER);
  const query = drawer.locator(".pt-audit-query");
  const expand = query.getByRole("button", { name: "Show full text", exact: true });
  await expand.focus();
  await page.keyboard.press("Enter");
  await expect(query.getByRole("button", { name: "Show less", exact: true })).toHaveAttribute("aria-expanded", "true");
  await query.getByRole("button", { name: "Copy Requested query", exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as unknown as { copied: string }).copied)).toBe(STORED_QUERY);
  await expect(page.getByText(/^Recorded value copied\. Truncated at capture:/)).toBeVisible();
  expect(page.url()).not.toContain("In+Progress");
  await drawer.getByRole("tab", { name: "Raw", exact: true }).click();
  await drawer.getByText("Record JSON", { exact: true }).click();
  await expect(drawer.locator("pre")).toContainText("raw-only-canary");
  await drawer.getByRole("button", { name: "Copy JSON", exact: true }).click();
  const copied = await page.evaluate(() => (window as unknown as { copied: string }).copied);
  expect(JSON.parse(copied).requestAudit.fields[0].value).toBe(LARGE_IDENTIFIER);
});

test("history, unavailable projection and unknown versions retain usable outcome and Raw", async ({ page }) => {
  const records: AuditRecord[] = [
    requestRecord({ requestAudit: undefined }),
    requestRecord({ requestAudit: { ...auditEnvelope(), status: "unavailable", reason: "projectionFailed" } }),
    requestRecord({ requestAudit: { version: 2, futureValue: "future-raw-only" } }),
  ];
  for (const [index, record] of records.entries()) {
    await page.unroute("**/v1/**");
    const { drawer } = await fixture(page, record);
    if (index === 0) await expect(drawer.getByRole("region", { name: "Request details", exact: true })).toHaveCount(0);
    else await expect(drawer.getByText("Request details unavailable", { exact: true })).toBeVisible();
    await expect(drawer.getByRole("region", { name: "Outcome", exact: true })).toBeVisible();
    await expect(drawer.getByRole("region", { name: "Identity", exact: true })).toBeVisible();
    if (index === 2) {
      await expect(drawer).not.toContainText("future-raw-only");
      await drawer.getByRole("tab", { name: "Raw", exact: true }).click();
      await drawer.getByText("Record JSON", { exact: true }).click();
      await expect(drawer.locator("pre")).toContainText("future-raw-only");
    }
  }
});

test("sampled records and outcomes preserve association without exposing raw children", async ({ page }) => {
  const record = requestRecord({ action: "attachment.add", requestAudit: { ...auditEnvelope([attachmentsField()]), status: "partial" }, providerAudit: {
    provider: "jira", attachments: Array.from({ length: 21 }, (_, inputIndex) => ({ inputIndex, status: "created", attachmentId: `returned-${inputIndex}` })),
  } });
  const { drawer } = await fixture(page, record);
  const details = drawer.getByRole("region", { name: "Request details", exact: true });
  await expect(details).toContainText("21 input items · 1 omitted at capture");
  await expect(details).toContainText("Fields supplied (recorded fields only)");
  await expect(details.getByText("image-4.png", { exact: true })).toBeVisible();
  await expect(details.getByText("image-5.png", { exact: true })).toHaveCount(0);
  await details.getByRole("button", { name: "15 more retained", exact: true }).click();
  await expect(details.getByText("image-19.png", { exact: true })).toBeVisible();
  await expect(details).not.toContainText("raw-child-canary");
  await expect(details).not.toContainText("Hidden child label");
  await drawer.getByText("Attachment outcomes (21)", { exact: true }).click();
  const outcomes = drawer.getByRole("list", { name: "Attachment outcomes", exact: true });
  await expect(outcomes.getByRole("listitem")).toHaveCount(21);
  await expect(outcomes.getByRole("listitem").last()).toContainText("returned-20");
  await expect(outcomes.getByRole("listitem").last()).toContainText("Request metadata sampled; not retained");
});

test("scalar lists retain item indices, statuses and exact integer values", async ({ page }) => {
  const list = auditField("projects", { label: "Requested projects", kind: "identifier", shape: "list", value: undefined, items: [
    { index: 0, state: "captured", encoding: "decimalInteger", value: LARGE_IDENTIFIER }, { index: 1, state: "null" }, { index: 2, state: "invalid" }, { index: 3, state: "tooLarge" }, { index: 4, state: "captured", value: "OPS" }, { index: 5, state: "captured", value: "WEB" },
  ], totalCount: 8, limitedCount: 0, invalidCount: 1, budgetOmittedCount: 2 });
  const records = auditField("records", { label: "Requested records", capture: "records", shape: undefined, kind: "records", value: undefined,
    columns: [{ key: "id", label: "Record ID", display: "primary", role: "fact", kind: "identifier", capture: "value", shape: "scalar" }],
    rows: [{ index: 0, state: "captured", cells: { id: { state: "captured", supplied: true, encoding: "decimalInteger", value: LARGE_IDENTIFIER } } }],
    totalCount: 1, limitedCount: 0, invalidCount: 0, budgetOmittedCount: 0,
  });
  const { drawer } = await fixture(page, requestRecord({ requestAudit: { ...auditEnvelope([list, records, { ...records, key: "hidden-records", label: "Hidden collection label", display: "raw" }]), status: "partial" } }));
  await expect(drawer).toContainText("8 input items · 2 omitted at capture (2 by audit budget) · 1 unexpected shapes");
  await expect(drawer).toContainText("Explicit null");
  await drawer.getByRole("button", { name: "1 more retained", exact: true }).click();
  await expect(drawer.getByText("WEB", { exact: true })).toBeVisible();
  await drawer.getByRole("button", { name: "Copy Record ID", exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as unknown as { copied: string }).copied)).toBe(LARGE_IDENTIFIER);
  await expect(drawer).not.toContainText("Hidden collection label");
});

test("uncertainty precedes requested facts; command execution never flattens process data", async ({ page }) => {
  const { drawer } = await fixture(page, requestRecord({ decision: "error", reasonCode: "upstream_timeout", providerAudit: { resultCount: 50, command: { name: "ticketing", spawned: true, operationDispatched: true, exitCode: null, signal: null, durationMs: 42, contractViolation: null, executable: "/sensitive/path", argv: ["canary-argv"], stdout: "canary-stdout" } } }));
  await expect(drawer.getByText("Outcome unverified", { exact: true })).toBeVisible();
  expect(await drawer.getByText("Outcome unverified", { exact: true }).evaluate((node) => !!(node.compareDocumentPosition(document.querySelector(".pt-audit-request-details")!) & Node.DOCUMENT_POSITION_FOLLOWING))).toBe(true);
  await drawer.getByText("Execution details", { exact: true }).click();
  await expect(drawer).toContainText("Approved commandticketing");
  await expect(drawer).toContainText("Exit codeUnknown");
  await expect(drawer).not.toContainText("canary-argv");
  await expect(drawer).not.toContainText("canary-stdout");
  await expect(drawer).not.toContainText("/sensitive/path");
  await expect(drawer).not.toContainText("50 returned");
});
