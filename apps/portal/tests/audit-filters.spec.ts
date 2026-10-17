// Focused browser checks use the built portal with an HTTP fixture. The real
// broker/SQLite visibility tiers are covered in portal.spec.ts.
import { expect, test, type Locator, type Page } from "@playwright/test";
import { createServer, type Server } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { AuditRecord } from "../src/types";
import { RESOURCE_TYPES } from "../unit/resource-types.fixture";
import { portalDist } from "./support/binaries";

const dist = portalDist;
let server: Server;
let baseUrl: string;

test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    const pathname = new URL(request.url!, "http://localhost").pathname;
    const asset = pathname.startsWith("/ui/assets/") ? path.join(dist, pathname.slice(4)) : path.join(dist, "index.html");
    try {
      response.setHeader("content-type", asset.endsWith(".js") ? "application/javascript" : asset.endsWith(".css") ? "text/css" : "text/html");
      response.end(await readFile(asset));
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture address");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

test.afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

const REQUEST_ID = "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a3b";
const LONG_ACTION = "merge_request.discussion.inline.replace_with_suggestion.batch";
const LONG_PRINCIPAL = "automation-service-principal-for-nightly-builds@example.test";
const TOKEN_ID = "9d7e4b1a-2c3f-4e5d-8a6b-7c8d9e0f1a2b";

function record(id: string, service: string, action: string, related?: string, overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    auditId: id, nodeId: "fixture", timestamp: new Date().toISOString(), agentRequestId: id,
    brokerRequestId: REQUEST_ID, principal: "alice", service, action, decision: "allow",
    ...(related ? { providerAudit: { management: { operation: action, targetService: related, phase: "success" } } } : {}),
    ...overrides
  };
}

type FixtureOptions = {
  tier?: "admin" | "auditor" | "manager" | "self";
  resourceRecords?: AuditRecord[];
  failed?: boolean;
  emptyHistory?: boolean;
  extraHistory?: boolean;
  /** No record carries a token (sessions and tokens stripped). */
  withoutTokens?: boolean;
  /** A record with a long action name and an unnamed, long principal. */
  longIdentifiers?: boolean;
  timeout?: boolean;
  paged?: boolean;
  viewport?: { width: number; height: number };
};

async function fixture(page: Page, options: FixtureOptions = {}) {
  const tier = options.tier ?? "admin";
  const service = { service: "jira", displayName: "Jira", actions: [{ action: "issue.view", description: "View issue", requiredScopes: {}, credentialModes: [] }], resourceScopes: {} };
  const initialRecords = options.emptyHistory ? [] : [
    record("login", "broker", "auth.local.login"), record("grant", "broker", "admin.policy.grants.create", "jira"),
    record("issue", "jira", "issue.view", undefined, { identitySource: { name: "managed", type: "broker_token", tokenClass: "agent_invoke", tokenId: TOKEN_ID } }),
    ...(options.extraHistory ? [
      record("retired", "retired", "historical.read", undefined, { nodeId: "node-b", upstreamStatus: 200, upstreamDurationMs: 42 }),
      record("junk", "jira", "unsupported.junk", undefined, { decision: "deny", reasonCode: "service_action_unknown" }),
    ] : []),
    ...(options.longIdentifiers ? [
      record("long", "jira", LONG_ACTION, undefined, { principal: LONG_PRINCIPAL }),
    ] : []),
  ];
  const allRecords = options.resourceRecords ?? initialRecords;
  const visible = tier === "manager" ? allRecords.filter((item) => item.service === "jira" || item.providerAudit) : allRecords;
  const records = options.withoutTokens ? visible.map(({ identitySource: _identity, ...item }) => item) : visible;
  const requests: URL[] = [];
  const apiRequests: URL[] = [];
  if (options.viewport) await page.setViewportSize(options.viewport);
  await page.route("**/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const endpoint = url.pathname;
    apiRequests.push(url);
    const envelope = (result: unknown) => ({ ok: true, decision: "allow", requestId: "fixture", brokerRequestId: "fixture", operation: "fixture", principal: "alice", result });
    let body: unknown;
    if (endpoint === "/v1/auth/session") {
      body = envelope({ role: tier === "admin" ? "admin" : tier === "auditor" ? "auditor" : tier === "self" ? "user" : "service_policy_manager", selfServiceEnabled: true, authenticated: true, principal: "alice",  policyManagementServices: tier === "manager" ? ["jira"] : [], auditQueryable: true });
    } else if (/\/audit\/options$/.test(endpoint)) {
      if (options.failed) return route.fulfill({ status: 503, json: { ok: false, reasonCode: "internal_error", error: { message: "Unavailable" } } });
      body = envelope({ services: [
        { service: "broker", actions: tier === "manager" ? ["admin.policy.grants.create"] : ["auth.local.login", "auth.logout", "tokens.issue", ...(tier === "admin" ? ["admin.policy.grants.create", "admin.tokens.issue"] : [])] },
      ] });
    } else if (/\/audit\/events$/.test(endpoint)) {
      requests.push(url);
      if (options.timeout) return route.fulfill({ status: 504, json: { ok: false, reasonCode: "audit_query_timeout", error: { message: "Audit query timed out" } } });
      if (options.paged) {
        const cursor = url.searchParams.get("cursor");
        const page = cursor ? [record("older", "jira", "issue.view", undefined, { timestamp: new Date(Date.now() - 3_600_000).toISOString() })] : records;
        body = envelope({ items: page, nextCursor: cursor ? null : "next-page" });
      } else {
        const action = url.searchParams.get("action");
        body = envelope({ items: records.filter((item) => (!url.searchParams.has("service") || item.service === url.searchParams.get("service"))
          && (!action || (action.endsWith("*") ? item.action.startsWith(action.slice(0, -1)) : item.action === action))), nextCursor: null });
      }
    } else if (/\/audit\/requests\//.test(endpoint)) {
      const id = decodeURIComponent(endpoint.split("/").pop()!);
      if (id !== REQUEST_ID) return route.fulfill({ status: 404, json: { ok: false, reasonCode: "audit_request_not_found", error: { message: "Not found" } } });
      body = envelope({ brokerRequestId: id, items: options.resourceRecords ?? [
        record("preflight", "broker", "tokens.issue", undefined, { timestamp: "2026-09-26T12:00:00.000100+00:00", providerAudit: { management: { phase: "preflight" } } }),
        record("success", "broker", "tokens.issue", undefined, { timestamp: "2026-09-26T12:00:01.250100+00:00", providerAudit: { management: { phase: "success" } } }),
      ] });
    } else if (endpoint === "/v1/admin/policy/catalog") {
      body = envelope({ services: [service], subjects: { users: [{ principalId: "alice", displayName: "Alice Example" }], groups: [], anonymous: false }, resources: [], resourceGroups: [], executionContexts: { allowedValues: [], contextRequired: false } });
    } else if (endpoint === "/v1/resource-types") {
      body = { resourceTypes: options.resourceRecords ? RESOURCE_TYPES : [] };
    } else if (endpoint === "/v1/tokens") {
      body = envelope([{ tokenId: TOKEN_ID, principalId: "alice", name: "agent-one", tokenClass: "agent_invoke", scopes: {}, createdAt: new Date().toISOString(), createdBy: "alice" }]);
    } else if (endpoint === "/v1/tokens/options") {
      // Activity suggests the caller's granted services and actions from the token options.
      body = envelope({ policyGeneration: 1, resources: [], resourceGroups: [], executionContexts: ["default"], services: [{
        service: "jira", displayName: "Jira", brokerHosts: [], executionContexts: ["default"],
        actions: [{ action: "issue.view", description: "View issue", readOnly: true, requiredScopes: {},  executionContexts: ["default"], effectiveAccessByExecutionContext: { default: [{ scopes: {}, excludedRequests: [] }] } }]
      }] });
    } else if (endpoint === "/v1/credentials") {
      body = envelope({ connections: [], retained: [] });
    } else {
      body = envelope([]);
    }
    await route.fulfill({ json: body });
  });
  await page.goto(`${baseUrl}/ui/${tier === "self" ? "activity" : "admin/audit"}`);
  await expect(page.getByRole("main", { name: tier === "self" ? "Activity" : "Audit", exact: true })).toBeVisible();
  return { requests, apiRequests };
}

/** Record rows' links: the row header (Action column) of each table row, named "<action> on <service>". */
function rowLinks(page: Page) {
  return page.getByRole("main").getByRole("rowheader").getByRole("link");
}

/** The record table's column headers, in order (columns hidden by width included; not the table's empty filler). */
async function columnHeaders(page: Page) {
  return (await page.getByRole("main").getByRole("table").locator("thead th:not(.wb-cell-filler)").allTextContents()).map((text) => text.trim());
}

/** The row whose link is named "<action> on <service>". */
function recordRow(page: Page, name: string) {
  return page.getByRole("main").getByRole("row").filter({ has: page.getByRole("rowheader", { name, exact: true }) });
}

async function choose(page: Page, name: string, option: string | RegExp) {
  await page.getByRole("combobox", { name, exact: true }).click();
  await page.getByRole("listbox", { name, exact: true }).getByRole("option", typeof option === "string" ? { name: option, exact: true } : { name: option }).click();
}

async function expectAligned(input: Locator, popup: Locator) {
  // The listbox matches the combobox frame (the input's parent), not the bare input.
  const field = await input.locator("xpath=..").boundingBox();
  const menu = await popup.locator("xpath=..").boundingBox();
  expect(field).not.toBeNull();
  expect(menu).not.toBeNull();
  expect(Math.abs(field!.x - menu!.x)).toBeLessThanOrEqual(1);
  expect(Math.abs(field!.width - menu!.width)).toBeLessThanOrEqual(1);
  const viewport = await input.page().evaluate(() => ({ width: innerWidth, height: innerHeight }));
  expect(menu!.x).toBeGreaterThanOrEqual(0);
  expect(menu!.x + menu!.width).toBeLessThanOrEqual(viewport.width);
  expect(menu!.y).toBeGreaterThanOrEqual(0);
  expect(menu!.y + menu!.height).toBeLessThanOrEqual(viewport.height);
}

for (const tier of ["admin", "manager", "self"] as const) {
  test(`${tier} can select Broker and related-service rows remain clearly labeled`, async ({ page }) => {
    await fixture(page, { tier });
    const service = page.getByRole("combobox", { name: "Service", exact: true });
    await service.click();
    const list = page.getByRole("listbox", { name: "Service", exact: true });
    await expect(list.getByRole("option").first()).toHaveAccessibleName(/^broker(?:\s|$)/);
    await expectAligned(service, list);
    const request = page.waitForRequest((request) => new URL(request.url()).pathname.endsWith("/audit/events") && new URL(request.url()).searchParams.get("service") === "broker");
    await service.press("Enter");
    await expect(service).toHaveValue("broker");
    expect(new URL((await request).url()).searchParams.has("scopeService")).toBe(false);
    await expect(page).toHaveURL(/service=broker/);
    await expect(rowLinks(page).filter({ hasNotText: / on broker$/ })).toHaveCount(0);
    await expect(rowLinks(page).first()).toBeVisible();
    await expect(page.getByText("Related service: jira", { exact: true })).toBeVisible();
    await choose(page, "Service", /^jira/);
    await expect(rowLinks(page)).toHaveText(["issue.view on jira"]);
  });
}

test("editable suggestions preserve raw service and principal identifiers during in-place edits", async ({ page }) => {
  await fixture(page);
  const service = page.getByRole("combobox", { name: "Service", exact: true });
  await expect(service).toHaveValue("");
  await expect(service).toHaveAttribute("placeholder", "All services");
  await service.click();
  await expect(service).toHaveValue("");
  await service.press("Escape");

  await choose(page, "Service", /^broker(?:\s|$)/);
  await expect(service).toHaveValue("broker");
  await service.click();
  await service.press("End");
  await service.pressSequentially(".old");
  await service.press("Enter");
  await expect(service).toHaveValue("broker.old");
  await expect(page).toHaveURL(/service=broker\.old/);

  await choose(page, "Principal", /Alice Example/);
  const principal = page.getByRole("combobox", { name: "Principal", exact: true });
  await expect(principal).toHaveValue("alice");
  await principal.click();
  await principal.press("End");
  await principal.pressSequentially(".former");
  const request = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname.endsWith("/audit/events") && url.searchParams.get("principal") === "alice.former";
  });
  await principal.press("Enter");
  const params = new URL((await request).url()).searchParams;
  expect(params.get("service")).toBe("broker.old");
  await expect(principal).toHaveValue("alice.former");
  await expect(page).toHaveURL(/principal=alice\.former&service=broker\.old/);
});

test("Enter on an exact action selects it rather than the first partial match", async ({ page }) => {
  await fixture(page);
  const action = page.getByRole("combobox", { name: "Action", exact: true });
  await action.fill("tokens.issue");
  // admin.tokens.issue sorts first and also contains the text.
  await expect(page.getByRole("listbox", { name: "Action", exact: true }).getByRole("option").first()).toHaveText("admin.tokens.issue");
  await action.press("Enter");
  await expect(page).toHaveURL(/action=tokens\.issue$/);
  await expect(action).toHaveValue("tokens.issue");
  await expect(action).toBeFocused();
  await expect(action).toHaveAttribute("aria-expanded", "false");
});

test("typed identifiers are case-sensitive and never re-cased to a suggestion", async ({ page }) => {
  await fixture(page);
  // Principal IDs, services, and actions are case-sensitive: `ALICE` is not the suggested `alice`.
  const principal = page.getByRole("combobox", { name: "Principal", exact: true });
  const request = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname.endsWith("/audit/events") && url.searchParams.get("principal") === "ALICE";
  });
  await principal.fill("ALICE");
  await principal.press("Enter");
  await request;
  await expect(principal).toHaveValue("ALICE");
  await expect(page).toHaveURL(/principal=ALICE/);
  // Leaving the field commits what was typed, as typed.
  const action = page.getByRole("combobox", { name: "Action", exact: true });
  await action.fill("Tokens.Issue");
  await action.press("Tab");
  await expect(action).toHaveValue("Tokens.Issue");
  await expect(page).toHaveURL(/action=Tokens\.Issue/);
});

test("canonical suggestions exclude arbitrary history while manual historical filters remain usable", async ({ page }) => {
  await fixture(page, { extraHistory: true });
  const service = page.getByRole("combobox", { name: "Service", exact: true });
  await service.click();
  await expect(page.getByRole("listbox", { name: "Service", exact: true }).getByRole("option", { name: "retired", exact: true })).toHaveCount(0);
  await service.press("Escape");
  const action = page.getByRole("combobox", { name: "Action", exact: true });
  await action.click();
  const options = page.getByRole("listbox", { name: "Action", exact: true });
  await expect(options.getByRole("option", { name: "unsupported.junk", exact: true })).toHaveCount(0);
  await expect(options.getByRole("option", { name: "historical.read", exact: true })).toHaveCount(0);
  await action.press("Escape");
  await choose(page, "Service", /^broker(?:\s|$)/);
  await action.click();
  await expect(page.getByRole("listbox", { name: "Action", exact: true }).getByRole("option", { name: "auth.logout", exact: true })).toBeVisible();
  await action.fill("auth.*");
  await action.press("Enter");
  await expect(page).toHaveURL(/service=broker&action=auth\.\*/);
  await expect(rowLinks(page)).toHaveText(["auth.local.login on broker"]);
  // Unconfirmed typing does not change the service or drop the action.
  await service.fill("bro");
  await service.fill("broker");
  await service.press("Tab");
  await expect(service).toHaveValue("broker");
  await expect(action).toHaveValue("auth.*");
  // A suggested service drops an action known to belong elsewhere…
  await choose(page, "Service", /^jira/);
  await expect(action).toHaveValue("");
  // …but keeps actions nobody suggested.
  await action.fill("unobserved.operation");
  await action.press("Enter");
  await choose(page, "Service", /^broker(?:\s|$)/);
  await expect(action).toHaveValue("unobserved.operation");
  await expect(page).toHaveURL(/action=unobserved\.operation/);
  await expect(page.getByText("No matching records", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Clear all", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/audit$/);
  await service.fill("retired");
  await service.press("Enter");
  await expect(service).toHaveValue("retired");
  await action.click();
  await expect(page.getByRole("listbox", { name: "Action", exact: true }).getByRole("option")).toHaveCount(0);
  await action.fill("historical.read");
  await action.press("Enter");
  await expect(page).toHaveURL(/service=retired&action=historical\.read/);
  await expect(rowLinks(page)).toHaveText(["historical.read on retired"]);
  await action.click();
  await action.press("Escape");
  await expect(action).toHaveAttribute("aria-expanded", "false");
});

for (const theme of ["light", "dark"] as const) {
  test(`audit dropdowns align and fit the viewport in ${theme} mode`, async ({ page }, testInfo) => {
    await fixture(page, { viewport: { width: 1280, height: 640 } });
    await page.evaluate((theme) => document.documentElement.dataset.theme = theme, theme);
    for (const name of ["Principal", "Service", "Action"]) {
      const input = page.getByRole("combobox", { name, exact: true });
      await input.scrollIntoViewIfNeeded();
      await input.click();
      const list = page.getByRole("listbox", { name, exact: true });
      await expectAligned(input, list);
      if (name === "Action") await page.screenshot({ path: testInfo.outputPath(`audit-${theme}.png`) });
      await input.press("Escape");
    }
    // Near the bottom of the scrolled sidebar the listbox still fits the viewport.
    const input = page.getByRole("combobox", { name: "Action", exact: true });
    await page.getByRole("complementary", { name: "Audit filters" }).evaluate((sidebar) => {
      sidebar.scrollTop = sidebar.scrollHeight;
    });
    await input.click();
    await expectAligned(input, page.getByRole("listbox", { name: "Action", exact: true }));
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollHeight <= document.documentElement.clientHeight + 1)).toBe(true);
  });
}

test("canonical broker suggestions remain available with empty audit history", async ({ page }) => {
  await fixture(page, { emptyHistory: true });
  await expect(page.getByText("No records in this time range. Try a longer range.", { exact: true })).toBeVisible();
  await choose(page, "Service", /^broker(?:\s|$)/);
  await expect(page.getByText("No matching records", { exact: true })).toBeVisible();
  const action = page.getByRole("combobox", { name: "Action", exact: true });
  await action.click();
  await expect(page.getByRole("listbox", { name: "Action", exact: true }).getByRole("option", { name: "auth.local.login", exact: true })).toBeVisible();
  await action.fill("tokens");
  await expect(page.getByRole("listbox", { name: "Action", exact: true }).getByRole("option", { name: "tokens.issue", exact: true })).toBeVisible();
  await action.press("Escape");
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/audit$/);
});

test("filters remain editable when metadata is unavailable", async ({ page }) => {
  await fixture(page, { failed: true });
  await expect(page.getByText("Audit suggestions are unavailable. You can still enter filters.", { exact: true })).toBeVisible();
  await choose(page, "Service", /^broker(?:\s|$)/);
  const action = page.getByRole("combobox", { name: "Action", exact: true });
  await action.fill("auth.*");
  await action.press("Enter");
  await expect(page).toHaveURL(/service=broker&action=auth\.\*/);
  await expect(rowLinks(page)).toHaveText(["auth.local.login on broker"]);
});

test("sidebar facets, search, and time range apply to the URL and the query", async ({ page }) => {
  const { requests } = await fixture(page);
  const last = () => requests[requests.length - 1]!.searchParams;
  // Search applies on Enter (and after a pause while typing).
  const search = page.getByRole("searchbox", { name: "Search", exact: true });
  await search.fill('"exact phrase" pre*');
  await search.press("Enter");
  await expect(page).toHaveURL(/q=%22exact\+phrase%22\+pre\*/);
  await expect.poll(() => last().get("q")).toBe('"exact phrase" pre*');
  // Decisions are single-valued.
  const filters = page.getByRole("complementary", { name: "Audit filters" });
  await filters.getByRole("button", { name: "Denied", exact: true }).click();
  await expect(filters.getByRole("button", { name: "Denied", exact: true })).toHaveAttribute("aria-current", "true");
  await expect(page).toHaveURL(/decision=deny/);
  await expect.poll(() => last().get("decision")).toBe("deny");
  // More filters: phase applies at once; text facets on Enter.
  await filters.getByRole("button", { name: /More filters/ }).click();
  await filters.getByLabel("Phase", { exact: true }).selectOption("preflight");
  await expect(page).toHaveURL(/phase=preflight/);
  await filters.getByLabel("Reason code", { exact: true }).fill("scope_unresolved");
  await filters.getByLabel("Reason code", { exact: true }).press("Enter");
  await expect(page).toHaveURL(/reasonCode=scope_unresolved/);
  await expect.poll(() => last().get("reasonCode")).toBe("scope_unresolved");
  // Presets resolve to an absolute `from`; custom ranges send both bounds.
  const range = filters.getByRole("group", { name: "Time range" });
  await range.getByRole("button", { name: "7d", exact: true }).click();
  await expect(page).toHaveURL(/range=7d/);
  await expect.poll(() => Math.abs(Date.now() - 7 * 86_400_000 - Date.parse(last().get("from") ?? ""))).toBeLessThan(120_000);
  expect(last().has("to")).toBe(false);
  await range.getByRole("button", { name: "Custom", exact: true }).click();
  await expect(page).toHaveURL(/range=custom&from=/);
  const custom = filters.getByRole("form", { name: "Custom range" });
  await custom.getByLabel("From", { exact: true }).fill("2026-09-02T00:00");
  await custom.getByLabel("To", { exact: true }).fill("2026-09-01T00:00");
  await custom.getByRole("button", { name: "Apply range", exact: true }).click();
  await expect(custom.getByRole("alert")).toHaveText("The start of the range must not be after its end.");
  await custom.getByLabel("To", { exact: true }).fill("2026-09-03T12:30");
  await custom.getByRole("button", { name: "Apply range", exact: true }).click();
  await expect.poll(() => last().get("to")).toBe(new Date(2026, 8, 3, 12, 30).toISOString());
  expect(last().get("from")).toBe(new Date(2026, 8, 2).toISOString());
  await expect(page.getByTestId("audit-range")).toHaveText(/^from .+ to .+$/);
  // Clear all keeps nothing but the defaults.
  await filters.getByRole("button", { name: "Clear all", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/audit$/);
  await expect(search).toHaveValue("");
});

test("records open in a URL-addressable drawer with summary, request timeline, and raw JSON", async ({ page }) => {
  await fixture(page);
  const row = rowLinks(page).filter({ hasText: "issue.view on jira" });
  await row.click();
  await expect(page).toHaveURL(new RegExp(`request=${REQUEST_ID}&record=issue$`));
  const drawer = page.getByRole("complementary", { name: "Allowed: issue.view on jira" });
  await expect(drawer).toBeVisible();
  await expect(drawer.getByRole("tab", { name: "Summary" })).toHaveAttribute("aria-selected", "true");
  await expect(drawer).toContainText("Broker request ID");
  await expect(drawer).toContainText(REQUEST_ID);
  await expect(drawer.getByRole("link", { name: "Open principal", exact: true })).toHaveAttribute("href", "/ui/admin/principals/alice");

  // Filter actions apply in place and keep the drawer open.
  await drawer.getByRole("button", { name: "Filter", exact: true }).click();
  await page.getByRole("menuitem", { name: "Filter to this request", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`requestId=${REQUEST_ID}&request=${REQUEST_ID}&record=issue$`));
  await expect(drawer).toBeVisible();

  // The timeline lists every record of the request, oldest first, with gaps.
  await drawer.getByRole("tab", { name: /^Timeline/ }).click();
  // Selecting a step renames the drawer, so find the timeline from the page.
  const steps = page.getByRole("list", { name: "Request timeline" }).getByRole("button");
  await expect(steps).toHaveCount(2);
  await expect(steps.nth(0)).toContainText("preflight");
  await expect(steps.nth(0)).toContainText("start");
  await expect(steps.nth(1)).toContainText("success");
  await expect(steps.nth(1)).toContainText("+1.25 s");
  await steps.nth(1).click();
  await expect(page).toHaveURL(/record=success$/);
  await expect(steps.nth(1)).toHaveAttribute("aria-current", "true");
  await expect(page.getByRole("complementary", { name: "Allowed: tokens.issue on broker" })).toBeVisible();

  // Raw keeps JSON collapsed until asked.
  const current = page.getByRole("complementary", { name: "Allowed: tokens.issue on broker" });
  await current.getByRole("tab", { name: "Raw" }).click();
  await expect(current.getByRole("button", { name: "Copy JSON", exact: true })).toBeVisible();
  await expect(current.locator("pre").last()).not.toBeVisible();
  await current.getByText("Record JSON", { exact: true }).click();
  await expect(current.locator("pre").last()).toContainText('"auditId": "success"');

  // Deep links restore the drawer; Escape closes it.
  await page.reload();
  await expect(page.getByRole("complementary", { name: "Allowed: tokens.issue on broker" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page).not.toHaveURL(/request=/);
  await expect(page.getByRole("complementary", { name: /on broker$/ })).toHaveCount(0);

  // Unknown requests say so in the drawer.
  await page.goto(`${baseUrl}/ui/admin/audit?request=not-a-request`);
  await expect(page.getByText("This is not a broker request ID.", { exact: true })).toBeVisible();
});

test("j/k move the cursor, Enter opens, the drawer follows, and Escape returns focus to the row", async ({ page }) => {
  await fixture(page);
  await expect(rowLinks(page)).toHaveCount(3);
  await page.keyboard.press("j");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/record=login$/);
  await expect(page.getByRole("complementary", { name: "Allowed: auth.local.login on broker" })).toBeVisible();
  await page.keyboard.press("j");
  await expect(page).toHaveURL(/record=grant$/);
  await expect(page.getByRole("complementary", { name: "Allowed: admin.policy.grants.create on broker" })).toBeVisible();
  await expect(rowLinks(page).nth(1)).toHaveAttribute("aria-current", "true");
  await page.keyboard.press("Escape");
  await expect(page).not.toHaveURL(/request=/);
  await expect(rowLinks(page).nth(1)).toBeFocused();
});

test("load more continues the paging session with only the cursor", async ({ page }) => {
  const { requests } = await fixture(page, { paged: true });
  await expect(rowLinks(page)).toHaveCount(3);
  const main = page.getByRole("main");
  await expect(main.getByRole("status").filter({ hasText: /^3 records$/ })).toBeVisible();
  // The last day may continue on the next page.
  await expect(main.getByRole("rowheader", { name: /^Today/ })).toContainText("3+ records");
  await main.getByRole("button", { name: "Load more records", exact: true }).click();
  await expect(rowLinks(page)).toHaveCount(4);
  expect([...requests[requests.length - 1]!.searchParams.keys()].sort()).toEqual(["cursor", "limit"]);
  await expect(main.getByRole("status").filter({ hasText: /^4 records$/ })).toBeVisible();
  await expect(main.getByRole("button", { name: /^Load more/ })).toHaveCount(0);
});

test("Load more waits while a filter change loads a new result set", async ({ page }) => {
  await fixture(page, { paged: true });
  const main = page.getByRole("main");
  const loadMore = main.getByRole("button", { name: "Load more records", exact: true });
  await expect(loadMore).toBeEnabled();
  // Hold the new result set: the previous records stay and Load more waits.
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  await page.route((url) => url.pathname.endsWith("/audit/events") && url.searchParams.get("decision") === "deny", async (route) => {
    await held;
    await route.fallback();
  });
  await page.getByRole("complementary", { name: "Audit filters" }).getByRole("button", { name: "Denied", exact: true }).click();
  await expect(page).toHaveURL(/decision=deny/);
  await expect(loadMore).toBeDisabled();
  await expect(rowLinks(page)).toHaveCount(3);
  release();
  await expect(loadMore).toBeEnabled();
});

test("a failed next page keeps the loaded records and retries the same page", async ({ page }) => {
  const { requests } = await fixture(page, { paged: true });
  // Routes registered later run first: fail the first continuation, then fall back to the fixture.
  let failNext = true;
  await page.route((url) => url.pathname.endsWith("/audit/events") && url.searchParams.has("cursor"), async (route) => {
    if (!failNext) return route.fallback();
    failNext = false;
    await route.fulfill({ status: 503, json: { ok: false, reasonCode: "internal_error", error: { message: "Store unavailable" } } });
  });
  const main = page.getByRole("main");
  await main.getByRole("button", { name: "Load more records", exact: true }).click();
  await expect(main.getByRole("alert")).toContainText("More records could not be loaded: Store unavailable");
  await expect(rowLinks(page)).toHaveCount(3);
  await main.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(rowLinks(page)).toHaveCount(4);
  expect([...requests[requests.length - 1]!.searchParams.keys()].sort()).toEqual(["cursor", "limit"]);
  await expect(main.getByRole("alert")).toHaveCount(0);
});

test("audit query timeouts are explained in place", async ({ page }) => {
  await fixture(page, { timeout: true });
  await expect(page.getByText("The audit query took too long. Narrow the time range or add filters, then try again.", { exact: true })).toBeVisible();
});

test("auto-refresh starts a new session every 15 seconds while one page is loaded", async ({ page }) => {
  await page.clock.install();
  const { requests } = await fixture(page);
  await expect(rowLinks(page).first()).toBeVisible();
  const before = requests.length;
  const toggle = page.getByRole("button", { name: "Auto-refresh", exact: true });
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-pressed", "true");
  await page.clock.runFor(15_500);
  await expect.poll(() => requests.length).toBeGreaterThan(before);
});

test("records show as one-line table rows with decision, service, and principal", async ({ page }) => {
  await fixture(page, { extraHistory: true });
  const table = page.getByRole("main").getByRole("table", { name: "Audit records", exact: true });
  await expect(table).toBeVisible();
  // Optional columns show when a loaded record has a value: Phase, Upstream, Node (only with several nodes), and Reason.
  expect(await columnHeaders(page)).toEqual(["Time", "Decision", "Service", "Action", "Principal", "Phase", "Upstream", "Node", "Reason"]);
  // Decision is a dot column: its header is for assistive tech only.
  await expect(table.getByRole("columnheader", { name: "Decision", exact: true }).locator(".wb-sr-only")).toHaveText("Decision");
  await expect(recordRow(page, "historical.read on retired").getByRole("cell").nth(5)).toHaveText("200 · 42 ms");
  await expect(recordRow(page, "historical.read on retired").getByRole("cell").nth(6)).toHaveText("node-b");
  await expect(recordRow(page, "admin.policy.grants.create on broker").getByRole("cell").nth(4)).toHaveText("success");
  // Newest first, grouped by day under a sticky group row.
  await expect(table.getByRole("rowheader", { name: /^Today/ })).toContainText("5 records");
  // Allowed stays a quiet dot (labelled for assistive tech); denials show their label, and the reason code has its own column.
  const login = recordRow(page, "auth.local.login on broker");
  await expect(login.getByRole("cell").nth(1)).toHaveText("Allowed");
  await expect(login.getByRole("cell").nth(1).getByTitle("Allowed", { exact: true })).toBeVisible();
  await expect(login.getByRole("cell").nth(7)).toHaveText("");
  const junk = recordRow(page, "unsupported.junk on jira");
  await expect(junk.getByRole("cell").nth(1)).toHaveText("Denied");
  await expect(junk.getByText("Denied", { exact: true })).toBeVisible();
  await expect(junk.getByRole("cell").nth(7)).toHaveText("service_action_unknown");
  // The action cell hugs the name and keeps the full name as its tooltip.
  await expect(junk.getByRole("rowheader")).toHaveAttribute("title", "unsupported.junk");
  // The service has its own column; broker management records name the related service.
  await expect(recordRow(page, "admin.policy.grants.create on broker").getByRole("cell").nth(2)).toHaveText("broker Related service: jira", { useInnerText: true });
  await expect(recordRow(page, "issue.view on jira").getByRole("cell").nth(2)).toHaveText("jira");
  await expect(recordRow(page, "issue.view on jira").getByRole("cell").nth(3)).toHaveText("Alice Example");
  // A plain click anywhere on the row opens its record.
  await recordRow(page, "issue.view on jira").getByRole("cell").nth(3).click();
  await expect(page).toHaveURL(new RegExp(`request=${REQUEST_ID}&record=issue$`));
  await expect(rowLinks(page).filter({ hasText: "issue.view on jira" })).toHaveAttribute("aria-current", "true");
  await expect(page.getByRole("complementary", { name: "Allowed: issue.view on jira" })).toBeVisible();
});

test("Activity names tokens and never offers a principal filter", async ({ page }) => {
  await fixture(page, { tier: "self" });
  await expect(page.getByText("Your own broker activity, including requests made with your agent tokens.", { exact: true })).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Principal", exact: true })).toHaveCount(0);
  await expect(page.getByRole("main").getByRole("table", { name: "Activity records", exact: true })).toBeVisible();
  expect(await columnHeaders(page)).toEqual(["Time", "Decision", "Service", "Action", "Token", "Phase"]);
  await expect(recordRow(page, "issue.view on jira").getByRole("cell").nth(3)).toHaveText("agent-one");
  await page.goto(`${baseUrl}/ui/activity?principal=bob`);
  await expect(page).toHaveURL(/\/ui\/activity$/);
});

test("long identifiers shrink with an ellipsis in a 1024px window with the drawer open", async ({ page }) => {
  await fixture(page, { longIdentifiers: true, viewport: { width: 1024, height: 800 } });
  const main = page.getByRole("main");
  const table = main.getByRole("table", { name: "Audit records", exact: true });
  const long = recordRow(page, `${LONG_ACTION} on jira`);
  await expect(long).toBeVisible();
  // A wide pane shows the full values.
  await expect(long.getByRole("rowheader")).toHaveAttribute("title", LONG_ACTION);
  await long.getByRole("cell").nth(3).click();
  await expect(page.getByRole("complementary", { name: `Allowed: ${LONG_ACTION} on jira` })).toBeVisible();
  // With the drawer open the table stays within the main pane; the full values stay in the tooltips.
  await expect.poll(async () => {
    const [tableBox, mainBox] = await Promise.all([table.boundingBox(), main.boundingBox()]);
    return Math.round(tableBox!.x + tableBox!.width - (mainBox!.x + mainBox!.width));
  }).toBeLessThanOrEqual(10);
  expect(await main.evaluate((element) => {
    const scroll = element.querySelector(".wb-scroll");
    return scroll ? scroll.scrollWidth - scroll.clientWidth : 0;
  })).toBeLessThanOrEqual(1);
  await expect(long.getByRole("rowheader")).toHaveAttribute("title", LONG_ACTION);
  await expect(long.getByRole("cell").nth(3)).toHaveAttribute("title", LONG_PRINCIPAL);
});

test("Activity leaves out the Token column when no loaded record has a token", async ({ page }) => {
  await fixture(page, { tier: "self", withoutTokens: true });
  await expect(page.getByRole("main").getByRole("table", { name: "Activity records", exact: true })).toBeVisible();
  await expect(rowLinks(page)).toHaveCount(3);
  expect(await columnHeaders(page)).toEqual(["Time", "Decision", "Service", "Action", "Phase"]);
});

const auditRepository = { kind: "resource", id: "historical-repository", displayName: "Payments API", displayNameTruncated: false, resourceType: "git_repository", selector: { kind: "exact", value: "engineering/payments" }, version: 1 };
const auditGroup = { kind: "resource_group", id: "historical-group", displayName: "Engineering repositories", displayNameTruncated: false, version: 2 };
function resourceAuditRecords() {
  return [
    record("resource-preflight", "broker", "admin.policy.resource_groups.patch", undefined, { providerAudit: { management: { phase: "preflight", target: { id: auditGroup.id } } } }),
    record("resource-success", "broker", "admin.policy.resource_groups.patch", undefined, { providerAudit: { management: { phase: "success", target: auditGroup, change: { before: { ...auditGroup, version: 1, includedCount: 0, excludedCount: 0 }, after: { ...auditGroup, includedCount: 1, excludedCount: 0 }, changedFields: ["includedResourceIds"], membership: { includedAdded: { count: 1, items: [auditRepository], truncated: false } } } } } })
  ];
}

for (const tier of ["admin", "auditor", "manager", "self"] as const) {
  test(`${tier} sees recorded membership names and only authorized current-entry links`, async ({ page }) => {
    const { apiRequests } = await fixture(page, { tier, resourceRecords: resourceAuditRecords() });
    const changed = rowLinks(page).filter({ hasText: /Added “Payments API” to “Engineering repositories”/ });
    await expect(changed).toBeVisible();
    await expect(rowLinks(page).filter({ hasText: "Attempt recorded: Update resource group" })).toBeVisible();
    await changed.click();
    const drawer = page.getByRole("complementary").filter({ has: page.getByRole("tab", { name: "Summary", exact: true }) });
    await expect(drawer.getByText("Included resources added (1)", { exact: true })).toBeVisible();
    await expect(drawer.getByText("Completed", { exact: true }).first()).toBeVisible();
    await expect(drawer.getByText(/Links open the current entry at that ID/)).toBeVisible();
    await expect(drawer.getByRole("button", { name: "Copy resource ID", exact: true })).toBeVisible();
    for (const label of ["Payments API", "Engineering repositories"]) {
      if (tier === "admin" || tier === "auditor") await expect(drawer.getByRole("link", { name: label, exact: true })).toBeVisible();
      else await expect(drawer.getByRole("link", { name: label, exact: true })).toHaveCount(0);
    }
    expect(apiRequests.some((url) => /\/v1\/admin\/policy\/(resources|resource-groups)(\/|$)/.test(url.pathname))).toBe(false);
    if (tier === "self") expect(apiRequests.some((url) => url.pathname.startsWith("/v1/admin/"))).toBe(false);
    await drawer.getByRole("tab", { name: /^Timeline/ }).click();
    await expect(drawer.getByRole("button", { name: /Attempt recorded: Update resource group/ })).toBeVisible();
    await expect(drawer.getByRole("button", { name: /Added “Payments API” to “Engineering repositories”/ })).toBeVisible();
    await drawer.getByRole("tab", { name: "Raw", exact: true }).click();
    await drawer.getByText("Record JSON", { exact: true }).click();
    await expect(drawer.locator("pre").filter({ hasText: '"auditId": "resource-success"' })).toContainText('"includedAdded"');
  });
}

test("historical links explain a missing current entry and browser Back retains the audit selection", async ({ page }) => {
  await fixture(page, { resourceRecords: resourceAuditRecords() });
  await rowLinks(page).filter({ hasText: /Added “Payments API”/ }).click();
  const original = page.url();
  const drawer = page.getByRole("complementary").filter({ has: page.getByRole("tab", { name: "Summary", exact: true }) });
  await drawer.getByRole("link", { name: "Payments API", exact: true }).click();
  await expect(page).toHaveURL(/resources\?item=historical-repository/);
  await expect(page.getByText("No current resource is available at this ID. It may have been deleted.", { exact: false })).toBeVisible();
  await page.goBack();
  await expect(page).toHaveURL(original);
  await expect(drawer.getByText("Included resources added (1)", { exact: true })).toBeVisible();
  await drawer.getByRole("link", { name: "Engineering repositories", exact: true }).click();
  await expect(page).toHaveURL(/resource-groups\?item=historical-group/);
  await expect(page.getByText("No current resource group is available at this ID. It may have been deleted.", { exact: false })).toBeVisible();
});

test("preflight without a visible terminal record remains an unknown outcome", async ({ page }) => {
  await fixture(page, { resourceRecords: resourceAuditRecords().slice(0, 1) });
  await rowLinks(page).filter({ hasText: "Attempt recorded: Update resource group" }).click();
  const drawer = page.getByRole("complementary").filter({ has: page.getByRole("tab", { name: "Summary", exact: true }) });
  await expect(drawer.getByText("Completion not recorded", { exact: true })).toBeVisible();
  await expect(drawer.getByText("Name not recorded. This event does not contain a resource snapshot.", { exact: true })).toBeVisible();
  await expect(drawer.getByText("Completed", { exact: true })).toHaveCount(0);
});

test("long and markup-like audit names render as text within a narrow drawer", async ({ page }) => {
  const longName = `<img src=x onerror=alert(1)> 支払い ${"repository ".repeat(35)}`;
  const renamed = { ...auditRepository, displayName: longName };
  const records = [record("long-resource", "broker", "admin.policy.resources.create", undefined, { providerAudit: { management: { phase: "success", target: renamed, change: { before: null, after: { ...renamed, enabled: true, allowedExecutionContexts: ["default"] }, changedFields: ["displayName", "selector"] } } } })];
  await fixture(page, { resourceRecords: records, viewport: { width: 900, height: 900 } });
  await rowLinks(page).filter({ hasText: /Created Git repository/ }).click();
  const drawer = page.getByRole("complementary").filter({ has: page.getByRole("tab", { name: "Summary", exact: true }) });
  await expect(drawer.getByRole("link", { name: longName, exact: true })).toBeVisible();
  await expect(drawer.locator("img")).toHaveCount(0);
  expect(await drawer.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
});

test("combined edits remain explicit in list, drawer and timeline while cleared names show Not set", async ({ page }) => {
  const renamed = { ...auditRepository, displayName: "Platform API", selector: { kind: "namespace", value: "engineering" } };
  const cleared = { ...renamed, displayName: null };
  const records = [
    record("combined-edit", "broker", "admin.policy.resources.patch", undefined, { providerAudit: { management: { phase: "success", target: renamed, change: { before: auditRepository, after: renamed, changedFields: ["displayName", "selector"] } } } }),
    record("cleared-name", "broker", "admin.policy.resources.patch", undefined, { providerAudit: { management: { phase: "success", target: cleared, change: { before: renamed, after: cleared, changedFields: ["displayName"] } } } })
  ];
  await fixture(page, { resourceRecords: records });
  const combinedSummary = "Renamed Git repository “Payments API” to “Platform API” — changed coverage";
  await expect(rowLinks(page).filter({ hasText: combinedSummary })).toBeVisible();
  await rowLinks(page).filter({ hasText: combinedSummary }).click();
  const drawer = page.getByRole("complementary").filter({ has: page.getByRole("tab", { name: "Summary", exact: true }) });
  await expect(drawer.getByRole("heading", { name: combinedSummary, exact: true })).toBeVisible();
  await drawer.getByRole("tab", { name: /^Timeline/ }).click();
  await expect(drawer.getByRole("button", { name: new RegExp(combinedSummary) })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(drawer).toHaveCount(0);
  await rowLinks(page).filter({ hasText: "Cleared display name of Git repository “Platform API”" }).click();
  await expect(drawer.getByText("Platform API → Not set", { exact: true })).toBeVisible();
  await expect(drawer.getByRole("link", { name: "Repositories under engineering", exact: true })).toBeVisible();
});
