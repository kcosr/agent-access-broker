import { test, expect, type Locator, type Page } from "@playwright/test";
import { createServer, type Server } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { AddressInfo } from "node:net";
import type { PrincipalRole } from "../src/types";
import { RESOURCE_TYPES } from "../unit/resource-types.fixture";
import { portalDist } from "./support/binaries";

// Deterministic browser contracts for search, navigation, asynchronous states,
// and capability gates. The real-store regression lives in portal.spec.ts.
let server: Server;
let baseUrl: string;
const envelope = (result: unknown) => ({ ok: true, result });
const stamp = { createdAt: "2026-10-01T00:00:00Z", updatedAt: "2026-10-01T00:00:00Z", createdBy: "viewer", updatedBy: "viewer" };
const resource = { id: "engineering-repository", displayName: "Payments repository", resourceType: "git_repository", selector: { kind: "exact", value: "engineering/payments" }, allowedExecutionContexts: ["default"], enabled: true, version: 1, ...stamp };
const excludedResource = { ...resource, id: "private-repository", displayName: "Restricted repository", selector: { kind: "exact", value: "engineering/private" }, enabled: false };
const resourceGroups = Array.from({ length: 8 }, (_, i) => ({ id: `portfolio-${i + 1}`, name: `Portfolio ${i + 1}`, includedResourceIds: [resource.id], excludedResourceIds: [excludedResource.id], version: 1, ...stamp }));
const userGroup = { groupId: "engineering-team", displayName: "Platform operators", description: "Incident response staff", status: "active", memberCount: 1, ...stamp };
const principal = { principalId: "viewer", kind: "user", role: "admin", selfServiceEnabled: true, displayName: "Morgan Example", email: "morgan@example.test", groups: [userGroup.groupId], status: "active", signInMethods: { localPassword: "active", microsoft: "absent" }, ...stamp };
const action = { action: "issue.inspect", description: "Inspect issue details", readOnly: true, requiredScopes: {}, credentialModes: ["service"], lookupRequired: false, inputSchema: { type: "object", properties: {} } };
const service = { service: "jira", displayName: "Jira", surface: "http", actions: [action], resourceScopes: {}, configuredCredentialModes: ["service"], lookupCredentialConfigured: false };
const catalog = { services: [service], subjects: { users: [principal], groups: [userGroup], anonymous: false }, resources: [resource, excludedResource], resourceGroups, executionContexts: { allowedValues: ["default"], defaultContext: "default", contextRequired: false } };
const config = { identityAuthority: "managed", policyAuthority: "managed", generation: 1, loadedAt: stamp.createdAt, configHash: "fixture" };
const grant = { grantRef: "engineering-read", grantId: "engineering-read", writable: true, version: 1, subjects: [`group:${userGroup.groupId}`], service: "jira", actions: [action.action], credentialMode: "service", executionContexts: ["default"], status: "active", resources: { resourceIds: [], resourceGroupIds: [] } };
const consumers = [{ service: "jira", displayName: "Jira", credentialVerificationInputs: [] }];
const target = { connection: "work-account", displayName: "Jira", consumers, otherConsumers: 0, profile: "personal", credentialKind: "bearer", inputSchema: { connection: "work-account", profile: "personal", credentialKind: "bearer", fields: [] } };
const credential = { credentialId: "credential-123", ownerPrincipal: "viewer", ownerKind: "user", connection: target.connection, profile: "personal", credentialKind: "bearer", metadata: {}, status: "active", ...stamp };
const credentialList = { connections: [{ connection: target.connection, displayName: "Jira", method: "token", consumers, otherConsumers: 0, profile: "personal", credentialKind: "bearer", registration: null, credential }], retained: [] };
const draftImport = { definition: { service: "metrics-draft", displayName: "Metrics draft", adapterKind: "mcp_http", endpoint: "https://metrics.example.test/mcp", executionBindings: [], connectionSettings: {}, discovery: { kind: "anonymous" }, transportAuth: false }, status: "draft", version: 1, actions: [], slotVersions: {}, ...stamp };

test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    const pathname = new URL(request.url!, "http://localhost").pathname;
    const asset = pathname.startsWith("/ui/assets/") ? pathname.slice(4) : "index.html";
    try {
      const content = await readFile(path.join(portalDist, asset));
      response.setHeader("content-type", asset.endsWith(".js") ? "text/javascript" : asset.endsWith(".css") ? "text/css" : "text/html");
      response.end(content);
    } catch { response.writeHead(404).end(); }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

test.afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

async function fixture(page: Page, role: PrincipalRole = "admin", selfServiceEnabled = true) {
  const session = { authenticated: true, principal: "viewer", role, selfServiceEnabled, policyManagementServices: role === "service_policy_manager" ? ["jira"] : [], auditQueryable: true, csrfHeader: "x-csrf-token", csrfToken: "test-csrf", signInMethods: { localPassword: "active", microsoft: "absent" }, loginOptions: { localPassword: { enabled: true } }, tokenIssuancePolicy: { selfAgentInvoke: { defaultTtl: "1h", maxTtl: "8h", options: ["1h"] } } };
  const requests: string[] = [];
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/v1/**", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    requests.push(pathname);
    let result: unknown = [];
    if (pathname === "/v1/auth/session") result = session;
    else if (pathname === "/v1/resource-types") result = { resourceTypes: RESOURCE_TYPES };
    else if (pathname === "/v1/me") result = { serviceLimits: [] };
    else if (pathname === "/v1/admin/config/status") result = config;
    else if (pathname === "/v1/admin/principals") result = [principal];
    else if (pathname === "/v1/admin/groups") result = [userGroup];
    else if (pathname === `/v1/admin/groups/${userGroup.groupId}`) result = { ...userGroup, members: [], policyReferenceSections: [] };
    else if (pathname === "/v1/admin/policy/status") result = { ...config, writable: role !== "auditor", policyGeneration: 1, counts: { active: 1, disabled: 0, deleted: 0 }, managementScope: role === "service_policy_manager" ? { kind: "services", services: ["jira"] } : { kind: "global" } };
    else if (pathname === "/v1/admin/policy/catalog") result = catalog;
    else if (pathname === "/v1/admin/policy/grants") result = [grant];
    else if (pathname === "/v1/admin/policy/resources") result = [resource, excludedResource];
    else if (pathname === "/v1/admin/policy/resource-groups") result = resourceGroups;
    else if (pathname.endsWith("/effective-access")) result = { policyGeneration: 1, access: [] };
    else if (pathname === "/v1/tokens/options") result = { policyGeneration: 1, executionContexts: ["default"], services: [{ ...service, executionContexts: ["default"], brokerHosts: [], actions: [{ requiredScopes: { "project": { resourceType: "jira_project" } }, ...action, executionContexts: ["default"], effectiveAccessByExecutionContext: { default: [{ scopes: {}, excludedRequests: [] }] } }] }], resources: [resource], resourceGroups: [] };
    else if (pathname === "/v1/credentials/targets") result = [target];
    else if (pathname === "/v1/credentials") result = credentialList;
    else if (pathname === "/v1/admin/imports") result = { catalogRevision: 1, operatorEnabled: true, availableKinds: ["mcp_http"], importAuthentication: [], services: [draftImport] };
    else if (pathname === "/v1/admin/imports/metrics-draft/preview") result = { service: draftImport, operatorAllowed: true, catalogRevision: 1, scopedMcp: { ready: false, issues: [], truncated: false }, scopedMcpWarnings: [], importAuthentication: [], affectedGrants: [], affectedGrantsByAction: {}, preview: null };
    else if (pathname.endsWith("/audit/options")) result = { services: [] };
    else if (pathname.endsWith("/audit/events")) result = { records: [], nextCursor: null };
    await route.fulfill({ json: envelope(result) });
  });
  await page.goto(`${baseUrl}/ui/account`);
  await expect(page.getByRole("main")).toBeVisible();
  return { session, requests, errors };
}

async function search(page: Page, query: string) {
  const palette = page.getByRole("dialog", { name: "Command palette", exact: true });
  if (!await palette.isVisible()) await page.keyboard.press("Control+k");
  await expect(palette).toBeVisible();
  await palette.getByRole("combobox").fill(query);
  return palette;
}

async function keyboardSelect(page: Page, palette: Locator, option: Locator) {
  const count = await palette.getByRole("option").count();
  for (let i = 0; i <= count; i++) {
    if (await option.getAttribute("aria-selected") === "true") {
      await page.keyboard.press("Enter");
      return;
    }
    await page.keyboard.press("ArrowDown");
  }
  throw new Error("Palette option was not reachable with the keyboard");
}

for (const role of ["admin", "auditor"] as const) {
  test(`${role} searches resource groups by name, ID and member and opens the group drawer`, async ({ page }) => {
    const model = await fixture(page, role);
    let palette = await search(page, "PORTFOLIO 8");
    await expect(palette.getByRole("group", { name: "Resource groups", exact: true }).getByRole("option", { name: /Portfolio 8/ })).toBeVisible();
    palette = await search(page, "portfolio-8");
    await palette.getByRole("group", { name: "Resource groups", exact: true }).getByRole("option", { name: /Portfolio 8/ }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/catalog\/resource-groups\?item=portfolio-8$/);
    await expect(page.getByRole("complementary", { name: "Resource group Portfolio 8", exact: true })).toBeVisible();
    palette = await search(page, "restricted");
    await expect(palette.getByRole("group", { name: "Resource groups", exact: true }).getByRole("option", { name: /Portfolio 1/ })).toBeVisible();
    palette = await search(page, "repository payments");
    await expect(palette.getByRole("group", { name: "Resources", exact: true }).getByRole("option", { name: /Payments repository/ })).toBeVisible();
    expect(model.errors).toEqual([]);
  });
}

test("user-group descriptions and grant subject display names are searchable", async ({ page }) => {
  const model = await fixture(page);
  let palette = await search(page, "incident response");
  await palette.getByRole("group", { name: "User groups", exact: true }).getByRole("option", { name: /Platform operators/ }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/groups\/engineering-team$/);
  await expect(page.getByRole("main")).toContainText("Platform operators");
  palette = await search(page, "platform operators");
  await expect(palette.getByRole("group", { name: "Grants", exact: true }).getByRole("option", { name: /engineering-read/ })).toBeVisible();
  expect(model.errors).toEqual([]);
});

test("nested page names navigate directly to the intended list", async ({ page }) => {
  const model = await fixture(page);
  for (const [label, pathname, kind] of [
    ["Resource groups", "/ui/admin/catalog/resource-groups", null],
    ["User groups", "/ui/admin/principals", "groups"],
    ["Service accounts", "/ui/admin/principals", "service-accounts"],
    ["Resources", "/ui/admin/catalog/resources", null]
  ] as const) {
    const palette = await search(page, label);
    await palette.getByRole("group", { name: "Go to", exact: true }).getByRole("option", { name: new RegExp(`^${label}`) }).click();
    await expect.poll(() => {
      const url = new URL(page.url());
      return { pathname: url.pathname, kind: url.searchParams.get("kind") };
    }).toEqual({ pathname, kind });
    await expect(page.getByRole("dialog", { name: "Command palette", exact: true })).toHaveCount(0);
  }
  expect(model.errors).toEqual([]);
});

test("overflow results expand with the keyboard and reset for a new query", async ({ page }) => {
  const model = await fixture(page);
  const palette = await search(page, "portfolio");
  const section = palette.getByRole("group", { name: "Resource groups", exact: true });
  const more = section.getByRole("option", { name: "Show all 8 Resource groups", exact: true });
  await expect(more).toBeVisible();
  await expect(section.getByRole("option", { name: /Portfolio 8/ })).toHaveCount(0);
  await keyboardSelect(page, palette, more);
  await expect(palette).toBeVisible();
  await expect(section.getByRole("option", { name: /Portfolio 8/ })).toBeVisible();
  await search(page, "portfolio-1");
  await search(page, "portfolio");
  await expect(more).toBeVisible();
  await expect(section.getByRole("option", { name: /Portfolio 8/ })).toHaveCount(0);
  await more.click();
  await expect(palette.getByRole("combobox")).toBeFocused();
  await page.keyboard.type("-8");
  await expect(palette.getByRole("combobox")).toHaveValue("portfolio-8");
  await expect(section.getByRole("option", { name: /Portfolio 8/ })).toBeVisible();
  expect(model.errors).toEqual([]);
});

for (const method of ["keyboard", "pointer"] as const) {
  test(`pending and failed resource-group requests retry with ${method} and keep focus`, async ({ page }) => {
    const model = await fixture(page);
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    let fail = true;
    await page.route("**/v1/admin/policy/resource-groups", async (route) => {
      if (fail) {
        await held;
        await route.fulfill({ status: 503, json: { ok: false, error: { message: "Temporary fixture failure" } } });
      } else await route.fulfill({ json: envelope(resourceGroups) });
    });
    const palette = await search(page, "portfolio-8");
    const liveStatus = palette.getByRole("status");
    const statusNode = await liveStatus.elementHandle();
    await expect(liveStatus).toHaveCount(1);
    await expect(liveStatus).toHaveAttribute("aria-live", "polite");
    await expect(liveStatus).toHaveAttribute("aria-atomic", "true");
    await expect(liveStatus).toContainText("Loading Resource groups…");
    await expect(palette.getByRole("listbox").getByRole("status")).toHaveCount(0);
    await expect(palette.getByRole("group", { name: "Resource groups", exact: true }).getByText("Loading Resource groups…", { exact: true })).toBeVisible();
    await expect(palette.getByText("No results", { exact: true })).toHaveCount(0);
    release();
    const retry = palette.getByRole("group", { name: "Resource groups", exact: true }).getByRole("option", { name: "Retry Resource groups", exact: true });
    await expect(retry).toBeVisible();
    await expect(liveStatus).toContainText("Could not load resource groups.");
    await expect(retry).toHaveAccessibleDescription("Could not load resource groups. Results may be incomplete.");
    expect(await liveStatus.evaluate((node, original) => node === original, statusNode)).toBe(true);
    await expect(palette.getByRole("listbox").getByRole("status")).toHaveCount(0);
    await expect(palette.getByText("No results", { exact: true })).toHaveCount(0);
    fail = false;
    if (method === "keyboard") await keyboardSelect(page, palette, retry);
    else await retry.click();
    await expect(palette).toBeVisible();
    await expect(palette.getByRole("combobox")).toBeFocused();
    await expect(palette.getByRole("group", { name: "Resource groups", exact: true }).getByRole("option", { name: /Portfolio 8/ })).toBeVisible();
    await expect(retry).toHaveCount(0);
    await expect(liveStatus).toHaveText(/\d+ results\./);
    expect(await liveStatus.evaluate((node, original) => node === original, statusNode)).toBe(true);
    await expect(palette.getByRole("status")).toHaveCount(1);
    expect(model.errors).toEqual([]);
  });
}

test("actions, draft imports, own credentials and audit search have usable destinations", async ({ page }) => {
  const model = await fixture(page);
  let palette = await search(page, "issue.inspect");
  await palette.getByRole("group", { name: "Service actions", exact: true }).getByRole("option").first().click();
  await expect.poll(() => new URL(page.url()).pathname).toBe("/ui/admin/catalog/services/jira");
  expect(new URL(page.url()).searchParams.get("action")).toBe(action.action);
  await expect(page.getByRole("complementary", { name: /issue.inspect/ })).toBeVisible();
  palette = await search(page, "metrics-draft");
  await palette.getByRole("group", { name: "Services", exact: true }).getByRole("option", { name: /Metrics draft/ }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/catalog\/services\/metrics-draft\/import$/);
  await expect(page.getByRole("main")).toContainText("Metrics draft");
  palette = await search(page, "credential-123");
  await palette.getByRole("group", { name: "Your credentials", exact: true }).getByRole("option").first().click();
  await expect.poll(() => new URL(page.url()).pathname).toBe("/ui/credentials");
  expect(new URL(page.url()).searchParams.get("credential")).toBe("work-account");
  await expect(page.getByRole("complementary", { name: /Jira/ })).toBeVisible();
  palette = await search(page, "investigation-123");
  await palette.getByRole("option", { name: /Search audit for/ }).click();
  await expect.poll(() => new URL(page.url()).pathname).toBe("/ui/admin/audit");
  expect(new URL(page.url()).searchParams.get("q")).toBe("investigation-123");
  expect(model.errors).toEqual([]);
});

for (const role of ["user", "service_policy_manager"] as const) {
  test(`${role} has scoped results without administrative entity requests or destinations`, async ({ page }) => {
    const model = await fixture(page, role, true);
    let palette = await search(page, "portfolio");
    for (const title of ["Principals", "User groups", "Resources", "Resource groups"]) {
      await expect(palette.getByRole("group", { name: title, exact: true })).toHaveCount(0);
    }
    palette = await search(page, "issue.inspect");
    await palette.getByRole("group", { name: "Service actions", exact: true }).getByRole("option").first().click();
    await expect.poll(() => new URL(page.url()).pathname).toBe(role === "user" ? "/ui/access" : "/ui/admin/policies");
    expect(new URL(page.url()).searchParams.get("service")).toBe("jira");
    await expect(page.getByText("Page not found", { exact: true })).toHaveCount(0);
    expect(model.requests.filter((url) => ["/v1/admin/principals", "/v1/admin/groups", "/v1/admin/policy/resources", "/v1/admin/policy/resource-groups", "/v1/admin/imports"].includes(url))).toEqual([]);
    expect(model.errors).toEqual([]);
  });
}

test("an auditor without self-service has no personal results or mutation commands", async ({ page }) => {
  const model = await fixture(page, "auditor", false);
  const palette = await search(page, "credential");
  await expect(palette.getByRole("group", { name: "Your credentials", exact: true })).toHaveCount(0);
  for (const query of ["create", "issue", "reload", "import service"]) {
    await search(page, query);
    for (const name of ["Create user", "Create service account", "Create group", "Create grant", "Issue agent token", "Reload runtime configuration", "Import service"]) {
      await expect(palette.getByRole("option", { name, exact: true })).toHaveCount(0);
    }
  }
  expect(model.requests.filter((url) => /^\/v1\/(tokens|credentials|oauth)(\/|$)/.test(url))).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("cached resource data stays searchable without empty loading sections during refresh", async ({ page }) => {
  const model = await fixture(page);
  const palette = await search(page, "portfolio-8");
  const groups = palette.getByRole("group", { name: "Resource groups", exact: true });
  await expect(groups.getByRole("option", { name: /Portfolio 8/ })).toBeVisible();
  await page.keyboard.press("Escape");
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  let refreshing = false;
  await page.route("**/v1/admin/policy/resource-groups", async (route) => {
    refreshing = true;
    await held;
    await route.fulfill({ json: envelope(resourceGroups) });
  });
  // Advance Date.now beyond the query's 30-second stale time without a sleep.
  await page.clock.setFixedTime(new Date(Date.now() + 60_000));
  try {
    await search(page, "portfolio-8");
    await expect.poll(() => refreshing).toBe(true);
    await expect(groups.getByRole("option", { name: /Portfolio 8/ })).toBeVisible();
    await expect(palette.getByText("Loading Resource groups…", { exact: true })).toHaveCount(0);
    await search(page, "investigation-123");
    await expect(palette.getByRole("option", { name: /Search audit for/ })).toBeVisible();
    await expect(groups).toHaveCount(0);
    await expect(palette.getByRole("group", { name: "Resources", exact: true })).toHaveCount(0);
    expect(model.errors).toEqual([]);
  } finally {
    release();
  }
});


test("empty search announces no results through the persistent live region", async ({ page }) => {
  const model = await fixture(page, "user");
  const palette = await search(page, "");
  const liveStatus = palette.getByRole("status");
  await expect(liveStatus).toHaveText(/\d+ results\./);
  const statusNode = await liveStatus.elementHandle();
  await palette.getByRole("combobox").fill("no-matching-fixture-entity");
  await expect(liveStatus).toHaveCount(1);
  await expect(liveStatus).toHaveText("No results");
  await expect(palette.getByRole("listbox").getByRole("status")).toHaveCount(0);
  await expect(palette.getByRole("listbox")).toContainText("No results");
  expect(await liveStatus.evaluate((node, original) => node === original, statusNode)).toBe(true);
  expect(model.errors).toEqual([]);
});

test("the issue-token command opens the dedicated self-service page", async ({ page }) => {
  const model = await fixture(page, "user", true);
  const palette = await search(page, "Issue agent token");
  await palette.getByRole("option", { name: "Issue agent token", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/tokens\/new/);
  await expect(page.getByRole("main", { name: "Issue agent token", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Issue agent token", exact: true })).toBeVisible();
  await expect(page.getByRole("dialog", { name: "Issue agent token", exact: true })).toHaveCount(0);
  expect(model.errors).toEqual([]);
});
