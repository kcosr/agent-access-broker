import { expect, test, type Locator, type Page } from "@playwright/test";
import type { AgentTokenIssueBody, AgentTokenOptions, PrincipalRole, Session } from "../src/types";
import { RESOURCE_TYPES } from "../unit/resource-types.fixture";
import { COMMAND_RESOURCE_TYPES } from "../unit/command-import.fixture";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

// These exercise portal contracts against explicit API fixtures. The real-service
// self/admin issuance and MCP reveal assertions remain in portal.spec.ts.
let assets: PortalAssets;
let baseUrl: string;
const envelope = (result: unknown) => ({ ok: true, result });
const stamp = { createdAt: "2026-10-14T00:00:00Z", updatedAt: "2026-10-14T00:00:00Z", createdBy: "viewer", updatedBy: "viewer" };
const ttlPolicy = { defaultTtl: "1h", maxTtl: "8h", options: ["1h", "8h"] };
const rawToken = "aab_test_one_time_token_page_secret";
const owner = (principalId: string, status = "active") => ({ principalId, kind: "user", displayName: principalId, role: "user", selfServiceEnabled: true, status, groups: [], signInMethods: { localPassword: "active", microsoft: "absent" }, groupMemberships: [], policyReferenceSections: [], activePolicyGroupSubjects: [], ...stamp });
const action = (action: string, readOnly: boolean, executionContexts = ["internal", "external"]) => ({ action, readOnly, description: `${action} description`, executionContexts, requiredScopeTypes: ["project"], resourceType: "jira_project" as const, effectiveAccessByExecutionContext: Object.fromEntries(executionContexts.map((context) => [context, [{ included: [{ kind: "all" as const }], excluded: [] }]])) });
function tokenOptions(): AgentTokenOptions {
  return {
    policyGeneration: 1,
    executionContexts: ["internal", "external"],
    resources: [{ id: "project", displayName: "Example project", resourceType: "jira_project", selector: { kind: "exact", value: "EXAMPLE" }, allowedExecutionContexts: ["internal", "external"], enabled: true }],
    resourceGroups: [{ id: "empty-group", name: "Empty group" }],
    services: [
      { service: "jira", displayName: "Jira", brokerHosts: [], executionContexts: ["internal", "external"], actions: [action("issue.view", true), action("comment.view", true), action("issue.internal", true, ["internal"]), action("issue.create", false), action("issue.update", false)] },
      { service: "tracker", displayName: "Tracker", brokerHosts: [], executionContexts: ["internal", "external"], actions: [action("record.view", true), action("record.create", false)] }
    ],
    mcp: null
  };
}

test.beforeAll(async () => {
  assets = await servePortalAssets();
  baseUrl = assets.baseUrl;
});
test.afterAll(async () => { await assets.close(); });

async function fixture(page: Page, role: PrincipalRole = "user", selfServiceEnabled = true) {
  const model = {
    session: { authenticated: true, principal: "viewer", role, selfServiceEnabled, policyManagementServices: [], csrfHeader: "x-csrf-token", csrfToken: "fixture", loginOptions: { localPassword: { enabled: true } }, tokenIssuancePolicy: { selfAgentInvoke: ttlPolicy, administered: { agentInvoke: ttlPolicy, userManage: ttlPolicy, admin: ttlPolicy } } } as Session,
    options: tokenOptions(),
    principalStatus: "active",
    requests: [] as string[],
    previews: [] as AgentTokenIssueBody[],
    invalidPreviews: [] as AgentTokenIssueBody[],
    issued: [] as { pathname: string; body: AgentTokenIssueBody }[],
    records: [] as unknown[],
    errors: [] as string[],
    issueWait: Promise.resolve(),
    optionReads: 0,
    sessionReads: 0
  };
  page.on("pageerror", (error) => model.errors.push(error.message));
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    model.requests.push(pathname);
    let result: unknown = [];
    if (pathname === "/v1/auth/session") { model.sessionReads++; result = model.session; }
    else if (pathname === "/v1/auth/logout") { model.session = { authenticated: false, loginOptions: { localPassword: { enabled: true } } }; result = model.session; }
    else if (pathname === "/v1/resource-types") {
      // A discovery route: its body is the result itself, without an envelope.
      await route.fulfill({ json: { resourceTypes: [...RESOURCE_TYPES, ...COMMAND_RESOURCE_TYPES] } });
      return;
    }
    else if (pathname.endsWith("/tokens/options") || pathname.endsWith("/agent-token-options")) { model.optionReads++; result = model.options; }
    else if (pathname === "/v1/credentials") result = { connections: [], retained: [] };
    else if ((pathname.endsWith("/effective-access") || pathname.endsWith("/agent-token-effective-access"))) {
      const body = request.postDataJSON() as AgentTokenIssueBody;
      model.previews.push(body);
      // Match the backend's structural rejection instead of concealing the bug
      // with an unconditional successful empty preview.
      const restrictions = body.serviceRestrictions ?? {};
      const invalid = !body.allowedExecutionContexts?.length || (body.allowedServices !== undefined && (!body.allowedServices.length || body.allowedServices.some((service) => !Object.hasOwn(restrictions, service) || !restrictions[service].actions.length)));
      if (invalid) {
        model.invalidPreviews.push(body);
        await route.fulfill({ status: 400, json: { ok: false, reasonCode: "input_invalid", error: { message: "allowedServices, actions, and contexts must not be empty" } } });
        return;
      }
      result = { policyGeneration: model.options.policyGeneration, access: [] };
    } else if (pathname === "/v1/tokens" || /\/v1\/admin\/principals\/[^/]+\/agent-tokens$/.test(pathname)) {
      if (request.method() === "POST") {
        const body = request.postDataJSON() as AgentTokenIssueBody;
        model.issued.push({ pathname, body });
        await model.issueWait;
        const principalId = pathname === "/v1/tokens" ? "viewer" : pathname.split("/")[4];
        const record = { tokenId: "tok_created", principalId, name: body.name, tokenClass: "agent_invoke", scopes: body, ...stamp };
        model.records = [record];
        result = { token: rawToken, record };
      } else result = model.records;
    } else if (/\/v1\/admin\/principals\/[^/]+$/.test(pathname)) result = owner(pathname.split("/").at(-1)!, model.principalStatus);
    else if (pathname === "/v1/admin/principals") result = [owner("target", model.principalStatus), owner("other"), owner("viewer")];
    else if (pathname.endsWith("/login-methods")) result = [];
    else if (pathname.endsWith("/identity-token")) result = { principalId: "viewer", configured: false, enabled: true, readOnly: false, revision: 1, updatedAt: stamp.createdAt };
    else if (pathname.endsWith("/identity-access")) result = { principalId: "viewer", incarnation: "fixture", paused: false, version: 1, ...stamp };
    else if (pathname.endsWith("/identity-bindings")) result = { bindings: [], configuredNamespaces: [] };
    else if (pathname === "/v1/admin/policy/catalog") result = { services: [], subjects: { users: [], groups: [], anonymous: false }, resources: [], resourceGroups: [], executionContexts: { allowedValues: ["internal", "external"], defaultContext: "internal" } };
    else if (pathname === "/v1/admin/policy/status") result = { policyGeneration: 1, writable: true, authority: "managed", counts: { active: 0, disabled: 0, deleted: 0 }, managementScope: { kind: "global" } };
    else if (pathname === "/v1/me") result = { serviceLimits: [] };
    else if (pathname === "/v1/admin/config/status") result = { identityAuthority: "managed", policyAuthority: "managed", generation: 1, loadedAt: stamp.createdAt, configHash: "fixture" };
    else if (pathname.endsWith("/audit/options")) result = { services: [] };
    else if (pathname.endsWith("/audit/events")) result = { records: [], nextCursor: null };
    await route.fulfill({ json: envelope(result) });
  });
  return model;
}

const editor = (page: Page) => page.getByRole("main", { name: "Issue agent token", exact: true });
const service = (page: Page, name: string) => editor(page).getByRole("group", { name: `${name.toLowerCase()} token access`, exact: true });
const reads = (group: Locator) => group.getByRole("group", { name: "Read-only", exact: true });
const writes = (group: Locator) => group.getByRole("group", { name: "Write-capable", exact: true });
async function restrict(page: Page) {
  await editor(page).getByRole("group", { name: "Access", exact: true }).getByRole("button", { name: "Restrict to selected", exact: true }).click();
}
async function refreshQueries(page: Page) {
  // Queries deliberately do not refetch on window focus. Reconnection refetches
  // stale active queries, as a real network reconnection would.
  await page.clock.setFixedTime(new Date(await page.evaluate(() => Date.now()) + 120_000));
  await page.evaluate(() => { window.dispatchEvent(new Event("offline")); window.dispatchEvent(new Event("online")); });
}

test("incomplete boundaries never request a preview, while names do not refetch valid boundaries", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await expect(editor(page)).toBeVisible();
  await expect.poll(() => model.previews.length).toBe(1);
  expect(model.previews[0]).toEqual({ allowedExecutionContexts: ["internal", "external"] });
  await restrict(page);
  await expect(editor(page).getByRole("button", { name: "Issue token", exact: true })).toBeDisabled();
  const count = model.previews.length;
  await editor(page).getByRole("checkbox", { name: "jira", exact: true }).check();
  await expect(editor(page)).toContainText("Select at least one action");
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("still-incomplete");
  expect(model.previews).toHaveLength(count);
  await reads(service(page, "Jira")).getByLabel("issue.view", { exact: true }).check();
  await expect.poll(() => model.previews.length).toBe(count + 1);
  await expect(editor(page).getByRole("button", { name: "Issue token", exact: true })).toBeEnabled();
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("a different name");
  await expect(editor(page).getByText("No access currently", { exact: true }).last()).toBeVisible();
  expect(model.previews).toHaveLength(count + 1);
  const contexts = editor(page).getByRole("group", { name: "Execution contexts", exact: true });
  await contexts.getByLabel("internal", { exact: true }).uncheck();
  await expect.poll(() => model.previews.length).toBe(count + 2);
  await contexts.getByLabel("external", { exact: true }).uncheck();
  await expect(editor(page).getByRole("button", { name: "Issue token", exact: true })).toBeDisabled();
  expect(model.previews).toHaveLength(count + 2);
  expect(model.invalidPreviews).toEqual([]);
  expect(model.issued).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("empty selected resources and live empty groups remain valid previews and issue exact restrictions", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await restrict(page);
  await editor(page).getByRole("checkbox", { name: "jira", exact: true }).check();
  await editor(page).getByLabel("issue.view", { exact: true }).check();
  await editor(page).getByRole("group", { name: "jira resources", exact: true }).getByRole("button", { name: "Selected resources and groups", exact: true }).click();
  await expect.poll(() => model.previews.at(-1)?.serviceRestrictions?.jira?.resources).toEqual({ resourceIds: [], resourceGroupIds: [] });
  await expect(editor(page).getByText("No access currently", { exact: true }).last()).toBeVisible();
  await editor(page).getByLabel("Empty group", { exact: true }).check();
  await expect.poll(() => model.previews.at(-1)?.serviceRestrictions?.jira?.resources).toEqual({ resourceIds: [], resourceGroupIds: ["empty-group"] });
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("empty-is-valid");
  await editor(page).getByRole("button", { name: "Issue token", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Token created", exact: true })).toBeVisible();
  expect(model.issued).toEqual([{
    pathname: "/v1/tokens",
    body: {
      name: "empty-is-valid", ttl: "1h", allowedExecutionContexts: ["internal", "external"], allowedServices: ["jira"],
      serviceRestrictions: { jira: { actions: ["issue.view"], resources: { resourceIds: [], resourceGroupIds: ["empty-group"] } } }
    }
  }]);
  await expect(page).toHaveURL(/\/ui\/tokens\?token=tok_created$/);
  expect(page.url()).not.toContain(rawToken);
  expect(await page.evaluate(() => JSON.stringify({ local: localStorage, session: sessionStorage, history: history.state }))).not.toContain(rawToken);
  expect(model.invalidPreviews).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("each service shares the grant picker with independent filters and scoped bulk selection", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await restrict(page);
  for (const name of ["jira", "tracker"]) await editor(page).getByRole("checkbox", { name, exact: true }).check();
  const jira = service(page, "Jira");
  const tracker = service(page, "Tracker");
  const jiraFilter = jira.getByRole("searchbox", { name: "Filter jira actions", exact: true });
  const trackerFilter = tracker.getByRole("searchbox", { name: "Filter tracker actions", exact: true });
  const bounds = await Promise.all([reads(jira), writes(jira)].map((column) => column.boundingBox()));
  expect(bounds[1]!.x).toBeGreaterThan(bounds[0]!.x);
  expect(Math.abs(bounds[0]!.y - bounds[1]!.y)).toBeLessThan(2);
  await reads(jira).getByLabel("comment.view", { exact: true }).check();
  await writes(jira).getByLabel("issue.update", { exact: true }).check();
  await jiraFilter.fill("issue.view");
  await reads(jira).getByRole("button", { name: "Select all matching read-only actions", exact: true }).click();
  await trackerFilter.fill("record.create");
  await writes(tracker).getByRole("button", { name: "Select all matching write-capable actions", exact: true }).click();
  await expect(jiraFilter).toHaveValue("issue.view");
  await reads(jira).getByRole("button", { name: "Select none of the matching read-only actions", exact: true }).click();
  await jiraFilter.fill("");
  await expect(reads(jira).getByLabel("comment.view", { exact: true })).toBeChecked();
  await expect(writes(jira).getByLabel("issue.update", { exact: true })).toBeChecked();
  await expect(reads(jira).getByLabel("issue.view", { exact: true })).not.toBeChecked();
  await expect(trackerFilter).toHaveValue("record.create");
  await expect(writes(tracker).getByLabel("record.create", { exact: true })).toBeChecked();
  await expect.poll(() => model.previews.at(-1)?.serviceRestrictions).toEqual({ jira: { actions: ["comment.view", "issue.update"] }, tracker: { actions: ["record.create"] } });
  expect(model.invalidPreviews).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("selected context-ineligible reads retain metadata and are removable; refreshed options preserve the owner draft", async ({ page }) => {
  const model = await fixture(page, "admin");
  await page.goto(`${baseUrl}/ui/admin/principals/target/tokens/new`);
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("owner-draft");
  await restrict(page);
  await editor(page).getByRole("checkbox", { name: "jira", exact: true }).check();
  const jira = service(page, "Jira");
  await reads(jira).getByLabel("issue.internal", { exact: true }).check();
  await editor(page).getByRole("group", { name: "Execution contexts", exact: true }).getByLabel("internal", { exact: true }).uncheck();
  await expect(reads(jira).getByLabel("issue.internal", { exact: true })).toBeChecked();
  await expect(writes(jira).getByLabel("issue.internal", { exact: true })).toHaveCount(0);
  await expect(reads(jira)).toContainText("Unavailable");
  await reads(jira).getByLabel("issue.view", { exact: true }).check();
  model.options = { ...model.options, policyGeneration: 2, services: model.options.services.map((entry) => ({ ...entry, actions: entry.actions.filter((entry) => entry.action !== "issue.view") })) };
  const previous = model.optionReads;
  await refreshQueries(page);
  await expect.poll(() => model.optionReads).toBeGreaterThan(previous);
  await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("owner-draft");
  await expect(editor(page).getByRole("heading", { name: "Issue agent token", exact: true })).toBeVisible();
  await expect(editor(page)).toContainText("For target");
  await expect(writes(jira).getByLabel("issue.view", { exact: true })).toBeChecked();
  await expect(writes(jira)).toContainText("Not currently granted");
  await reads(jira).getByLabel("issue.internal", { exact: true }).click();
  await expect(reads(jira).getByLabel("issue.internal", { exact: true })).toHaveCount(0);
  await writes(jira).getByLabel("issue.view", { exact: true }).click();
  await expect(writes(jira).getByLabel("issue.view", { exact: true })).toHaveCount(0);
  expect(model.errors).toEqual([]);
});

test("token action columns stack without horizontal overflow on a narrow viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const model = await fixture(page);
  model.options.services[0].actions.push({ ...action("an.unusually.long.imported.action.identifier.that.must.wrap.within.the.column", true), description: "A long imported description should wrap across lines without pushing the selector beyond the available viewport width." });
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await restrict(page);
  await editor(page).getByRole("checkbox", { name: "jira", exact: true }).check();
  const jira = service(page, "Jira");
  const bounds = await Promise.all([reads(jira), writes(jira)].map((column) => column.boundingBox()));
  expect(Math.abs(bounds[0]!.x - bounds[1]!.x)).toBeLessThan(2);
  expect(bounds[1]!.y).toBeGreaterThanOrEqual(bounds[0]!.y + bounds[0]!.height);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  expect(await jira.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  const issueBounds = await editor(page).getByRole("button", { name: "Issue token", exact: true }).boundingBox();
  expect(issueBounds!.x).toBeGreaterThanOrEqual(0);
  expect(issueBounds!.x + issueBounds!.width).toBeLessThanOrEqual(390);
  expect(issueBounds!.y + issueBounds!.height).toBeLessThanOrEqual(844);
  expect(model.errors).toEqual([]);
});

for (const [role, selfServiceEnabled, pathname] of [
  ["user", false, "/ui/tokens/new"],
  ["auditor", true, "/ui/admin/principals/target/tokens/new"],
  ["service_policy_manager", true, "/ui/admin/principals/target/tokens/new"]
] as const) {
  test(`${role} direct token route requires its own issuance authority: ${pathname}`, async ({ page }) => {
    const model = await fixture(page, role, selfServiceEnabled);
    await page.goto(`${baseUrl}${pathname}`);
    await expect(page.getByText("Page not found", { exact: true })).toBeVisible();
    expect(model.optionReads).toBe(0);
    expect(model.previews).toEqual([]);
    expect(model.issued).toEqual([]);
    expect(model.errors).toEqual([]);
  });
}

test("a disabled administered owner has no issuance form or preview", async ({ page }) => {
  const model = await fixture(page, "admin");
  model.principalStatus = "disabled";
  await page.goto(`${baseUrl}/ui/admin/principals/target/tokens/new`);
  await expect(page.getByRole("heading", { name: "Issue agent token", exact: true })).toBeVisible();
  await expect(editor(page)).toContainText(/disabled/i);
  await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveCount(0);
  expect(model.previews).toEqual([]);
  expect(model.issued).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("dirty Cancel preserves the draft until discard and honors its return destination", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${baseUrl}/ui/tokens/new?returnTo=${encodeURIComponent("/ui/access?service=jira")}`);
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("unsaved");
  await editor(page).getByRole("button", { name: "Cancel", exact: true }).click();
  const confirm = page.getByRole("alertdialog", { name: "Discard changes?", exact: true });
  await expect(confirm).toBeVisible();
  await confirm.getByRole("button", { name: "Keep editing", exact: true }).click();
  await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("unsaved");
  await editor(page).getByRole("button", { name: "Cancel", exact: true }).click();
  await confirm.getByRole("button", { name: "Discard changes", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/access\?service=jira$/);
  expect(model.issued).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("browser Back asks before discarding a dirty draft and completes after Discard", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${baseUrl}/ui/tokens`);
  await page.getByRole("button", { name: "Issue token", exact: true }).first().click();
  await expect(page).toHaveURL(/\/ui\/tokens\/new\?returnTo=%2Fui%2Ftokens$/);
  const name = editor(page).getByRole("textbox", { name: "Name", exact: true });
  await name.fill("unsaved");
  const confirm = page.getByRole("alertdialog", { name: "Discard changes?", exact: true });
  await page.goBack();
  await confirm.getByRole("button", { name: "Keep editing", exact: true }).click();
  await expect(confirm).toHaveCount(0);
  await expect(page).toHaveURL(/\/ui\/tokens\/new\?returnTo=%2Fui%2Ftokens$/);
  await expect(name).toHaveValue("unsaved");
  await page.goBack();
  await confirm.getByRole("button", { name: "Discard changes", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/tokens$/);
  await expect(confirm).toHaveCount(0);
  await expect(editor(page)).toHaveCount(0);
  expect(model.issued).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("the footer counts issues in page order and its link reveals the first one", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await restrict(page);
  await editor(page).getByRole("checkbox", { name: "jira", exact: true }).check();
  const footer = editor(page).getByRole("region", { name: "Issue token", exact: true });
  await expect(footer.getByRole("status")).toHaveText("2 issues · Enter a token name.");
  await expect(footer).not.toHaveClass(/wb-draftbar--neutral/);
  await footer.getByRole("button", { name: "Enter a token name.", exact: true }).click();
  await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toBeFocused();
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("named");
  await expect(footer.getByRole("status")).toHaveText("1 issue · Select at least one action for Jira.");
  await editor(page).getByRole("button", { name: "Collapse Jira", exact: true }).click();
  await expect(service(page, "Jira")).toHaveCount(0);
  await footer.getByRole("button", { name: "Select at least one action for Jira.", exact: true }).click();
  await expect(reads(service(page, "Jira")).getByLabel("issue.view", { exact: true })).toBeFocused();
  await reads(service(page, "Jira")).getByLabel("issue.view", { exact: true }).check();
  await expect(footer.getByRole("status")).toHaveText("Ready to issue. Restrictions cannot be edited after issuance.");
  await expect(footer).toHaveClass(/wb-draftbar--neutral/);
  expect(model.issued).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("an action issue focuses the action filter when the filter hides every action", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await restrict(page);
  await editor(page).getByRole("checkbox", { name: "jira", exact: true }).check();
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("named");
  const filter = service(page, "Jira").getByRole("searchbox", { name: "Filter jira actions", exact: true });
  await filter.fill("no-such-action");
  await editor(page).getByRole("group", { name: "jira resources", exact: true }).getByRole("button", { name: "Selected resources and groups", exact: true }).click();
  await editor(page).getByRole("region", { name: "Issue token", exact: true }).getByRole("button", { name: "Select at least one action for Jira.", exact: true }).click();
  await expect(filter).toBeFocused();
  expect(model.errors).toEqual([]);
});

test("the summary counts each service's selection and opens a collapsed service", async ({ page }) => {
  const model = await fixture(page);
  model.options.resources.push({ id: "space", displayName: "Example space", resourceType: "confluence_space", selector: { kind: "exact", value: "SPACE" }, allowedExecutionContexts: ["internal", "external"], enabled: true });
  await page.goto(`${baseUrl}/ui/tokens/new?service=jira`);
  const summary = editor(page).getByRole("complementary", { name: "Token summary", exact: true });
  await expect(summary).toContainText("1 service");
  await expect(summary.getByRole("button", { name: /^Jira/ })).toContainText("5 of 5 actions · all granted resources");
  await editor(page).getByRole("group", { name: "jira resources", exact: true }).getByRole("button", { name: "Selected resources and groups", exact: true }).click();
  // Only resource types the service's actions use are offered.
  await expect(service(page, "Jira").getByRole("checkbox", { name: /^Example project/ })).toBeVisible();
  await expect(service(page, "Jira").getByRole("checkbox", { name: /^Example space/ })).toHaveCount(0);
  await service(page, "Jira").getByLabel("Empty group", { exact: true }).check();
  await expect(summary.getByRole("button", { name: /^Jira/ })).toContainText("5 of 5 actions · 1 group");
  await editor(page).getByRole("button", { name: "Collapse Jira", exact: true }).click();
  await expect(service(page, "Jira")).toHaveCount(0);
  await summary.getByRole("button", { name: /^Jira/ }).click();
  await expect(service(page, "Jira")).toBeVisible();
  await expect(editor(page).getByRole("button", { name: "Collapse Jira", exact: true })).toHaveAttribute("aria-expanded", "true");
  expect(model.errors).toEqual([]);
});

test("pending issuance prevents duplicate submission and navigation; success replaces the editor and retains reveal", async ({ page }) => {
  const model = await fixture(page);
  let release!: () => void;
  model.issueWait = new Promise<void>((resolve) => { release = resolve; });
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("single-dispatch");
  // Two clicks before another browser task must still dispatch only one POST.
  await editor(page).getByRole("button", { name: "Issue token", exact: true }).evaluate((element) => { (element as HTMLButtonElement).click(); (element as HTMLButtonElement).click(); });
  await expect.poll(() => model.issued.length).toBe(1);
  await expect(editor(page).getByRole("button", { name: /Issuing|Issue token/ })).toBeDisabled();
  await page.getByRole("navigation", { name: "My access", exact: true }).getByRole("link", { name: "Access", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/tokens\/new$/);
  await expect(page.getByText(/Wait for issuance to finish before leaving this page\./)).toBeVisible();
  await expect(page.getByRole("button", { name: "Discard changes", exact: true })).toHaveCount(0);
  release();
  const reveal = page.getByRole("dialog", { name: "Token created", exact: true });
  await expect(reveal.getByLabel("Token", { exact: true })).toHaveText(rawToken);
  await expect(page).toHaveURL(/\/ui\/tokens\?token=tok_created$/);
  await expect(page.getByRole("alertdialog", { name: "Discard changes?", exact: true })).toHaveCount(0);
  expect(model.issued).toHaveLength(1);
  expect(await page.evaluate(() => JSON.stringify({ local: localStorage, session: sessionStorage, history: history.state }))).not.toContain(rawToken);
  expect(model.errors).toEqual([]);
});

for (const change of ["signed-out", "different-viewer", "same-viewer-capabilities", "same-viewer-role-change"] as const) {
  test(`a late issuance response handles ${change} using the current session`, async ({ page }) => {
    const model = await fixture(page);
    let release!: () => void;
    model.issueWait = new Promise<void>((resolve) => { release = resolve; });
    await page.goto(`${baseUrl}/ui/tokens/new`);
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("late-response");
    await editor(page).getByRole("button", { name: "Issue token", exact: true }).click();
    await expect.poll(() => model.issued.length).toBe(1);
    model.session = change === "signed-out"
      ? { authenticated: false, loginOptions: { localPassword: { enabled: true } } }
      : { ...model.session, ...(change === "different-viewer" ? { principal: "someone-else" } : change === "same-viewer-role-change" ? { role: "admin" } : { selfServiceEnabled: false }) };
    const previous = model.sessionReads;
    await refreshQueries(page);
    await expect.poll(() => model.sessionReads).toBeGreaterThan(previous);
    if (change === "signed-out") await expect(page.getByLabel("Password", { exact: true })).toBeVisible();
    if (change === "same-viewer-capabilities") await expect(page.getByText("Page not found", { exact: true })).toBeVisible();
    // A different viewer replaces the previous viewer's draft with a fresh one.
    if (change === "different-viewer") await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("");
    if (change === "same-viewer-role-change") {
      await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("");
      await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toBeDisabled();
      await expect(editor(page).getByRole("button", { name: "Issue token", exact: true })).toBeDisabled();
    }
    const response = page.waitForResponse((response) => response.request().method() === "POST" && new URL(response.url()).pathname === "/v1/tokens");
    release();
    await (await response).finished();
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    const reveal = page.getByRole("dialog", { name: "Token created", exact: true });
    if (change === "same-viewer-capabilities" || change === "same-viewer-role-change") {
      await expect(reveal.getByLabel("Token", { exact: true })).toHaveText(rawToken);
      await expect(page).toHaveURL(/\/ui\/tokens\?token=tok_created$/);
    } else {
      await expect(reveal).toHaveCount(0);
      await expect(page.getByText(rawToken, { exact: true })).toHaveCount(0);
    }
    expect(model.issued).toHaveLength(1);
    expect(page.url()).not.toContain(rawToken);
    expect(await page.evaluate(() => JSON.stringify({ local: localStorage, session: sessionStorage, history: history.state }))).not.toContain(rawToken);
    expect(model.errors).toEqual([]);
  });
}

test("Access toolbar and action drawer preserve full-service prefills", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${baseUrl}/ui/access?service=jira`);
  await page.getByRole("button", { name: "Issue token", exact: true }).first().click();
  await expect(page).toHaveURL(/\/ui\/tokens\/new\?/);
  const jira = service(page, "Jira");
  for (const action of model.options.services[0].actions) await expect(jira.getByLabel(action.action, { exact: true })).toBeChecked();
  await expect(editor(page).getByRole("checkbox", { name: "tracker", exact: true })).not.toBeChecked();
  await editor(page).getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/access\?service=jira$/);
  await page.getByRole("link", { name: "issue.view", exact: true }).click();
  await page.getByRole("button", { name: "Issue token for Jira", exact: true }).click();
  for (const action of model.options.services[0].actions) await expect(jira.getByLabel(action.action, { exact: true })).toBeChecked();
  expect(model.errors).toEqual([]);
});

test("the token empty-state action opens a clean creation page", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${baseUrl}/ui/tokens`);
  await expect(page.getByRole("heading", { name: "No agent tokens yet", exact: true })).toBeVisible();
  const issueButtons = page.getByRole("button", { name: "Issue token", exact: true });
  await expect(issueButtons).toHaveCount(2);
  await issueButtons.last().click();
  await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("");
  await expect(editor(page).getByRole("checkbox", { name: "jira", exact: true })).toHaveCount(0);
  expect(model.errors).toEqual([]);
});

test("an initialized owner draft survives empty grant and lifetime-policy refreshes", async ({ page }) => {
  const model = await fixture(page);
  const originalOptions = model.options;
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("retained-draft");
  await restrict(page);
  await editor(page).getByRole("checkbox", { name: "jira", exact: true }).check();
  await reads(service(page, "Jira")).getByLabel("issue.view", { exact: true }).check();
  await editor(page).getByRole("group", { name: "jira resources", exact: true }).getByRole("button", { name: "Selected resources and groups", exact: true }).click();
  await editor(page).getByLabel("Empty group", { exact: true }).check();
  model.options = { ...model.options, policyGeneration: 2, services: [], executionContexts: [], resources: [], resourceGroups: [] };
  let previous = model.optionReads;
  await refreshQueries(page);
  await expect.poll(() => model.optionReads).toBeGreaterThan(previous);
  await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("retained-draft");
  await expect(editor(page).getByRole("checkbox", { name: "jira", exact: true })).toBeChecked();
  await expect(service(page, "Jira").getByLabel("issue.view", { exact: true })).toBeChecked();
  await expect(editor(page).getByRole("button", { name: "Issue token", exact: true })).toBeDisabled();
  model.options = { ...originalOptions, policyGeneration: 3 };
  model.session = { ...model.session, tokenIssuancePolicy: undefined };
  previous = model.optionReads;
  await refreshQueries(page);
  await expect.poll(() => model.optionReads).toBeGreaterThan(previous);
  await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("retained-draft");
  await expect(editor(page).getByRole("button", { name: "Issue token", exact: true })).toBeDisabled();
  model.session = { ...model.session, tokenIssuancePolicy: { selfAgentInvoke: ttlPolicy } };
  const sessionReads = model.sessionReads;
  await refreshQueries(page);
  await expect.poll(() => model.sessionReads).toBeGreaterThan(sessionReads);
  await expect(editor(page).getByRole("button", { name: "Issue token", exact: true })).toBeEnabled();
  await expect(editor(page).getByLabel("Empty group", { exact: true })).toBeChecked();
  await expect(editor(page).getByRole("group", { name: "Execution contexts", exact: true }).getByRole("checkbox")).toHaveCount(2);
  for (const context of ["internal", "external"]) await expect(editor(page).getByRole("group", { name: "Execution contexts", exact: true }).getByLabel(context, { exact: true })).toBeChecked();
  expect(model.issued).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("reopening the token command preserves the current draft and cancel destination", async ({ page }) => {
  const model = await fixture(page);
  const initial = `${baseUrl}/ui/tokens/new?returnTo=${encodeURIComponent("/ui/access?service=jira")}`;
  await page.goto(initial);
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("keep-this-draft");
  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog", { name: "Command palette", exact: true });
  await palette.getByRole("combobox").fill("Issue agent token");
  await palette.getByRole("option", { name: "Issue agent token", exact: true }).click();
  await expect(page).toHaveURL(initial);
  await expect(page.getByRole("alertdialog", { name: "Discard changes?", exact: true })).toHaveCount(0);
  await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("keep-this-draft");
  expect(model.issued).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("discarding into a different service-prefilled URL resets the owner draft", async ({ page }) => {
  const model = await fixture(page);
  const destination = "/ui/tokens/new?service=tracker";
  await page.goto(`${baseUrl}/ui/tokens/new?service=jira&returnTo=${encodeURIComponent(destination)}`);
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("discard-this-draft");
  await expect(editor(page).getByRole("checkbox", { name: "jira", exact: true })).toBeChecked();
  await editor(page).getByRole("button", { name: "Cancel", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Discard changes?", exact: true }).getByRole("button", { name: "Discard changes", exact: true }).click();
  await expect(page).toHaveURL(`${baseUrl}${destination}`);
  await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("");
  await expect(editor(page).getByRole("checkbox", { name: "jira", exact: true })).not.toBeChecked();
  await expect(editor(page).getByRole("checkbox", { name: "tracker", exact: true })).toBeChecked();
  for (const action of model.options.services[1].actions) await expect(service(page, "Tracker").getByLabel(action.action, { exact: true })).toBeChecked();
  expect(model.issued).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("a service named constructor keeps its own explicit action and resource restrictions", async ({ page }) => {
  const model = await fixture(page);
  model.options = { ...model.options, services: [{ ...model.options.services[0], service: "constructor", displayName: "Constructor" }] };
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await restrict(page);
  await editor(page).getByRole("checkbox", { name: "constructor", exact: true }).check();
  const constructor = service(page, "Constructor");
  await expect(constructor).toBeVisible();
  await expect(editor(page).getByRole("button", { name: "Issue token", exact: true })).toBeDisabled();
  await reads(constructor).getByLabel("issue.view", { exact: true }).check();
  await constructor.getByRole("group", { name: "constructor resources", exact: true }).getByRole("button", { name: "Selected resources and groups", exact: true }).click();
  await expect.poll(() => Object.hasOwn(model.previews.at(-1)?.serviceRestrictions ?? {}, "constructor")).toBe(true);
  await expect.poll(() => model.previews.at(-1)?.serviceRestrictions?.constructor).toEqual({ actions: ["issue.view"], resources: { resourceIds: [], resourceGroupIds: [] } });
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("explicit-constructor");
  await editor(page).getByRole("button", { name: "Issue token", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Token created", exact: true })).toBeVisible();
  expect(model.issued).toHaveLength(1);
  expect(model.issued[0].body.allowedServices).toEqual(["constructor"]);
  expect(Object.hasOwn(model.issued[0].body.serviceRestrictions!, "constructor")).toBe(true);
  expect(model.issued[0].body.serviceRestrictions?.constructor).toEqual({ actions: ["issue.view"], resources: { resourceIds: [], resourceGroupIds: [] } });
  expect(model.invalidPreviews).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("a command service restricts its typed actions to resources of its imported type only", async ({ page }) => {
  const model = await fixture(page);
  const contexts = ["internal", "external"];
  // Broker-checked and command-checked typed actions name the import's Broker type; an untyped action names none.
  const commandAction = (name: string, resourceType: string | null) => ({
    ...action(name, true),
    requiredScopeTypes: resourceType ? [resourceType] : [],
    resourceType,
    effectiveAccessByExecutionContext: Object.fromEntries(contexts.map((context) => [context, resourceType ? [{ included: [{ kind: "all" as const }], excluded: [] }] : []]))
  });
  const resource = (id: string, displayName: string, resourceType: string, value: string) => ({ id, displayName, resourceType, selector: { kind: "exact" as const, value }, allowedExecutionContexts: contexts, enabled: true });
  model.options = {
    ...model.options,
    resources: [...model.options.resources, resource("ops", "Operations", "ticketing_project", "OPS"), resource("triage-queue", "Triage", "ticketing_queue", "triage")],
    services: [
      ...model.options.services,
      { service: "ticketing", displayName: "Ticketing", brokerHosts: [], executionContexts: contexts, actions: [commandAction("issue.view", "ticketing_project"), commandAction("issue.search", "ticketing_project"), commandAction("whoami", null)] }
    ]
  };
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await restrict(page);
  await editor(page).getByRole("checkbox", { name: "ticketing", exact: true }).check();
  const ticketing = service(page, "Ticketing");
  await reads(ticketing).getByLabel("issue.search", { exact: true }).check();
  await ticketing.getByRole("group", { name: "ticketing resources", exact: true }).getByRole("button", { name: "Selected resources and groups", exact: true }).click();
  // Only resources of the actions' imported type are offered, labelled by the type the import declared.
  await expect(ticketing.getByLabel("Operations · OPS", { exact: true })).toBeVisible();
  await expect(ticketing.getByText("Project · internal, external", { exact: true })).toBeVisible();
  await expect(ticketing.getByLabel("Example project · EXAMPLE", { exact: true })).toHaveCount(0);
  await expect(ticketing.getByLabel("Triage · triage", { exact: true })).toHaveCount(0);
  await ticketing.getByLabel("Operations · OPS", { exact: true }).check();
  await expect.poll(() => model.previews.at(-1)?.serviceRestrictions?.ticketing).toEqual({ actions: ["issue.search"], resources: { resourceIds: ["ops"], resourceGroupIds: [] } });
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("command-boundary");
  await editor(page).getByRole("button", { name: "Issue token", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Token created", exact: true })).toBeVisible();
  expect(model.issued[0].body.serviceRestrictions?.ticketing).toEqual({ actions: ["issue.search"], resources: { resourceIds: ["ops"], resourceGroupIds: [] } });
  expect(model.invalidPreviews).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("a command service with only untyped actions has no resource selection", async ({ page }) => {
  const model = await fixture(page);
  const contexts = ["internal", "external"];
  model.options = {
    ...model.options,
    services: [
      ...model.options.services,
      { service: "notes", displayName: "Notes", brokerHosts: [], executionContexts: contexts, actions: [{ ...action("note.list", true), requiredScopeTypes: [], resourceType: null, effectiveAccessByExecutionContext: { internal: [], external: [] } }] }
    ]
  };
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await restrict(page);
  await editor(page).getByRole("checkbox", { name: "notes", exact: true }).check();
  const notes = service(page, "Notes");
  await reads(notes).getByLabel("note.list", { exact: true }).check();
  await expect(notes).toContainText("Access is controlled by action grants; this service has no resource selections.");
  await expect(notes.getByRole("group", { name: "notes resources", exact: true })).toHaveCount(0);
  await expect.poll(() => model.previews.at(-1)?.serviceRestrictions?.notes).toEqual({ actions: ["note.list"] });
  expect(model.invalidPreviews).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("self and administered routes share the pending fence for the same owner", async ({ page }) => {
  const model = await fixture(page);
  let release!: () => void;
  model.issueWait = new Promise<void>((resolve) => { release = resolve; });
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("one-owner-one-request");
  await editor(page).getByRole("button", { name: "Issue token", exact: true }).click();
  await expect.poll(() => model.issued.length).toBe(1);
  model.session = { ...model.session, role: "admin", selfServiceEnabled: false };
  await refreshQueries(page);
  await expect(page.getByText("Page not found", { exact: true })).toBeVisible();
  // A role change can unmount the self-service editor while preserving the
  // admitted request. Navigate through ordinary links to the same owner's
  // administered editor; that route must share the existing pending fence.
  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog", { name: "Command palette", exact: true });
  await palette.getByRole("combobox").fill("viewer");
  await palette.getByRole("group", { name: "Principals", exact: true }).getByRole("option", { name: /viewer/ }).click();
  await page.getByRole("navigation", { name: "User sections", exact: true }).getByRole("link", { name: "Tokens", exact: true }).click();
  await page.getByRole("button", { name: "Issue token", exact: true }).first().click();
  await expect(page).toHaveURL(/\/ui\/admin\/principals\/viewer\/tokens\/new/);
  await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toBeDisabled();
  await expect(editor(page).getByRole("button", { name: "Issue token", exact: true })).toBeDisabled();
  release();
  await expect(page.getByRole("dialog", { name: "Token created", exact: true }).getByLabel("Token", { exact: true })).toHaveText(rawToken);
  expect(model.issued).toHaveLength(1);
  expect(model.issued[0].pathname).toBe("/v1/tokens");
  expect(model.errors).toEqual([]);
});

test("a removed lifetime remains explicit and can be replaced after policy refresh", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("updated-lifetime");
  const lifetime = editor(page).getByLabel("Lifetime", { exact: true });
  await lifetime.selectOption("8h");
  model.session = { ...model.session, tokenIssuancePolicy: { selfAgentInvoke: { defaultTtl: "1h", maxTtl: "1h", options: ["1h"] } } };
  await refreshQueries(page);
  await expect(lifetime).toHaveValue("8h");
  await expect(lifetime.locator('option[value="8h"]')).toContainText("no longer available");
  await expect(editor(page).getByRole("button", { name: "Issue token", exact: true })).toBeDisabled();
  await lifetime.selectOption("1h");
  await expect(editor(page).getByRole("complementary", { name: "Token summary", exact: true })).toContainText("1 hour");
  await expect(editor(page).getByRole("button", { name: "Issue token", exact: true })).toBeEnabled();
  await editor(page).getByRole("button", { name: "Issue token", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Token created", exact: true })).toBeVisible();
  expect(model.issued).toEqual([{ pathname: "/v1/tokens", body: { name: "updated-lifetime", ttl: "1h", allowedExecutionContexts: ["internal", "external"] } }]);
  expect(model.errors).toEqual([]);
});

for (const pending of [false, true]) {
  test(`explicit sign-out leaves the ${pending ? "pending" : "dirty"} token editor without a discard prompt`, async ({ page }) => {
    const model = await fixture(page);
    let release = () => {};
    if (pending) model.issueWait = new Promise<void>((resolve) => { release = resolve; });
    try {
      await page.goto(`${baseUrl}/ui/tokens/new`);
      await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("sign-out-draft");
      if (pending) {
        await editor(page).getByRole("button", { name: "Issue token", exact: true }).click();
        await expect.poll(() => model.issued.length).toBe(1);
      }
      await page.getByRole("button", { name: "Account", exact: true }).click();
      await page.getByRole("menuitem", { name: "Sign out", exact: true }).click();
      await expect(page).toHaveURL(`${baseUrl}/ui`);
      await expect(page.getByLabel("Password", { exact: true })).toBeVisible();
      await expect(page.getByRole("alertdialog", { name: "Discard changes?", exact: true })).toHaveCount(0);
      if (pending) {
        const response = page.waitForResponse((response) => response.request().method() === "POST" && new URL(response.url()).pathname === "/v1/tokens");
        release();
        await (await response).finished();
        await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
      }
      await expect(page.getByRole("dialog", { name: "Token created", exact: true })).toHaveCount(0);
      await expect(page.getByText(rawToken, { exact: true })).toHaveCount(0);
      await expect(page).toHaveURL(`${baseUrl}/ui`);
      expect(model.issued).toHaveLength(pending ? 1 : 0);
      expect(model.errors).toEqual([]);
    } finally { release(); }
  });
}

test("required password changes redirect a dirty token draft without a discard prompt", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${baseUrl}/ui/tokens/new`);
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("password-lock-draft");
  model.session = { ...model.session, passwordChangeRequired: true };
  let releasePreview!: () => void;
  const previewWait = new Promise<void>((resolve) => { releasePreview = resolve; });
  await page.route("**/v1/tokens/effective-access", async (route) => {
    await previewWait;
    await route.fulfill({ status: 403, json: { ok: false, reasonCode: "password_change_required", error: { message: "Password change required" } } });
  });
  // Finish the checkbox state assertion before the response navigates away
  // and removes the editor. The redirect assertions below remain unchanged.
  try {
    await editor(page).getByRole("group", { name: "Execution contexts", exact: true }).getByLabel("external", { exact: true }).uncheck();
  } finally { releasePreview(); }
  await expect(page).toHaveURL(`${baseUrl}/ui/account`);
  await expect(page.getByRole("main", { name: "Account", exact: true })).toBeVisible();
  await expect(page.getByRole("main", { name: "Account", exact: true }).getByText("Change your password to continue", { exact: true })).toBeVisible();
  await expect(page.getByRole("alertdialog", { name: "Discard changes?", exact: true })).toHaveCount(0);
  expect(model.issued).toEqual([]);
  expect(model.errors).toEqual([]);
});

test("a password-required redirect suppresses a pending issuance success and its secret", async ({ page }) => {
  const model = await fixture(page);
  let releaseIssue!: () => void;
  let releasePreview!: () => void;
  model.issueWait = new Promise<void>((resolve) => { releaseIssue = resolve; });
  const previewWait = new Promise<void>((resolve) => { releasePreview = resolve; });
  await page.route("**/v1/tokens/effective-access", async (route) => {
    await previewWait;
    await route.fulfill({ status: 403, json: { ok: false, reasonCode: "password_change_required", error: { message: "Password change required" } } });
  });
  try {
    await page.goto(`${baseUrl}/ui/tokens/new`);
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("pending-password-lock");
    await editor(page).getByRole("button", { name: "Issue token", exact: true }).click();
    await expect.poll(() => model.issued.length).toBe(1);
    model.session = { ...model.session, passwordChangeRequired: true };
    releasePreview();
    await expect(page).toHaveURL(`${baseUrl}/ui/account`);
    await expect(page.getByRole("main", { name: "Account", exact: true })).toBeVisible();
    await expect(page.getByRole("main", { name: "Account", exact: true }).getByText("Change your password to continue", { exact: true })).toBeVisible();
    await expect(page.getByRole("alertdialog", { name: "Discard changes?", exact: true })).toHaveCount(0);
    const response = page.waitForResponse((response) => response.request().method() === "POST" && new URL(response.url()).pathname === "/v1/tokens");
    releaseIssue();
    await (await response).finished();
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    await expect(page).toHaveURL(`${baseUrl}/ui/account`);
    await expect(page.getByRole("main", { name: "Account", exact: true })).toBeVisible();
    await expect(page.getByRole("main", { name: "Account", exact: true }).getByText("Change your password to continue", { exact: true })).toBeVisible();
    await expect(page.getByRole("dialog", { name: "Token created", exact: true })).toHaveCount(0);
    await expect(page.getByText(rawToken, { exact: true })).toHaveCount(0);
    expect(await page.evaluate(() => JSON.stringify({ local: localStorage, session: sessionStorage, history: history.state }))).not.toContain(rawToken);
    expect(model.issued).toHaveLength(1);
    expect(model.errors).toEqual([]);
  } finally { releasePreview(); releaseIssue(); }
});
