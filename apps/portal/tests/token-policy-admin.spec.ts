import { expect, test, type Page } from "@playwright/test";
import type { GroupDetail, PrincipalDetail, PrincipalRole } from "../src/types";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

// Mocked UI contracts; the real-store issuance flow is in portal.spec.ts.
let assets: PortalAssets;
test.beforeAll(async () => { assets = await servePortalAssets(); });
test.afterAll(async () => { await assets.close(); });
const stamp = { createdAt: "2026-11-02T00:00:00Z", updatedAt: "2026-11-02T00:00:00Z", createdBy: "admin", updatedBy: "admin" };

async function fixture(page: Page, role: PrincipalRole = "admin", authority = "managed") {
  const group: GroupDetail = { groupId: "readers", displayName: "Engineering readers", description: "Read access", status: "active", memberCount: 1, autoEnrollNewMicrosoftUsers: false, agentTokenIssuance: { mode: "read_only", allowedExecutionContexts: ["default"] }, members: [], policyReferenceSections: [], ...stamp };
  const principal: PrincipalDetail = { principalId: "alice", kind: "user", displayName: "Alice", status: "active", role: "user", selfServiceEnabled: true, agentTokenIssuance: { mode: "inherit", allowedExecutionContexts: [] }, agentTokenIssuancePolicy: { source: "groups", contexts: [{ executionContext: "default", mode: "read_only", groupIds: ["readers"] }] }, groups: ["readers"], groupMemberships: [], activePolicyGroupSubjects: ["group:readers"], policyReferenceSections: [], signInMethods: { localPassword: "absent", microsoft: "absent" }, ...stamp };
  const model = { group, principal, authority, policyAuthority: "managed", contexts: ["default"], recordFailure: false, writeFailure: false, writes: [] as { path: string; body: Record<string, unknown> }[], sessionReads: 0, errors: [] as string[] };
  page.on("pageerror", (error) => model.errors.push(error.message));
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const write = request.method() !== "GET";
    const body = write ? request.postDataJSON() as Record<string, unknown> : {};
    if (write) model.writes.push({ path, body });
    if ((model.writeFailure && write) || (model.recordFailure && request.method() === "GET" && path === "/v1/admin/principals/alice")) {
      await route.fulfill({ status: 503, json: { ok: false, error: { message: "Settings temporarily unavailable" } } });
      return;
    }
    let result: unknown = [];
    if (path === "/v1/auth/session") {
      model.sessionReads++;
      result = { authenticated: true, principal: "admin", role, selfServiceEnabled: false, csrfHeader: "x-csrf-token", csrfToken: "fixture", loginOptions: { localPassword: { enabled: true } }, tokenIssuancePolicy: {} };
    } else if (path === "/v1/admin/config/status") result = { identityAuthority: model.authority, policyAuthority: model.policyAuthority, generation: 1, loadedAt: stamp.createdAt, configHash: "fixture" };
    else if (path === "/v1/admin/principals/alice/access") {
      Object.assign(principal, body);
      principal.agentTokenIssuancePolicy = principal.agentTokenIssuance.mode === "inherit"
        ? { source: "groups", contexts: [{ executionContext: "default", mode: "read_only", groupIds: ["readers"] }] }
        : { source: "user", contexts: principal.agentTokenIssuance.mode === "disabled" ? [] : principal.agentTokenIssuance.allowedExecutionContexts.map((executionContext) => ({ executionContext, mode: principal.agentTokenIssuance.mode as "read_only" | "write_capable", groupIds: [] })) };
      result = principal;
    } else if (path === "/v1/admin/principals") {
      if (write) Object.assign(principal, body);
      result = write ? principal : [principal];
    } else if (/^\/v1\/admin\/principals\/[^/]+$/.test(path)) result = principal;
    else if (path === "/v1/admin/groups") {
      if (write) Object.assign(group, body);
      result = write ? group : [group];
    } else if (/^\/v1\/admin\/groups\/[^/]+$/.test(path)) {
      if (write) Object.assign(group, body);
      result = group;
    } else if (path === "/v1/admin/policy/catalog") result = { services: [], subjects: { users: [], groups: [], anonymous: false }, resources: [], resourceGroups: [], executionContexts: { allowedValues: model.contexts, defaultContext: model.contexts[0] } };
    else if (path.endsWith("/identity-token")) result = { principalId: principal.principalId, configured: false, enabled: true, readOnly: false, revision: 1, updatedAt: stamp.createdAt };
    else if (path.endsWith("/identity-access")) result = { principalId: principal.principalId, incarnation: "fixture", paused: false, version: 1, ...stamp };
    else if (path.endsWith("/identity-bindings")) result = { bindings: [], configuredNamespaces: [] };
    else if (path === "/v1/resource-types") { await route.fulfill({ json: { resourceTypes: [] } }); return; }
    await route.fulfill({ json: { ok: true, result } });
  });
  return model;
}

test("account access reviews issuance overrides and displays their resolved source", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${assets.baseUrl}/ui/admin/principals/alice`);
  const section = page.getByRole("region", { name: "Account access", exact: true });
  await expect(section.getByText("Current saved policy: default: Read-only, inherited from Engineering readers", { exact: true })).toBeVisible();
  await expect(section.getByRole("combobox", { name: "Agent token issuance", exact: true })).toHaveValue("inherit");
  await section.getByRole("combobox", { name: "Agent token issuance", exact: true }).selectOption("disabled");
  await section.getByRole("button", { name: "Save access", exact: true }).click();
  const review = page.getByRole("alertdialog", { name: "Update account access?", exact: true });
  await expect(review).toContainText("agent token issuance set to Disabled");
  await expect(review).toContainText("Existing token restrictions stay unchanged");
  await review.getByRole("button", { name: "Update access", exact: true }).click();
  await expect(section.getByText("Current saved policy: Disabled, explicit account override", { exact: true })).toBeVisible();
  expect(model.writes).toEqual([{ path: "/v1/admin/principals/alice/access", body: { agentTokenIssuance: { mode: "disabled", allowedExecutionContexts: [] } } }]);
  expect(model.errors).toEqual([]);
});

test("group issuance saves independently and disabled groups retain their inactive setting", async ({ page }) => {
  const model = await fixture(page);
  model.group.status = "disabled";
  await page.goto(`${assets.baseUrl}/ui/admin/groups/readers`);
  const section = page.getByRole("region", { name: "Token issuance", exact: true });
  await expect(section).toContainText("Disabled does not override permission from another group");
  await expect(section).toContainText("contribution is inactive");
  await expect(section.getByRole("combobox", { name: "Agent token issuance", exact: true })).toHaveValue("read_only");
  await section.getByRole("combobox", { name: "Agent token issuance", exact: true }).selectOption("write_capable");
  await section.getByRole("button", { name: "Save token issuance", exact: true }).click();
  await expect(section.getByRole("button", { name: "Save token issuance", exact: true })).toBeDisabled();
  expect(model.writes).toEqual([{ path: "/v1/admin/groups/readers", body: { agentTokenIssuance: { mode: "write_capable", allowedExecutionContexts: ["default"] } } }]);
  expect(model.group.status).toBe("disabled");
  await expect.poll(() => model.sessionReads).toBeGreaterThan(1);
  expect(model.errors).toEqual([]);
});

test("TOML groups expose no editable or active issuance contribution", async ({ page }) => {
  const model = await fixture(page, "admin", "toml");
  await page.goto(`${assets.baseUrl}/ui/admin/groups/readers`);
  const section = page.getByRole("region", { name: "Token issuance", exact: true });
  await expect(section).toContainText("Group token issuance is unavailable under toml identity authority.");
  await expect(section.getByRole("combobox")).toHaveCount(0);
  await expect(section.getByRole("button")).toHaveCount(0);
  expect(model.writes).toEqual([]);
});

test("auditors can read issuance controls but cannot save them", async ({ page }) => {
  const model = await fixture(page, "auditor");
  await page.goto(`${assets.baseUrl}/ui/admin/principals/alice`);
  const account = page.getByRole("region", { name: "Account access", exact: true });
  await expect(account).toContainText("Inherit from groups");
  await expect(account.getByRole("combobox", { name: "Agent token issuance", exact: true })).toHaveCount(0);
  await expect(account.getByRole("button", { name: "Save access", exact: true })).toHaveCount(0);
  await page.goto(`${assets.baseUrl}/ui/admin/groups/readers`);
  const group = page.getByRole("region", { name: "Token issuance", exact: true });
  await expect(group.getByRole("combobox", { name: "Agent token issuance", exact: true })).toBeDisabled();
  await expect(group.getByRole("button", { name: "Save token issuance", exact: true })).toHaveCount(0);
  expect(model.writes).toEqual([]);
});

test("service accounts explain why a policy selector cannot enable self-issuance", async ({ page }) => {
  const model = await fixture(page);
  model.principal.kind = "service_account";
  model.principal.selfServiceEnabled = false;
  await page.goto(`${assets.baseUrl}/ui/admin/principals/alice`);
  await expect(page.getByText(/Self-issuance is unavailable for service accounts/)).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Agent token issuance", exact: true })).toHaveCount(0);
});

for (const kind of ["user", "group"] as const) {
  test(`new ${kind} creation sends its explicit issuance default`, async ({ page }) => {
    const model = await fixture(page);
    await page.goto(`${assets.baseUrl}/ui/admin/principals?kind=${kind === "group" ? "groups" : "users"}`);
    if (kind === "group") await page.getByRole("button", { name: /^Groups/ }).click();
    await page.getByRole("button", { name: kind === "group" ? "Create group" : "Create user", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: kind === "group" ? "Create group" : "Create user", exact: true });
    await expect(dialog.getByLabel("Agent token issuance", { exact: true })).toHaveValue(kind === "group" ? "disabled" : "inherit");
    await dialog.getByLabel(kind === "group" ? "Group ID" : "Principal ID", { exact: true }).fill("new-record");
    await dialog.getByRole("button", { name: kind === "group" ? "Create group" : "Create user", exact: true }).click();
    await expect.poll(() => model.writes.length).toBe(1);
    expect(model.writes[0].body.agentTokenIssuance).toEqual({ mode: kind === "group" ? "disabled" : "inherit", allowedExecutionContexts: [] });
    expect(model.errors).toEqual([]);
  });
}

const accountSection = (page: Page) => page.getByRole("region", { name: "Account access", exact: true });
async function refreshSettings(page: Page) {
  await page.clock.setFixedTime(new Date(await page.evaluate(() => Date.now()) + 120_000));
  await page.evaluate(() => { window.dispatchEvent(new Event("offline")); window.dispatchEvent(new Event("online")); });
}
async function confirmAccess(page: Page) {
  await page.getByRole("alertdialog", { name: "Update account access?", exact: true }).getByRole("button", { name: "Update access", exact: true }).click();
}

for (const authority of ["managed", "toml"]) {
  test(`account authoring uses the complete dynamic registry under ${authority} identity and TOML policy`, async ({ page }) => {
    const model = await fixture(page, "admin", authority);
    model.policyAuthority = "toml";
    model.contexts = ["deployment_z", "build-2", "default"];
    await page.goto(`${assets.baseUrl}/ui/admin/principals/alice`);
    const section = accountSection(page);
    await section.getByLabel("Agent token issuance", { exact: true }).selectOption("write_capable");
    const contexts = section.getByRole("group", { name: "Permitted issuance contexts" });
    await expect(contexts.getByRole("checkbox")).toHaveCount(3);
    expect(await contexts.getByRole("checkbox").evaluateAll((elements) => elements.map((element) => element.getAttribute("aria-label")))).toEqual(model.contexts);
    for (const context of model.contexts) await expect(contexts.getByLabel(context, { exact: true })).not.toBeChecked();
    await expect(section.getByRole("button", { name: "Save access", exact: true })).toBeDisabled();
    await contexts.getByLabel("build-2", { exact: true }).check();
    await section.getByRole("button", { name: "Save access", exact: true }).click();
    await confirmAccess(page);
    await expect.poll(() => model.writes.length).toBe(1);
    expect(model.writes[0].body).toEqual({ agentTokenIssuance: { mode: "write_capable", allowedExecutionContexts: ["build-2"] } });
    await section.getByLabel("Agent token issuance", { exact: true }).selectOption("inherit");
    await expect(section).toContainText("The inherited result appears after saving and refreshing.");
    await expect(section).toContainText("build-2: Write-capable, explicit account override");
    await section.getByLabel("Agent token issuance", { exact: true }).selectOption("read_only");
    await expect(contexts.getByLabel("build-2", { exact: true })).not.toBeChecked();
    expect(model.errors).toEqual([]);
  });
}

test("a contexts-only edit adopts a concurrent role and self-service change without submitting either", async ({ page }) => {
  const model = await fixture(page);
  model.principal.agentTokenIssuance = { mode: "read_only", allowedExecutionContexts: ["default"] };
  model.contexts = ["default", "external"];
  await page.goto(`${assets.baseUrl}/ui/admin/principals/alice`);
  const section = accountSection(page);
  await section.getByLabel("external", { exact: true }).check();
  model.principal.role = "auditor";
  model.principal.selfServiceEnabled = false;
  await section.getByRole("button", { name: "Save access", exact: true }).click();
  const review = page.getByRole("alertdialog");
  await expect(review).toContainText("Auditor role and self-service disabled");
  await expect(review).not.toContainText("tokens for this account will be revoked");
  await confirmAccess(page);
  await expect.poll(() => model.writes.length).toBe(1);
  expect(model.writes[0].body).toEqual({ agentTokenIssuance: { mode: "read_only", allowedExecutionContexts: ["default", "external"] } });
  await expect(section.getByLabel("Role", { exact: true })).toHaveValue("auditor");
  await expect(section.getByLabel("Self-service enabled", { exact: true })).not.toBeChecked();
});

for (const choice of ["Keep my draft", "Discard draft"]) {
  test(`concurrent edited values require explicit ${choice.toLowerCase()} before any submission`, async ({ page }) => {
    const model = await fixture(page);
    model.principal.agentTokenIssuance = { mode: "read_only", allowedExecutionContexts: ["default"] };
    model.contexts = ["default", "external", "internal"];
    await page.goto(`${assets.baseUrl}/ui/admin/principals/alice`);
    const section = accountSection(page);
    await section.getByLabel("external", { exact: true }).check();
    await section.getByLabel("Role", { exact: true }).selectOption("admin");
    model.principal.agentTokenIssuance = { mode: "read_only", allowedExecutionContexts: ["internal"] };
    model.principal.role = "auditor";
    model.principal.selfServiceEnabled = false;
    await section.getByRole("button", { name: "Save access", exact: true }).click();
    await expect(section).toContainText("Saved settings changed since you started editing");
    await expect(section.getByLabel("external", { exact: true })).toBeChecked();
    await expect(section.getByLabel("Role", { exact: true })).toHaveValue("admin");
    await expect(section.getByLabel("Self-service enabled", { exact: true })).not.toBeChecked();
    await expect(section.getByRole("button", { name: "Save access", exact: true })).toBeDisabled();
    expect(model.writes).toEqual([]);
    await section.getByRole("button", { name: choice, exact: true }).click();
    expect(model.writes).toEqual([]);
    if (choice === "Discard draft") {
      await expect(section.getByLabel("external", { exact: true })).not.toBeChecked();
      await expect(section.getByLabel("internal", { exact: true })).toBeChecked();
      await expect(section.getByLabel("Role", { exact: true })).toHaveValue("auditor");
      await expect(section.getByRole("button", { name: "Save access", exact: true })).toBeDisabled();
    } else {
      await expect(section).toContainText("Your next save replaces the edited values");
      await section.getByRole("button", { name: "Save access", exact: true }).click();
      await expect(page.getByRole("alertdialog")).toContainText("administrative API tokens for this account will be revoked");
      await confirmAccess(page);
      await expect.poll(() => model.writes.length).toBe(1);
      expect(model.writes[0].body).toEqual({ role: "admin", agentTokenIssuance: { mode: "read_only", allowedExecutionContexts: ["default", "external"] } });
    }
    expect(model.errors).toEqual([]);
  });
}

test("registry refetch retains removed selections and leaves new contexts unchecked", async ({ page }) => {
  const model = await fixture(page);
  model.principal.agentTokenIssuance = { mode: "read_only", allowedExecutionContexts: ["default"] };
  model.contexts = ["default", "retired"];
  await page.goto(`${assets.baseUrl}/ui/admin/principals/alice`);
  const section = accountSection(page);
  await section.getByLabel("retired", { exact: true }).check();
  model.contexts = ["default", "new-context"];
  await refreshSettings(page);
  await expect(section.getByLabel("new-context", { exact: true })).not.toBeChecked();
  await expect(section.getByLabel("retired", { exact: true })).toBeChecked();
  await expect(section).toContainText("No longer configured");
  await expect(section.getByRole("button", { name: "Save access", exact: true })).toBeDisabled();
  await section.getByLabel("retired", { exact: true }).click();
  await expect(section.getByLabel("retired", { exact: true })).toHaveCount(0);
  await expect(section.getByRole("button", { name: "Save access", exact: true })).toBeDisabled();
  await section.getByLabel("new-context", { exact: true }).check();
  await expect(section.getByRole("button", { name: "Save access", exact: true })).toBeEnabled();
  expect(model.writes).toEqual([]);
});

test("pre-save read failures preserve the draft and block the write", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${assets.baseUrl}/ui/admin/principals/alice`);
  const section = accountSection(page);
  await section.getByLabel("Agent token issuance", { exact: true }).selectOption("disabled");
  model.recordFailure = true;
  await section.getByRole("button", { name: "Save access", exact: true }).click();
  await expect(section).toContainText("Settings temporarily unavailable");
  await expect(section.getByLabel("Agent token issuance", { exact: true })).toHaveValue("disabled");
  expect(model.writes).toEqual([]);
  model.recordFailure = false;
  await section.getByRole("button", { name: "Save access", exact: true }).click();
  await confirmAccess(page);
  await expect.poll(() => model.writes.length).toBe(1);
});

test("group conflict and rejected save preserve the complete authored pair", async ({ page }) => {
  const model = await fixture(page);
  model.contexts = ["default", "external", "internal"];
  await page.goto(`${assets.baseUrl}/ui/admin/groups/readers`);
  const section = page.getByRole("region", { name: "Token issuance", exact: true });
  await section.getByLabel("external", { exact: true }).check();
  model.group.agentTokenIssuance = { mode: "write_capable", allowedExecutionContexts: ["internal"] };
  await section.getByRole("button", { name: "Save token issuance", exact: true }).click();
  await expect(section).toContainText("Saved settings changed since you started editing");
  await section.getByRole("button", { name: "Keep my draft", exact: true }).click();
  model.writeFailure = true;
  await section.getByRole("button", { name: "Save token issuance", exact: true }).click();
  await expect(section).toContainText("Settings temporarily unavailable");
  await expect(section.getByLabel("external", { exact: true })).toBeChecked();
  await expect(section.getByLabel("Agent token issuance", { exact: true })).toHaveValue("read_only");
  model.writeFailure = false;
  await section.getByRole("button", { name: "Save token issuance", exact: true }).click();
  await expect.poll(() => model.writes.length).toBe(2);
  expect(model.writes[1].body).toEqual({ agentTokenIssuance: { mode: "read_only", allowedExecutionContexts: ["default", "external"] } });
});

for (const kind of ["account", "group"] as const) {
  test(`saved ${kind} contexts are not labelled removed while the registry is pending or failed`, async ({ page }) => {
    const model = await fixture(page);
    model.principal.agentTokenIssuance = { mode: "read_only", allowedExecutionContexts: ["default"] };
    model.principal.agentTokenIssuancePolicy = { source: "user", contexts: [{ executionContext: "default", mode: "read_only", groupIds: [] }] };
    let fail = true;
    let release = () => {};
    const gate = new Promise<void>((resolve) => { release = resolve; });
    await page.route("**/v1/admin/policy/catalog", async (route) => {
      await gate;
      if (fail) await route.fulfill({ status: 503, json: { ok: false, error: { message: "Registry temporarily unavailable" } } });
      else await route.fallback();
    });
    try {
      await page.goto(`${assets.baseUrl}/ui/admin/${kind === "account" ? "principals/alice" : "groups/readers"}`);
      const section = kind === "account" ? accountSection(page) : page.getByRole("region", { name: "Token issuance", exact: true });
      const save = section.getByRole("button", { name: kind === "account" ? "Save access" : "Save token issuance", exact: true });
      await expect(section.getByLabel("default", { exact: true })).toBeChecked();
      await expect(section.getByLabel("Loading execution contexts", { exact: true })).toBeVisible();
      await expect(section).not.toContainText("No longer configured");
      await section.getByLabel("Agent token issuance", { exact: true }).selectOption("write_capable");
      await expect(save).toBeDisabled();
      release();
      await expect(section).toContainText("Registry temporarily unavailable");
      await expect(section).not.toContainText("No longer configured");
      await expect(section.getByLabel("default", { exact: true })).toBeChecked();
      await expect(save).toBeDisabled();
      model.contexts = ["replacement"];
      fail = false;
      await section.getByRole("button", { name: "Retry", exact: true }).click();
      await expect(section.getByLabel("replacement", { exact: true })).not.toBeChecked();
      await expect(section).toContainText("No longer configured");
      await expect(section.getByLabel("default", { exact: true })).toBeChecked();
      await expect(save).toBeDisabled();
      expect(model.writes).toEqual([]);
      expect(model.errors).toEqual([]);
    } finally { release(); }
  });
}
