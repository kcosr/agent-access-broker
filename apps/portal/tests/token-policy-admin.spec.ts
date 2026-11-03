import { expect, test, type Page } from "@playwright/test";
import type { GroupDetail, PrincipalDetail, PrincipalRole } from "../src/types";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

// Mocked UI contracts; the real-store issuance flow is in portal.spec.ts.
let assets: PortalAssets;
test.beforeAll(async () => { assets = await servePortalAssets(); });
test.afterAll(async () => { await assets.close(); });
const stamp = { createdAt: "2026-11-02T00:00:00Z", updatedAt: "2026-11-02T00:00:00Z", createdBy: "admin", updatedBy: "admin" };

async function fixture(page: Page, role: PrincipalRole = "admin", authority = "managed") {
  const group: GroupDetail = { groupId: "readers", displayName: "Engineering readers", description: "Read access", status: "active", memberCount: 1, autoEnrollNewMicrosoftUsers: false, agentTokenIssuance: "read_only", members: [], policyReferenceSections: [], ...stamp };
  const principal: PrincipalDetail = { principalId: "alice", kind: "user", displayName: "Alice", status: "active", role: "user", selfServiceEnabled: true, agentTokenIssuance: "inherit", agentTokenIssuancePolicy: { mode: "read_only", source: "groups", groupIds: ["readers"] }, groups: ["readers"], groupMemberships: [], activePolicyGroupSubjects: ["group:readers"], policyReferenceSections: [], signInMethods: { localPassword: "absent", microsoft: "absent" }, ...stamp };
  const model = { group, principal, authority, writes: [] as { path: string; body: Record<string, unknown> }[], sessionReads: 0, errors: [] as string[] };
  page.on("pageerror", (error) => model.errors.push(error.message));
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const write = request.method() !== "GET";
    const body = write ? request.postDataJSON() as Record<string, unknown> : {};
    if (write) model.writes.push({ path, body });
    let result: unknown = [];
    if (path === "/v1/auth/session") {
      model.sessionReads++;
      result = { authenticated: true, principal: "admin", role, selfServiceEnabled: false, csrfHeader: "x-csrf-token", csrfToken: "fixture", loginOptions: { localPassword: { enabled: true } }, tokenIssuancePolicy: {} };
    } else if (path === "/v1/admin/config/status") result = { identityAuthority: model.authority, policyAuthority: "managed", generation: 1, loadedAt: stamp.createdAt, configHash: "fixture" };
    else if (path === "/v1/admin/principals/alice/access") {
      Object.assign(principal, body);
      principal.agentTokenIssuancePolicy = principal.agentTokenIssuance === "inherit" ? { mode: "read_only", source: "groups", groupIds: ["readers"] } : { mode: principal.agentTokenIssuance, source: "user", groupIds: [] };
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
    } else if (path === "/v1/admin/policy/catalog") result = { services: [], subjects: { users: [], groups: [], anonymous: false }, resources: [], resourceGroups: [], executionContexts: { allowedValues: ["default"], defaultContext: "default" } };
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
  await expect(section.getByText("Read-only, inherited from Engineering readers", { exact: true })).toBeVisible();
  await expect(section.getByRole("combobox", { name: "Agent token issuance", exact: true })).toHaveValue("inherit");
  await section.getByRole("combobox", { name: "Agent token issuance", exact: true }).selectOption("disabled");
  await section.getByRole("button", { name: "Save access", exact: true }).click();
  const review = page.getByRole("alertdialog", { name: "Update account access?", exact: true });
  await expect(review).toContainText("agent token issuance set to Disabled");
  await expect(review).toContainText("Existing token restrictions stay unchanged");
  await review.getByRole("button", { name: "Update access", exact: true }).click();
  await expect(section.getByText("Disabled, explicit account override", { exact: true })).toBeVisible();
  expect(model.writes).toEqual([{ path: "/v1/admin/principals/alice/access", body: { role: "user", selfServiceEnabled: true, agentTokenIssuance: "disabled" } }]);
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
  expect(model.writes).toEqual([{ path: "/v1/admin/groups/readers", body: { agentTokenIssuance: "write_capable" } }]);
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
    expect(model.writes[0].body.agentTokenIssuance).toBe(kind === "group" ? "disabled" : "inherit");
    expect(model.errors).toEqual([]);
  });
}
