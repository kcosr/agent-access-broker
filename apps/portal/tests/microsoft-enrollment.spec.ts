import { expect, test, type Page } from "@playwright/test";
import type { MicrosoftEnrollment, PrincipalDetail } from "../src/types";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

// Administrator UI contracts only. Deterministic Microsoft callback behavior is
// covered by the host OidcBrowserFixture; no Microsoft authentication runs here.
let assets: PortalAssets;
test.beforeAll(async () => { assets = await servePortalAssets(); });
test.afterAll(async () => { await assets.close(); });
const stamp = { createdAt: "2026-11-09T00:00:00Z", updatedAt: "2026-11-09T00:00:00Z", createdBy: "admin", updatedBy: "admin" };
const reservation = (): MicrosoftEnrollment => ({ enrollmentId: "enrollment-1", principalId: "prepared", tenantId: "11111111-1111-4111-8111-111111111111", matchEmail: "person@example.test", revision: 3, ...stamp });
const returnedId = "usr-22222222-3333-4444-8555-666666666666";
const endpoint = "/v1/admin/principals/prepared/login-methods/oidc/microsoft/enrollment";

async function fixture(page: Page, pending = true) {
  const principal: PrincipalDetail = {
    principalId: "prepared", kind: "user", displayName: "Prepared Person", email: "profile@example.test", status: "active", role: "user", selfServiceEnabled: true,
    microsoftEnrollment: pending ? reservation() : null,
    agentTokenIssuance: { mode: "inherit", allowedExecutionContexts: [] }, agentTokenIssuancePolicy: { source: "default", contexts: [] },
    groups: [], groupMemberships: [], activePolicyGroupSubjects: [], policyReferenceSections: [], signInMethods: { localPassword: "absent", microsoft: "absent" }, ...stamp
  };
  const model = {
    principal, role: "admin", available: true, microsoftEnabled: false, linked: false, conflict: false, rejectCreate: false, rejectGroup: false, retryGroup: false,
    writes: [] as { path: string; method: string; body: Record<string, unknown>; query?: Record<string, string> }[], errors: [] as string[]
  };
  page.on("pageerror", (error) => model.errors.push(error.message));
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    const method = request.method();
    const write = method !== "GET";
    const body = write && request.postData() ? request.postDataJSON() as Record<string, unknown> : {};
    if (write) model.writes.push({ path, method, body, ...(method === "DELETE" ? { query: Object.fromEntries(url.searchParams) } : {}) });
    if (path === endpoint && method === "DELETE") {
      expect(request.postData()).toBeNull();
      expect(url.searchParams.has("enrollmentId")).toBe(true);
      expect(url.searchParams.has("expectedRevision")).toBe(true);
    }
    if ((model.conflict && write && path === endpoint) || (model.rejectCreate && write && path === "/v1/admin/principals")) {
      await route.fulfill({ status: 409, json: { ok: false, error: { message: "Enrollment changed or email already reserved" } } });
      return;
    }
    if (write && path.endsWith("/groups/readers")) {
      if (model.rejectGroup || model.retryGroup) {
        const retry = model.retryGroup;
        model.retryGroup = false;
        await route.fulfill({ status: retry ? 403 : 409, json: { ok: false, reasonCode: retry ? "csrf_invalid" : "group_changed", error: { message: "Group setup did not complete" } } });
        return;
      }
      principal.groups.push("readers");
    }
    let result: unknown = [];
    if (path === "/v1/auth/session") result = {
      authenticated: true, principal: "admin", role: model.role, selfServiceEnabled: false, csrfHeader: "x-csrf-token", csrfToken: "fixture",
      loginOptions: { localPassword: { enabled: true }, microsoft: { enabled: model.microsoftEnabled, available: model.microsoftEnabled } }
    };
    else if (path === "/v1/admin/config/status") result = { identityAuthority: "managed", policyAuthority: "managed", generation: 1, loadedAt: stamp.createdAt, configHash: "fixture", microsoftEnrollment: { available: model.available, tenantId: reservation().tenantId } };
    else if (path === "/v1/admin/principals") {
      if (write) {
        principal.principalId = body.microsoftEnrollment ? returnedId : body.principalId as string;
        principal.displayName = body.displayName as string;
        principal.email = body.email as string;
        principal.microsoftEnrollment = body.microsoftEnrollment ? { ...reservation(), principalId: principal.principalId, matchEmail: (body.microsoftEnrollment as { email: string }).email } : null;
      }
      result = write ? principal : [principal];
    } else if (path === `/v1/admin/principals/${principal.principalId}`) {
      if (write) Object.assign(principal, body);
      result = principal;
    } else if (path === endpoint) {
      if (method === "POST") principal.microsoftEnrollment = { ...reservation(), matchEmail: body.email as string };
      if (method === "PATCH") principal.microsoftEnrollment = { ...principal.microsoftEnrollment!, matchEmail: body.email as string, revision: principal.microsoftEnrollment!.revision + 1 };
      if (method === "DELETE") principal.microsoftEnrollment = null;
      result = method === "DELETE" ? { cancelled: true } : principal.microsoftEnrollment;
    } else if (path === `/v1/admin/principals/${principal.principalId}/login-methods`) result = model.linked ? [{ method: "oidc", status: "active", oidc: { provider: "microsoft", tenantId: reservation().tenantId, userObjectId: "22222222-2222-4222-8222-222222222222" } }] : [];
    else if (path === "/v1/admin/groups") result = [{ groupId: "readers", displayName: "Readers", status: "active", memberCount: 0, autoEnrollNewMicrosoftUsers: false, agentTokenIssuance: { mode: "disabled", allowedExecutionContexts: [] }, ...stamp }];
    else if (path === "/v1/admin/policy/catalog") result = { services: [], subjects: { users: [], groups: [], anonymous: false }, resources: [], resourceGroups: [], executionContexts: { allowedValues: ["default"], defaultContext: "default" } };
    else if (path.endsWith("/identity-token")) result = { principalId: principal.principalId, configured: false, enabled: true, readOnly: false, revision: 1, updatedAt: stamp.createdAt };
    else if (path.endsWith("/identity-access")) result = { principalId: principal.principalId, incarnation: "fixture", paused: false, version: 1, ...stamp };
    else if (path.endsWith("/identity-bindings")) result = { bindings: [], configuredNamespaces: [] };
    else if (path.endsWith("/application-access")) result = { access: [] };
    else if (path === "/v1/resource-types") { await route.fulfill({ json: { resourceTypes: [] } }); return; }
    await route.fulfill({ json: { ok: true, result } });
  });
  return model;
}
const signIn = (page: Page) => page.getByRole("region", { name: "Sign-in methods", exact: true });

for (const microsoftEnabled of [true, false]) {
  test(`Create user defaults to Microsoft with the provider ${microsoftEnabled ? "enabled" : "paused"}`, async ({ page }) => {
    const model = await fixture(page, false);
    model.microsoftEnabled = microsoftEnabled;
    await page.goto(`${assets.baseUrl}/ui/admin/principals`);
    await page.getByRole("button", { name: "Create user", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Create user", exact: true });
    await expect(dialog.getByLabel("Create a local account instead", { exact: true })).not.toBeChecked();
    await expect(dialog.getByLabel("Principal ID", { exact: true })).toHaveCount(0);
    await expect(dialog.getByLabel("Username", { exact: true })).toHaveCount(0);
    await expect(dialog.getByLabel("Prepare Microsoft sign-in by email", { exact: true })).toHaveCount(0);
    await expect(dialog.getByLabel("Enable local password sign-in", { exact: true })).toHaveCount(0);
    await expect(dialog.getByRole("button", { name: "Create user", exact: true })).toBeDisabled();
    await dialog.getByLabel("Microsoft email", { exact: true }).fill("person@example.test");
    await expect(dialog.getByLabel("Microsoft email", { exact: true })).toHaveAttribute("required", "");
    await expect(dialog).not.toContainText(reservation().tenantId);
    await dialog.getByRole("button", { name: "Create user", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`principals/${returnedId}$`));
    await expect(signIn(page)).toContainText("Awaiting first Microsoft sign-in");
    expect(model.writes).toHaveLength(1);
    expect(model.writes[0]).toMatchObject({ path: "/v1/admin/principals", method: "POST", body: { kind: "user", email: "person@example.test", microsoftEnrollment: { email: "person@example.test" } } });
    expect(model.writes[0].body).not.toHaveProperty("principalId");
    expect(model.writes[0].body).not.toHaveProperty("displayName");
    await expect(page.getByText("User has no sign-in methods.", { exact: false })).toHaveCount(0);
    expect(model.errors).toEqual([]);
  });
}

for (const rejectGroup of [false, true]) {
  test(`Microsoft creation uses the returned ID after group setup ${rejectGroup ? "failure" : "CSRF retry"}`, async ({ page }) => {
    const model = await fixture(page, false);
    model.rejectGroup = rejectGroup;
    model.retryGroup = !rejectGroup;
    await page.goto(`${assets.baseUrl}/ui/admin/principals`);
    await page.getByRole("button", { name: "Create user", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Create user", exact: true });
    await dialog.getByLabel("Microsoft email", { exact: true }).fill("person@example.test");
    await dialog.getByRole("combobox", { name: "Groups (optional)", exact: true }).click();
    await page.getByRole("option", { name: "readers - Readers", exact: true }).click();
    await page.keyboard.press("Escape");
    await dialog.getByRole("button", { name: "Create user", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`principals/${returnedId}$`));
    await expect(signIn(page)).toContainText("Awaiting first Microsoft sign-in");
    expect(model.writes.filter((write) => write.path === "/v1/admin/principals")).toHaveLength(1);
    expect(model.writes.slice(1)).toEqual(Array.from({ length: rejectGroup ? 1 : 2 }, () => ({ path: `/v1/admin/principals/${returnedId}/groups/readers`, method: "PUT", body: {} })));
    if (rejectGroup) await expect(page.getByText("User created, but setup did not complete. Finish setup on Overview.", { exact: true })).toBeVisible();
    else await expect(page.getByText("User created", { exact: true })).toBeVisible();
    expect(model.errors).toEqual([]);
  });
}

test("unavailable Microsoft keeps the default visible and requires an explicit local choice", async ({ page }) => {
  const model = await fixture(page, false);
  model.available = false;
  await page.goto(`${assets.baseUrl}/ui/admin/principals`);
  await page.getByRole("button", { name: "Create user", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Create user", exact: true });
  const local = dialog.getByLabel("Create a local account instead", { exact: true });
  await expect(local).not.toBeChecked();
  await expect(dialog).toContainText("Microsoft account creation requires managed identity and a configured Microsoft tenant.");
  await dialog.getByLabel("Microsoft email", { exact: true }).fill("person@example.test");
  await expect(dialog.getByRole("button", { name: "Create user", exact: true })).toBeDisabled();
  await expect(dialog.getByLabel("Principal ID", { exact: true })).toHaveCount(0);
  await local.check();
  await expect(dialog.getByLabel("Microsoft email", { exact: true })).toHaveCount(0);
  await dialog.getByLabel("Username", { exact: true }).fill("local-user");
  await expect(dialog.getByRole("button", { name: "Create user", exact: true })).toBeDisabled();
  await dialog.getByLabel("I authorize local password sign-in for this user independently of Microsoft sign-in.", { exact: true }).check();
  await expect(dialog.getByRole("button", { name: "Create user", exact: true })).toBeEnabled();
  await local.uncheck();
  await expect(dialog.getByLabel("Username", { exact: true })).toHaveCount(0);
  await expect(dialog.getByRole("button", { name: "Create user", exact: true })).toBeDisabled();
  expect(model.writes).toEqual([]);
});

test("switching between filled creation drafts preserves access and omits the local username from Microsoft creation", async ({ page }) => {
  const model = await fixture(page, false);
  model.microsoftEnabled = true;
  await page.goto(`${assets.baseUrl}/ui/admin/principals`);
  await page.getByRole("button", { name: "Create user", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Create user", exact: true });
  const local = dialog.getByLabel("Create a local account instead", { exact: true });
  await dialog.getByLabel("Microsoft email", { exact: true }).fill("alice@example.test");
  await dialog.getByLabel("Display name", { exact: false }).fill("Alice Example");
  await dialog.getByRole("combobox", { name: "Groups (optional)", exact: true }).click();
  await page.getByRole("option", { name: "readers - Readers", exact: true }).click();
  await page.keyboard.press("Escape");
  await expect(dialog.getByLabel("Role", { exact: true })).toHaveValue("user");
  await expect(dialog.getByRole("button", { name: "Create user", exact: true })).toBeEnabled();
  await local.check();
  await dialog.getByLabel("Username", { exact: true }).fill("alice.local");
  await expect(dialog.getByLabel("Email (optional)", { exact: true })).toHaveValue("alice@example.test");
  await expect(dialog.getByLabel("Display name", { exact: false })).toHaveValue("Alice Example");
  await expect(dialog.getByLabel("Role", { exact: true })).toHaveValue("user");
  await dialog.getByLabel("I authorize local password sign-in for this user independently of Microsoft sign-in.", { exact: true }).check();
  await dialog.getByLabel("Role", { exact: true }).selectOption("auditor");
  await local.uncheck();
  await expect(dialog.getByLabel("Role", { exact: true })).toHaveValue("auditor");
  await expect(dialog.getByLabel("Username", { exact: true })).toHaveCount(0);
  await expect(dialog.getByLabel("Microsoft email", { exact: true })).toHaveValue("alice@example.test");
  await dialog.getByRole("button", { name: "Create user", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`principals/${returnedId}$`));
  expect(model.writes[0].body).toMatchObject({ role: "auditor", displayName: "Alice Example", microsoftEnrollment: { email: "alice@example.test" } });
  expect(model.writes[0].body).not.toHaveProperty("principalId");
  expect(model.writes[1]).toMatchObject({ path: `/v1/admin/principals/${returnedId}/groups/readers`, method: "PUT" });
  expect(model.writes).toHaveLength(2);
});

test("duplicate enrollment creation leaves the populated form for correction", async ({ page }) => {
  const model = await fixture(page, false);
  model.rejectCreate = true;
  await page.goto(`${assets.baseUrl}/ui/admin/principals`);
  await page.getByRole("button", { name: "Create user", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Create user", exact: true });
  await dialog.getByLabel("Microsoft email", { exact: true }).fill("person@example.test");
  await dialog.getByRole("button", { name: "Create user", exact: true }).click();
  await expect(dialog).toContainText("Enrollment changed or email already reserved");
  await expect(dialog.getByLabel("Microsoft email", { exact: true })).toHaveValue("person@example.test");
  expect(model.writes).toHaveLength(1);
});

test("pending enrollment shows disabled reservations and blocks direct Object-ID linking", async ({ page }) => {
  const model = await fixture(page);
  model.principal.status = "disabled";
  model.microsoftEnabled = true;
  await page.goto(`${assets.baseUrl}/ui/admin/principals/prepared`);
  await expect(signIn(page)).toContainText("person@example.test");
  await expect(signIn(page)).toContainText(reservation().tenantId);
  await expect(signIn(page)).toContainText("email remains reserved");
  await expect(signIn(page).getByRole("button", { name: "Edit Microsoft enrollment", exact: true })).toBeEnabled();
  await expect(page.getByLabel("Microsoft User Object ID", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Profile", exact: true })).toContainText("may replace administrator edits");
  await expect(page.getByRole("region", { name: "Profile", exact: true })).toContainText("does not change enrollment");
  expect(model.writes).toEqual([]);
});

test("profile and pending email edits remain independent and use the reviewed revision", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${assets.baseUrl}/ui/admin/principals/prepared`);
  const profile = page.getByRole("region", { name: "Profile", exact: true });
  await profile.getByRole("textbox").nth(1).fill("new-profile@example.test");
  await profile.getByRole("button", { name: "Save profile", exact: true }).click();
  await expect(profile.getByRole("button", { name: "Save profile", exact: true })).toBeDisabled();
  await expect(signIn(page)).toContainText("person@example.test");
  await signIn(page).getByRole("button", { name: "Edit Microsoft enrollment", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Edit Microsoft enrollment", exact: true });
  await dialog.getByLabel("Microsoft match email", { exact: true }).fill("new-match@example.test");
  await dialog.getByRole("button", { name: "Edit Microsoft enrollment", exact: true }).click();
  await expect(signIn(page)).toContainText("new-match@example.test");
  expect(model.writes).toEqual([
    { path: "/v1/admin/principals/prepared", method: "PATCH", body: { displayName: "Prepared Person", email: "new-profile@example.test" } },
    { path: endpoint, method: "PATCH", body: { enrollmentId: "enrollment-1", expectedRevision: 3, email: "new-match@example.test" } }
  ]);
  expect(model.principal.email).toBe("new-profile@example.test");
});

test("explicit cancellation retains account setup and allows fresh paused-provider preparation", async ({ page }) => {
  const model = await fixture(page);
  await page.goto(`${assets.baseUrl}/ui/admin/principals/prepared`);
  await signIn(page).getByRole("button", { name: "Cancel Microsoft enrollment", exact: true }).click();
  const cancel = page.getByRole("dialog", { name: "Cancel Microsoft enrollment", exact: true });
  await expect(cancel).toContainText("Prepared account settings, groups and grants remain");
  await cancel.getByRole("button", { name: "Cancel Microsoft enrollment", exact: true }).click();
  await expect(signIn(page)).not.toContainText("Awaiting first Microsoft sign-in");
  await signIn(page).getByRole("button", { name: "Prepare Microsoft sign-in", exact: true }).click();
  const create = page.getByRole("dialog", { name: "Prepare Microsoft sign-in", exact: true });
  await create.getByLabel("Microsoft match email", { exact: true }).fill("fresh@example.test");
  await create.getByRole("button", { name: "Prepare Microsoft sign-in", exact: true }).click();
  await expect(signIn(page)).toContainText("fresh@example.test");
  expect(model.writes).toEqual([
    { path: endpoint, method: "DELETE", body: {}, query: { enrollmentId: "enrollment-1", expectedRevision: "3" } },
    { path: endpoint, method: "POST", body: { email: "fresh@example.test" } }
  ]);
  expect(model.principal.email).toBe("profile@example.test");
});

for (const action of ["edit", "cancel"] as const) {
  test(`stale ${action} preserves its original fence until explicit refresh`, async ({ page }) => {
    const model = await fixture(page);
    await page.goto(`${assets.baseUrl}/ui/admin/principals/prepared`);
    const label = action === "edit" ? "Edit Microsoft enrollment" : "Cancel Microsoft enrollment";
    await signIn(page).getByRole("button", { name: label, exact: true }).click();
    const dialog = page.getByRole("dialog", { name: label, exact: true });
    if (action === "edit") await dialog.getByLabel("Microsoft match email", { exact: true }).fill("edited@example.test");
    // A competing callback consumes enrollment, or an administrator replaces it.
    model.principal.microsoftEnrollment = action === "edit" ? null : { ...reservation(), enrollmentId: "replacement", revision: 1 };
    if (action === "edit") {
      model.linked = true;
      model.principal.signInMethods.microsoft = "active";
    }
    model.conflict = true;
    await dialog.getByRole("button", { name: label, exact: true }).click();
    await expect(dialog).toContainText("Enrollment changed or email already reserved");
    await expect(dialog.getByRole("button", { name: label, exact: true })).toHaveCount(0);
    expect(model.writes).toHaveLength(1);
    if (action === "edit") expect(model.writes[0]!.body).toMatchObject({ enrollmentId: "enrollment-1", expectedRevision: 3 });
    else expect(model.writes[0]).toMatchObject({ body: {}, query: { enrollmentId: "enrollment-1", expectedRevision: "3" } });
    await dialog.getByRole("button", { name: "Refresh enrollment", exact: true }).click();
    await expect(dialog).toHaveCount(0);
    if (action === "edit") {
      await expect(signIn(page).getByRole("button", { name: "Unlink Microsoft login", exact: true })).toBeVisible();
      await expect(signIn(page).getByRole("button", { name: "Prepare Microsoft sign-in", exact: true })).toHaveCount(0);
    } else await expect(signIn(page)).toContainText("replacement");
    expect(model.writes).toHaveLength(1);
  });
}

test("unavailable preparation disables writes but keeps pending inspection and cancellation", async ({ page }) => {
  const model = await fixture(page);
  model.available = false;
  await page.goto(`${assets.baseUrl}/ui/admin/principals/prepared`);
  await expect(signIn(page)).toContainText("person@example.test");
  await expect(signIn(page).getByRole("button", { name: "Edit Microsoft enrollment", exact: true })).toBeDisabled();
  await expect(signIn(page).getByRole("button", { name: "Cancel Microsoft enrollment", exact: true })).toBeEnabled();
});

test("auditors can inspect pending metadata without enrollment controls", async ({ page }) => {
  const model = await fixture(page);
  model.role = "auditor";
  await page.goto(`${assets.baseUrl}/ui/admin/principals/prepared`);
  await expect(signIn(page)).toContainText("person@example.test");
  await expect(signIn(page).getByRole("button", { name: /Microsoft enrollment/ })).toHaveCount(0);
  expect(model.writes).toEqual([]);
});

test("established Microsoft methods offer no pending-enrollment creation", async ({ page }) => {
  const model = await fixture(page, false);
  model.linked = true;
  model.principal.signInMethods.microsoft = "active";
  await page.goto(`${assets.baseUrl}/ui/admin/principals/prepared`);
  await expect(signIn(page).getByRole("button", { name: "Unlink Microsoft login", exact: true })).toBeVisible();
  await expect(signIn(page).getByRole("button", { name: "Prepare Microsoft sign-in", exact: true })).toHaveCount(0);
});
