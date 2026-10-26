import { test, expect, type Page } from "@playwright/test";
import { createServer, type Server } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { AddressInfo } from "node:net";
import type { PrincipalRole } from "../src/types";
import { portalDist } from "./support/binaries";

let server: Server;
let baseUrl: string;
const envelope = (result: unknown) => ({ ok: true, result });
const principal = (id = "target") => ({ principalId: id, kind: "user", role: "user", selfServiceEnabled: true, displayName: id, groups: [], status: "active", createdAt: "2026-09-29T00:00:00Z", updatedAt: "2026-09-29T00:00:00Z", createdBy: "admin", signInMethods: { localPassword: "active", microsoft: "absent" }, groupMemberships: [], policyReferenceSections: [], activePolicyGroupSubjects: [] });
const config = { identityAuthority: "managed", policyAuthority: "managed", generation: 1, loadedAt: "2026-09-29T00:00:00Z", configHash: "fixture" };
const catalog = { services: [{ service: "jira", displayName: "Jira", surface: "http", actions: [{ action: "read", description: "Read", readOnly: true, requiredScopeTypes: [], credentialModes: ["service"] }], resourceScopes: {}, configuredCredentialModes: ["service"] }], subjects: { users: [], groups: [], anonymous: false }, resources: [], resourceGroups: [], executionContexts: { allowedValues: ["default"], defaultContext: "default" } };
const options = { policyGeneration: 1, executionContexts: ["default"], services: [], resources: [], resourceGroups: [] };
const grant = { grantRef: "managed-read", grantId: "managed-read", writable: true, version: 1, subjects: ["user:target"], service: "jira", actions: ["read"], credentialMode: "service", executionContexts: ["default"], status: "active", resources: { resourceIds: [], resourceGroupIds: [] } };

test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    const pathname = new URL(request.url!, "http://localhost").pathname;
    const asset = pathname.startsWith("/ui/assets/") ? pathname.slice(4) : "index.html";
    try { const content = await readFile(path.join(portalDist, asset)); response.setHeader("content-type", asset.endsWith(".js") ? "text/javascript" : asset.endsWith(".css") ? "text/css" : "text/html"); response.end(content); } catch { response.writeHead(404).end(); }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
test.afterAll(async () => { await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); });

async function fixture(page: Page, role: PrincipalRole, selfServiceEnabled: boolean, services = ["jira"]) {
  const session = { authenticated: true, principal: "viewer", role, selfServiceEnabled, policyManagementServices: role === "service_policy_manager" ? services : [], auditQueryable: true, csrfHeader: "x-csrf-token", csrfToken: "test-csrf", signInMethods: { localPassword: "active", microsoft: "absent" }, loginOptions: { localPassword: { enabled: true } }, tokenIssuancePolicy: { selfAgentInvoke: { defaultTtl: "1h", maxTtl: "8h", options: ["1h"] } } };
  const requests: string[] = [];
  const mutations: string[] = [];
  await page.route("**/v1/**", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    requests.push(pathname);
    if (route.request().method() !== "GET" && !pathname.endsWith("/effective-access")) mutations.push(pathname);
    let result: unknown = [];
    if (pathname === "/v1/auth/session") result = session;
    else if (pathname === "/v1/me") result = { serviceLimits: [] };
    else if (pathname === "/v1/credentials") result = { connections: [], retained: [] };
    else if (pathname === "/v1/admin/config/status") result = config;
    else if (pathname === "/v1/admin/principals") result = [principal()];
    else if (pathname === "/v1/admin/principals/target") result = principal();
    else if (pathname.endsWith("/login-methods")) result = [{ method: "local_password", status: "active" }];
    else if (pathname.endsWith("/identity-token")) result = { principalId: "target", configured: true, enabled: false, readOnly: true, revision: 1, updatedAt: "2026-10-10T00:00:00Z" };
    else if (pathname.endsWith("/identity-access")) result = { principalId: "target", incarnation: "gate-fixture", paused: false, version: 1, updatedAt: "2026-10-10T00:00:00Z", updatedBy: "admin" };
    else if (pathname.endsWith("/identity-bindings")) result = { bindings: [{ bindingId: "binding-fixture", principalId: "target", namespace: "retired_namespace", username: "Alice", enabled: true, readOnly: false, version: 3, createdAt: "2026-10-10T00:00:00Z", createdBy: "admin", updatedAt: "2026-10-10T00:00:00Z", updatedBy: "admin", namespaceAvailable: false }], configuredNamespaces: [{ namespace: "managed_linux", credentialTransports: ["authorization_user", "caller_authorization"] }] };
    else if (pathname === "/v1/admin/policy/status") result = { ...config, writable: true, policyGeneration: 1, counts: { active: 1, disabled: 0, deleted: 0 }, managementScope: { kind: "global" } };
    else if (pathname === "/v1/admin/policy/catalog") result = catalog;
    else if (pathname === "/v1/admin/policy/grants") result = [grant];
    else if (pathname.endsWith("/effective-access")) result = { policyGeneration: 1, access: [] };
    else if (pathname.endsWith("/tokens/options") || pathname.endsWith("/agent-tokens/options")) result = options;
    else if (pathname === "/v1/admin/imports") result = { catalogRevision: 1, operatorEnabled: false, availableKinds: [], importAuthentication: [], services: [] };
    else if (pathname === "/v1/resource-types") result = { resourceTypes: [] };
    else if (pathname.endsWith("/audit/options")) result = { services: [] };
    else if (pathname.endsWith("/audit/events")) result = { records: [], nextCursor: null };
    await route.fulfill({ json: envelope(result) });
  });
  return { session, requests, mutations };
}

for (const entry of ["/ui", "/ui/login"]) {
  test(`session outage at ${entry} shows a retry and recovers sign-in options`, async ({ page }) => {
    let unavailable = true;
    await page.route("**/v1/auth/session", (route) => route.fulfill(unavailable
      ? { status: 503, json: { ok: false, error: { message: "Session service unavailable" } } }
      : { json: envelope({ authenticated: false, loginOptions: { localPassword: { enabled: true } } }) }));
    await page.goto(`${baseUrl}${entry}`);
    await expect(page.getByText("Couldn’t connect to the broker", { exact: true })).toBeVisible();
    await expect(page.getByText("No browser sign-in method is enabled for this broker.", { exact: true })).toHaveCount(0);
    unavailable = false;
    await page.getByRole("button", { name: "Retry", exact: true }).click();
    await expect(page.getByLabel("Principal", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Password", { exact: true })).toBeVisible();
  });
}

for (const role of ["user", "auditor", "service_policy_manager", "admin"] as const) {
  test(`${role} with self-service disabled has no personal navigation or requests`, async ({ page }) => {
    const model = await fixture(page, role, false);
    await page.goto(`${baseUrl}/ui`);
    await expect(page).toHaveURL(role === "user" ? /\/ui\/account$/ : /\/ui\/admin\/policies$/);
    await expect(page.getByRole("navigation", { name: "My access", exact: true })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "My access", exact: true })).toHaveCount(0);
    await page.goto(`${baseUrl}/ui/tokens`);
    await expect(page.getByText("Page not found", { exact: true })).toBeVisible();
    await page.goto(`${baseUrl}/ui/account`);
    await expect(page.getByLabel("Current password", { exact: true })).toBeVisible();
    await expect(page.getByText("Self-service is disabled for your account.", { exact: true })).toBeVisible();
    expect(model.requests.filter((url) => /^\/v1\/(tokens|credentials|oauth|audit)(\/|$)/.test(url))).toEqual([]);
  });
}

test("Auditor inspects managed grants, principals, tokens and system without admin actions", async ({ page }) => {
  const model = await fixture(page, "auditor", true);
  const errors: string[] = []; page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(`${baseUrl}/ui/admin/policies`);
  await expect(page.getByRole("navigation", { name: "Admin", exact: true }).getByRole("link")).toHaveText(["Policies", "Principals", "Catalog", "Audit"]);
  await expect(page.getByRole("link", { name: "Create grant", exact: true })).toHaveCount(0);
  await page.goto(`${baseUrl}/ui/admin/policies/managed-read/edit`);
  await expect(page.getByText("This grant is read-only.", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Save grant", exact: true })).toHaveCount(0);
  await page.goto(`${baseUrl}/ui/admin/principals/target`);
  await expect(page.getByRole("region", { name: "Identity token", exact: true })).toContainText("This identity token is disabled in Access paths.");
  // Auditors see every access path and its settings, without controls.
  const paths = page.getByRole("table", { name: "Access paths", exact: true });
  await expect(paths.getByRole("row")).toHaveCount(3);
  await expect(paths.getByRole("row").nth(1)).toHaveAccessibleName(/^Identity token/);
  await expect(paths.getByRole("row", { name: /^Identity token/ })).toContainText(/Configured\s*Disabled\s*Read-only\s*1/);
  await expect(paths.getByRole("row", { name: /^retired_namespace\/Alice/ })).toContainText(/Namespace unavailable\s*Enabled\s*Full access\s*3/);
  await expect(paths.getByRole("switch")).toHaveCount(0);
  for (const name of ["Pause identity access", "Add binding", "Delete binding retired_namespace/Alice", "Reveal identity token", "Copy identity token", "Save access", "Reset local password", "Disable user", "Save profile"]) await expect(page.getByRole("button", { name, exact: true })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Add username binding", exact: true })).toHaveCount(0);
  await expect(page.getByRole("form", { name: "Add username binding", exact: true })).toHaveCount(0);
  await expect(page.getByLabel("Exact username", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("checkbox", { name: "Read-only", exact: true })).toHaveCount(0);
  await page.goto(`${baseUrl}/ui/admin/principals/target/tokens`);
  for (const name of ["Issue token", "Issue setup token", "Issue admin token"]) await expect(page.getByRole("button", { name, exact: true })).toHaveCount(0);
  await page.goto(`${baseUrl}/ui/admin/system`);
  await expect(page.getByRole("button", { name: "Refresh", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Reload config", exact: true })).toHaveCount(0);
  await page.goto(`${baseUrl}/ui/tokens`);
  await expect(page.getByRole("button", { name: "Issue token", exact: true }).first()).toBeEnabled();
  await page.getByRole("button", { name: "Issue token", exact: true }).first().click();
  await expect(page).toHaveURL(/\/ui\/tokens\/new/);
  await expect(page.getByRole("heading", { name: "Issue agent token", exact: true })).toBeVisible();
  expect(model.mutations).toEqual([]);
  expect(errors).toEqual([]);
});

for (const { role, identityAuthority } of [
  { role: "auditor", identityAuthority: "managed" },
  { role: "admin", identityAuthority: "toml" }
] as const) {
  test(`${role} cannot change Microsoft enrollment with ${identityAuthority} identity authority`, async ({ page }) => {
    const model = await fixture(page, role, false);
    await page.route("**/v1/admin/config/status", (route) => route.fulfill({ json: envelope({ ...config, identityAuthority }) }));
    await page.route("**/v1/admin/groups/onboarding", (route) => route.fulfill({ json: envelope({
      groupId: "onboarding", displayName: "Onboarding", status: "disabled", autoEnrollNewMicrosoftUsers: identityAuthority === "managed", memberCount: 0, members: [], policyReferenceSections: []
    }) }));
    await page.goto(`${baseUrl}/ui/admin/groups/onboarding`);
    const enrollment = page.getByRole("checkbox", { name: "Automatically add new Microsoft users", exact: true });
    await expect(enrollment).toBeDisabled();
    if (identityAuthority === "managed") {
      await expect(enrollment).toBeChecked();
      await expect(page.getByText("Enrollment is paused while this group is disabled.", { exact: false })).toBeVisible();
    } else {
      await expect(enrollment).not.toBeChecked();
      await expect(page.getByText("Group writes are unavailable while identity authority is toml.", { exact: true })).toBeVisible();
    }
    expect(model.mutations).toEqual([]);
  });
}

test("mapped groups explain durable local membership when Microsoft enrollment is enabled", async ({ page }) => {
  const model = await fixture(page, "admin", false);
  await page.route("**/v1/auth/session", (route) => route.fulfill({ json: envelope({ ...model.session, loginOptions: { ...model.session.loginOptions, microsoft: { enabled: true } } }) }));
  await page.route("**/v1/admin/groups/onboarding", (route) => route.fulfill({ json: envelope({
    groupId: "onboarding", displayName: "Onboarding", status: "active", autoEnrollNewMicrosoftUsers: true, memberCount: 0, members: [], policyReferenceSections: []
  }) }));
  await page.route("**/v1/admin/groups/onboarding/external-group-bindings", (route) => route.fulfill({ json: envelope([
    { bindingId: "mapping", externalGroupId: "00000000-0000-0000-0000-000000000123", groupId: "onboarding", status: "active", createdAt: "2026-10-20T00:00:00Z", createdBy: "admin", updatedAt: "2026-10-20T00:00:00Z", updatedBy: "admin" }
  ]) }));
  await page.goto(`${baseUrl}/ui/admin/groups/onboarding/microsoft`);
  await expect(page.getByText("That local membership survives loss or expiry of Microsoft group membership.", { exact: false })).toBeVisible();
  await expect(page.getByRole("table", { name: "Microsoft group mappings", exact: true })).toContainText("00000000-0000-0000-0000-000000000123");
});

for (const role of ["admin", "auditor"] as const) {
  test(`${role} sees no human identity sections or requests for a system principal`, async ({ page }) => {
    const model = await fixture(page, role, false);
    await page.route("**/v1/admin/principals/target", (route) => route.fulfill({ json: envelope({ ...principal(), kind: "system" }) }));
    await page.goto(`${baseUrl}/ui/admin/principals/target`);
    await expect(page.getByRole("heading", { name: "Profile", exact: true })).toBeVisible();
    for (const name of ["Identity access", "Identity token"]) {
      await expect(page.getByRole("heading", { name, exact: true })).toHaveCount(0);
    }
    expect(model.requests.filter((url) => /\/identity-(?:access|bindings|token)$/.test(url))).toEqual([]);
  });
}

test("scope-less managers land on a supported empty view without policy fetches", async ({ page }) => {
  const model = await fixture(page, "service_policy_manager", false, []);
  await page.goto(`${baseUrl}/ui`);
  await expect(page.getByText("No services assigned", { exact: true })).toBeVisible();
  expect(model.requests.filter((url) => url.startsWith("/v1/admin/policy/"))).toEqual([]);
});

test("identity pause works without inventory and a stale gate refreshes without replay", async ({ page }) => {
  await fixture(page, "admin", false);
  let access = { principalId: "target", incarnation: "gate-fixture", paused: false, version: 4, updatedAt: "2026-10-10T00:00:00Z", updatedBy: "admin" };
  const writes: unknown[] = [];
  await page.route("**/v1/admin/principals/target/identity-token", (route) => route.fulfill({ json: envelope({ principalId: "target", configured: false, enabled: true, readOnly: false, revision: 1, updatedAt: "2026-10-10T00:00:00Z" }) }));
  await page.route("**/v1/admin/principals/target/identity-access", async (route) => {
    if (route.request().method() === "PATCH") {
      const body = route.request().postDataJSON();
      writes.push(body);
      if (writes.length === 1) {
        access = { ...access, version: 5 };
        await route.fulfill({ status: 409, json: { ok: false, reasonCode: "identity_version_conflict", error: { message: "Version changed" } } });
        return;
      }
      access = { ...access, paused: body.paused, version: access.version + 1 };
    }
    await route.fulfill({ json: envelope(access) });
  });
  await page.goto(`${baseUrl}/ui/admin/principals/target`);
  const identity = page.getByRole("region", { name: "Identity access", exact: true });
  const inventory = page.getByRole("region", { name: "Identity token", exact: true });
  await expect(inventory).toContainText("Not configured");
  await expect(inventory.getByRole("button", { name: /Pause|Resume/ })).toHaveCount(0);
  await identity.getByRole("button", { name: "Pause identity access", exact: true }).click();
  await expect(identity.getByRole("alert")).toHaveText("Identity settings changed. Review the refreshed state before trying again.");
  await expect(identity).toContainText("Version 5");
  expect(writes).toEqual([{ paused: true, expectedVersion: 4 }]);
  await identity.getByRole("button", { name: "Pause identity access", exact: true }).click();
  await expect(identity.getByRole("button", { name: "Resume identity access", exact: true })).toBeVisible();
  expect(writes).toEqual([{ paused: true, expectedVersion: 4 }, { paused: true, expectedVersion: 5 }]);
  await expect(inventory).toContainText("Not configured");
  await expect(identity).toContainText("Independently valid issued Broker tokens and browser sign-in remain available.");
});

test("username bindings preserve exact names, namespace availability, read-only creation and version checks", async ({ page }) => {
  await fixture(page, "admin", false);
  const binding = { bindingId: "new-binding", principalId: "target", namespace: "managed_linux", username: "Alice+01@example.test", enabled: true, readOnly: false, version: 1, createdAt: "2026-10-10T00:00:00Z", createdBy: "admin", updatedAt: "2026-10-10T00:00:00Z", updatedBy: "admin", namespaceAvailable: true };
  let bindings: typeof binding[] = [];
  const writes: unknown[] = [];
  let patchConflict = true;
  let deleteConflict = true;
  const conflict = { status: 409, json: { ok: false, reasonCode: "identity_version_conflict", error: { message: "Version changed" } } };
  await page.route("**/v1/admin/principals/target/identity-bindings**", async (route) => {
    const request = route.request();
    if (request.method() === "GET") {
      await route.fulfill({ json: envelope({ bindings, configuredNamespaces: [{ namespace: "managed_linux", credentialTransports: ["authorization_user", "caller_authorization"] }] }) });
      return;
    }
    const body = request.postDataJSON();
    writes.push({ method: request.method(), body, query: new URL(request.url()).search });
    if (request.method() === "POST") bindings = [{ ...binding, ...body }];
    if (request.method() === "PATCH") {
      // Another administrator changes the binding before the first Read-only change.
      if (patchConflict && "readOnly" in body) {
        patchConflict = false;
        bindings = [{ ...bindings[0]!, version: bindings[0]!.version + 1 }];
        await route.fulfill(conflict);
        return;
      }
      const { expectedVersion: _expected, ...change } = body;
      bindings = [{ ...bindings[0]!, ...change, version: bindings[0]!.version + 1, namespaceAvailable: false }];
    }
    if (request.method() === "DELETE") {
      if (deleteConflict) {
        deleteConflict = false;
        bindings = [{ ...bindings[0]!, version: bindings[0]!.version + 1 }];
        await route.fulfill(conflict);
        return;
      }
      bindings = [];
    }
    await route.fulfill({ json: envelope(bindings[0] ?? {}) });
  });
  await page.goto(`${baseUrl}/ui/admin/principals/target`);
  const identity = page.getByRole("region", { name: "Identity access", exact: true });
  const paths = identity.getByRole("table", { name: "Access paths", exact: true });
  await expect(paths.getByRole("row")).toHaveCount(2);
  await expect(identity.getByText("No username bindings.", { exact: true })).toBeVisible();
  // The create fields are their own titled form below the table, not settings of the table.
  await expect(identity.getByRole("heading", { name: "Add username binding", exact: true, level: 4 })).toBeVisible();
  const create = identity.getByRole("form", { name: "Add username binding", exact: true });
  await expect(create).toHaveAccessibleDescription("Trusted callers configured with the namespace can then attest this person on HTTP MCP by presenting the exact username.");
  await expect(create.getByRole("button")).toHaveText(["Add binding"]);
  await create.getByLabel("Identity namespace", { exact: true }).selectOption("managed_linux");
  await create.getByLabel("Exact username", { exact: true }).fill(" Alice ");
  await expect(create.getByRole("button", { name: "Add binding", exact: true })).toBeDisabled();
  await expect(create.getByText("Enter an exact username using the allowed characters; spaces are not removed.", { exact: true })).toBeVisible();
  await create.getByLabel("Exact username", { exact: true }).fill(binding.username);
  const createReadOnly = create.getByRole("checkbox", { name: "Read-only", exact: true });
  await expect(createReadOnly).not.toBeChecked();
  await createReadOnly.check();
  await create.getByRole("button", { name: "Add binding", exact: true }).click();
  const name = `managed_linux/${binding.username}`;
  const row = paths.getByRole("row", { name: new RegExp(`^${name.replace(/[.+]/g, "\\$&")}`) });
  const enabled = row.getByRole("switch", { name: `Binding ${name} enabled`, exact: true });
  const readOnly = row.getByRole("switch", { name: `Binding ${name} read-only`, exact: true });
  await expect(enabled).toBeChecked();
  await expect(readOnly).toBeChecked();
  await expect(createReadOnly).not.toBeChecked();
  await expect(create.getByLabel("Exact username", { exact: true })).toHaveValue("");
  // The identity token stays the first row.
  await expect(paths.getByRole("row").nth(1)).toHaveAccessibleName(/^Identity token/);
  await enabled.click();
  await expect(enabled).not.toBeChecked();
  await expect(row).toContainText("Namespace unavailable");
  await enabled.click();
  await expect(enabled).toBeChecked();
  await expect(readOnly).toBeChecked();
  // A stale version refreshes the row and asks for a fresh change; nothing is replayed.
  await readOnly.click();
  await expect(identity.getByText("Identity settings changed. Review the refreshed state before trying again.", { exact: true })).toBeVisible();
  await expect(row).toContainText(/Namespace unavailable\s*4\s*Delete$/);
  await expect(readOnly).toBeChecked();
  expect(writes).toHaveLength(4);
  await readOnly.click();
  await expect(readOnly).not.toBeChecked();
  await expect(enabled).toBeChecked();
  await row.getByRole("button", { name: `Delete binding ${name}`, exact: true }).click();
  await page.getByRole("alertdialog", { name: "Delete username binding?", exact: true }).getByRole("button", { name: "Delete binding", exact: true }).click();
  await expect(page.getByRole("alertdialog")).toHaveCount(0);
  await expect(identity.getByText("Identity settings changed. Review the refreshed state before trying again.", { exact: true })).toBeVisible();
  expect(writes).toHaveLength(6);
  await row.getByRole("button", { name: `Delete binding ${name}`, exact: true }).click();
  await page.getByRole("alertdialog", { name: "Delete username binding?", exact: true }).getByRole("button", { name: "Delete binding", exact: true }).click();
  await expect(identity.getByText("No username bindings.", { exact: true })).toBeVisible();
  await expect(paths.getByRole("row")).toHaveCount(2);
  expect(writes).toEqual([
    { method: "POST", body: { namespace: "managed_linux", username: binding.username, readOnly: true }, query: "" },
    { method: "PATCH", body: { enabled: false, expectedVersion: 1 }, query: "" },
    { method: "PATCH", body: { enabled: true, expectedVersion: 2 }, query: "" },
    { method: "PATCH", body: { readOnly: false, expectedVersion: 3 }, query: "" },
    { method: "PATCH", body: { readOnly: false, expectedVersion: 4 }, query: "" },
    { method: "DELETE", body: null, query: "?expectedVersion=5" },
    { method: "DELETE", body: null, query: "?expectedVersion=6" }
  ]);
});

test("without configured namespaces the add-binding heading explains why there is no form", async ({ page }) => {
  await fixture(page, "admin", false);
  await page.route("**/v1/admin/principals/target/identity-bindings", (route) => route.fulfill({ json: envelope({ bindings: [], configuredNamespaces: [] }) }));
  await page.goto(`${baseUrl}/ui/admin/principals/target`);
  const identity = page.getByRole("region", { name: "Identity access", exact: true });
  await expect(identity.getByRole("heading", { name: "Add username binding", exact: true, level: 4 })).toBeVisible();
  await expect(identity.getByText("No username identity namespaces are configured. Configure a trusted caller before adding a binding.", { exact: true })).toBeVisible();
  await expect(identity.getByRole("form", { name: "Add username binding", exact: true })).toHaveCount(0);
  await expect(identity.getByLabel("Exact username", { exact: true })).toHaveCount(0);
  await expect(identity.getByRole("button", { name: "Add binding", exact: true })).toHaveCount(0);
});

test("the identity token is the first, undeletable access path and its toggles send the current revision", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.setViewportSize({ width: 1024, height: 800 });
  await fixture(page, "admin", false);
  let token = { principalId: "target", configured: true, enabled: true, readOnly: false, revision: 4, updatedAt: "2026-10-10T00:00:00Z" };
  const writes: unknown[] = [];
  let conflict = true;
  await page.route("**/v1/admin/principals/target/identity-token", async (route) => {
    if (route.request().method() === "PATCH") {
      const body = route.request().postDataJSON();
      writes.push(body);
      if (conflict) {
        // Another administrator made the token read-only first.
        conflict = false;
        token = { ...token, readOnly: true, revision: token.revision + 1 };
        await route.fulfill({ status: 409, json: { ok: false, reasonCode: "identity_version_conflict", error: { message: "identity token revision changed" } } });
        return;
      }
      const { expectedRevision: _expected, ...change } = body;
      token = { ...token, ...change, revision: token.revision + 1 };
    }
    await route.fulfill({ json: envelope(token) });
  });
  await page.goto(`${baseUrl}/ui/admin/principals/target`);
  const identity = page.getByRole("region", { name: "Identity access", exact: true });
  const secret = page.getByRole("region", { name: "Identity token", exact: true });
  const paths = identity.getByRole("table", { name: "Access paths", exact: true });
  const row = paths.getByRole("row").nth(1);
  await expect(row).toHaveAccessibleName(/^Identity token Built-in/);
  await expect(row.getByRole("button")).toHaveCount(0);
  const enabled = row.getByRole("switch", { name: "Identity token enabled", exact: true });
  const readOnly = row.getByRole("switch", { name: "Identity token read-only", exact: true });
  await expect(enabled).toBeChecked();
  await expect(readOnly).not.toBeChecked();
  await expect(row).toContainText(/Configured\s*4$/);
  await enabled.click();
  await expect(identity.getByRole("alert")).toHaveText("Identity settings changed. Review the refreshed state before trying again.");
  await expect(readOnly).toBeChecked();
  await expect(enabled).toBeChecked();
  await expect(row).toContainText(/Configured\s*5$/);
  expect(writes).toEqual([{ enabled: false, expectedRevision: 4 }]);
  await enabled.click();
  await expect(enabled).not.toBeChecked();
  await expect(identity.getByRole("alert")).toHaveCount(0);
  await expect(secret).toContainText("This identity token is disabled in Access paths. Fingerprint access is denied while the secret is kept.");
  await readOnly.click();
  await expect(readOnly).not.toBeChecked();
  await expect(row).toContainText(/Configured\s*7$/);
  expect(writes).toEqual([{ enabled: false, expectedRevision: 4 }, { enabled: false, expectedRevision: 5 }, { readOnly: false, expectedRevision: 6 }]);
  // Secret management stays in the identity-token section, whatever the path settings.
  await expect(secret.getByRole("button", { name: "Reveal identity token", exact: true })).toBeEnabled();
  await expect(secret.getByRole("button", { name: "Generate token", exact: true })).toBeEnabled();
  await expect(secret.getByRole("button", { name: "Remove token", exact: true })).toBeEnabled();
  await expect(identity.getByRole("button", { name: "Pause identity access", exact: true })).toBeVisible();
  // The table and form fit a 1024px window without horizontal scrolling.
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  expect(await paths.evaluate((table) => table.parentElement!.scrollWidth <= table.parentElement!.clientWidth + 1)).toBe(true);
  expect(errors).toEqual([]);
});

test("authorization denial refreshes the session and closes stale mutation dialogs without replay", async ({ page }) => {
  const model = await fixture(page, "admin", false);
  let attempts = 0;
  await page.route("**/v1/admin/config/reload", async (route) => {
    attempts++; model.session.role = "auditor";
    await route.fulfill({ status: 403, json: { ok: false, reasonCode: "admin_required", error: { message: "Administrator access required" } } });
  });
  await page.goto(`${baseUrl}/ui/admin/system`);
  await page.getByRole("button", { name: "Reload config", exact: true }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: /Reload/ }).click();
  await expect(page.getByText("Auditor · read-only", { exact: true })).toBeVisible();
  await expect(page.getByRole("alertdialog")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Reload config", exact: true })).toHaveCount(0);
  expect(attempts).toBe(1);
});

test("account access edits preview scope deletion and preserve an independent self-service flag", async ({ page }) => {
  await fixture(page, "admin", true);
  const target = { ...principal(), role: "service_policy_manager" };
  let updated: unknown;
  await page.route("**/v1/admin/principals/target", (route) => route.fulfill({ json: envelope(target) }));
  await page.route("**/v1/admin/policy/service-managers", (route) => route.fulfill({ json: envelope(["jira", "gitlab"].map((service) => ({ assignmentId: service, service, principalId: "target", principalStatus: "active", serviceConfigured: true, createdAt: "2026-09-29T00:00:00Z", createdBy: "admin" }))) }));
  await page.route("**/v1/admin/principals/target/access", async (route) => {
    updated = route.request().postDataJSON();
    Object.assign(target, updated);
    await route.fulfill({ json: envelope(target) });
  });
  await page.goto(`${baseUrl}/ui/admin/principals/target`);
  await page.getByLabel("Role", { exact: true }).selectOption("auditor");
  await page.getByLabel("Self-service enabled", { exact: true }).uncheck();
  await page.getByRole("button", { name: "Save access", exact: true }).click();
  const confirmation = page.getByRole("alertdialog", { name: "Update account access?", exact: true });
  await expect(confirmation).toContainText("jira, gitlab");
  await expect(confirmation).toContainText("administrative API tokens");
  await confirmation.getByRole("button", { name: "Update access", exact: true }).click();
  await expect.poll(() => updated).toEqual({ role: "auditor", selfServiceEnabled: false });
  await expect(page.getByLabel("Role", { exact: true })).toHaveValue("auditor");
  await expect(page.getByLabel("Self-service enabled", { exact: true })).not.toBeChecked();
});

test("a manager role can change when policy is file-owned and assignments cannot be listed", async ({ page }) => {
  await fixture(page, "admin", true);
  const target = { ...principal(), role: "service_policy_manager" };
  let updated: unknown;
  let assignmentReads = 0;
  await page.route("**/v1/admin/config/status", (route) => route.fulfill({ json: envelope({ ...config, policyAuthority: "toml" }) }));
  await page.route("**/v1/admin/principals/target", (route) => route.fulfill({ json: envelope(target) }));
  await page.route("**/v1/admin/policy/service-managers", async (route) => {
    assignmentReads++;
    await route.fulfill({ status: 400, json: { ok: false, reasonCode: "managed_policy_required", error: { message: "Managed policy is required" } } });
  });
  await page.route("**/v1/admin/principals/target/access", async (route) => {
    updated = route.request().postDataJSON();
    Object.assign(target, updated);
    await route.fulfill({ json: envelope(target) });
  });
  await page.goto(`${baseUrl}/ui/admin/principals/target`);
  await expect(page.getByText("Service management assignments are available only when identity and policy are managed.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save managed services", exact: true })).toHaveCount(0);
  await page.getByLabel("Role", { exact: true }).selectOption("auditor");
  await page.getByRole("button", { name: "Save access", exact: true }).click();
  const confirmation = page.getByRole("alertdialog", { name: "Update account access?", exact: true });
  await expect(confirmation).toContainText("Any stored direct management assignments will be removed.");
  await expect(confirmation).toContainText("Assignment names are unavailable while policy is file-owned.");
  await confirmation.getByRole("button", { name: "Update access", exact: true }).click();
  await expect.poll(() => updated).toEqual({ role: "auditor", selfServiceEnabled: true });
  await expect(page.getByLabel("Role", { exact: true })).toHaveValue("auditor");
  expect(assignmentReads).toBe(0);
});

test("failed managed assignment reads block role-change confirmation and can be retried", async ({ page }) => {
  await fixture(page, "admin", true);
  let unavailable = true;
  await page.route("**/v1/admin/principals/target", (route) => route.fulfill({ json: envelope({ ...principal(), role: "service_policy_manager" }) }));
  await page.route("**/v1/admin/policy/service-managers", (route) => route.fulfill(unavailable
    ? { status: 503, json: { ok: false, reasonCode: "internal_error", error: { message: "Manager assignments unavailable" } } }
    : { json: envelope([{ assignmentId: "jira", service: "jira", principalId: "target", principalStatus: "active", serviceConfigured: true, createdAt: "2026-09-29T00:00:00Z", createdBy: "admin" }]) }));
  await page.goto(`${baseUrl}/ui/admin/principals/target`);
  await page.getByLabel("Role", { exact: true }).selectOption("auditor");
  await expect(page.getByText("Manager assignments unavailable", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Save access", exact: true })).toBeDisabled();
  unavailable = false;
  await page.getByRole("button", { name: "Retry", exact: true }).first().click();
  await page.getByRole("button", { name: "Save access", exact: true }).click();
  await expect(page.getByRole("alertdialog", { name: "Update account access?", exact: true })).toContainText("Direct management assignments will be removed: jira.");
});

test("manager services are selected directly on the account and allow several services", async ({ page }) => {
  await fixture(page, "admin", true);
  const target = { ...principal(), role: "service_policy_manager" };
  const assigned: string[] = [];
  await page.route("**/v1/admin/principals/target", (route) => route.fulfill({ json: envelope(target) }));
  await page.route("**/v1/admin/policy/catalog", (route) => route.fulfill({ json: envelope({ ...catalog, services: [...catalog.services, { ...catalog.services[0], service: "gitlab", displayName: "GitLab" }] }) }));
  await page.route("**/v1/admin/policy/service-managers", (route) => route.fulfill({ json: envelope(assigned.map((service) => ({ assignmentId: service, service, principalId: "target", principalStatus: "active", serviceConfigured: true, createdAt: "2026-09-29T00:00:00Z", createdBy: "admin" }))) }));
  await page.route("**/v1/admin/policy/services/*/managers/target", async (route) => {
    expect(route.request().method()).toBe("PUT");
    assigned.push(new URL(route.request().url()).pathname.split("/")[5]!);
    await route.fulfill({ json: envelope({}) });
  });
  await page.goto(`${baseUrl}/ui/admin/principals/target`);
  await page.getByRole("checkbox", { name: "Jira", exact: true }).check();
  await page.getByRole("checkbox", { name: "GitLab", exact: true }).check();
  await page.getByRole("button", { name: "Save managed services", exact: true }).click();
  await expect.poll(() => assigned.slice().sort()).toEqual(["gitlab", "jira"]);
  await expect(page.getByRole("checkbox", { name: "Jira", exact: true })).toBeChecked();
  await expect(page.getByRole("checkbox", { name: "GitLab", exact: true })).toBeChecked();
});

test("Auditor direct creation URLs and the command palette expose no administrative mutations", async ({ page }) => {
  await fixture(page, "auditor", false);
  await page.goto(`${baseUrl}/ui/admin/policies/new`);
  await expect(page.getByText("Page not found", { exact: true })).toBeVisible();
  for (const path of ["/ui/admin/catalog?import=1", "/ui/admin/catalog/resources?item=new", "/ui/admin/catalog/resource-groups?item=new"]) {
    await page.goto(`${baseUrl}${path}`);
    await expect(page.getByRole("dialog")).toHaveCount(0);
  }
  await page.goto(`${baseUrl}/ui/admin/principals`);
  await page.getByRole("button", { name: "Search or jump to…", exact: false }).click();
  for (const label of ["Create user", "Create service account", "Create group", "Create grant", "Issue agent token", "Reload runtime configuration", "Import service"]) {
    await expect(page.getByRole("option", { name: label, exact: false })).toHaveCount(0);
  }
});

test("Auditor can inspect a stored import preview while discovery and acceptance stay unavailable", async ({ page }) => {
  const model = await fixture(page, "auditor", false);
  const definition = { action: "inspect", description: "Inspect the imported service", source: { toolName: "inspect" }, inputSchema: { type: "object" }, annotations: {}, readOnly: true };
  const imported = {
    definition: { service: "metrics", displayName: "Metrics", adapterKind: "mcp_http", endpoint: "https://example.test/mcp", executionBindings: [], connectionSettings: {}, discovery: { kind: "anonymous" }, transportAuth: false },
    status: "draft", version: 1, actions: [], slotVersions: {}, credentialInputs: {}, createdAt: "2026-09-29T00:00:00Z", updatedAt: "2026-09-29T00:00:00Z", createdBy: "admin", updatedBy: "admin"
  };
  const data = {
    service: imported, operatorAllowed: false, catalogRevision: 1, scopedMcp: { ready: false, issues: [], truncated: false }, scopedMcpWarnings: [], importAuthentication: [], affectedGrants: [], affectedGrantsByAction: {},
    preview: { service: "metrics", serviceVersion: 1, catalogRevision: 1, configRevision: "fixture", credentialVersions: {}, manifestHash: "fixture-preview", manifest: { protocolVersion: "fixture", metadata: {}, tools: [{ definition, unsupportedReason: null, readOnlyHint: true }] }, createdAt: "2026-09-29T00:00:00Z", expiresAt: "2026-09-30T00:00:00Z", createdBy: "admin" }
  };
  await page.route("**/v1/admin/imports", (route) => route.fulfill({ json: envelope({ catalogRevision: 1, operatorEnabled: false, availableKinds: [], importAuthentication: [], services: [imported] }) }));
  await page.route("**/v1/admin/imports/metrics/preview", (route) => route.fulfill({ json: envelope(data) }));
  await page.goto(`${baseUrl}/ui/admin/catalog/services/metrics/import`);
  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  const preview = page.getByRole("dialog", { name: "Review discovered tools", exact: true });
  await expect(preview).toContainText("Inspect the imported service");
  await expect(preview.getByRole("button", { name: "Accept selected tools", exact: true })).toHaveCount(0);
  for (const field of await preview.locator("input:not([type=search]), select").all()) await expect(field).toBeDisabled();
  await preview.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(preview).toHaveCount(0);
  for (const name of ["Discover tools", "Edit configuration", "Enable", "Disable", "Retire"]) await expect(page.getByRole("button", { name, exact: true })).toHaveCount(0);
  expect(model.mutations).toEqual([]);
});
