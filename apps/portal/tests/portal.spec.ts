import { expect, test, type Locator, type Page } from "@playwright/test";
import { once } from "node:events";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { RESOURCE_TYPES } from "../unit/resource-types.fixture";
import { brokerBinary, portalDist } from "./support/binaries";
import { startBroker } from "./support/broker-process";
import { releaseTestRoot } from "./support/test-root";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

let broker: ChildProcessWithoutNullStreams | undefined;
let baseUrl = "";
let tempDir = "";
let requestCounter = 0;
/** The empty personal credentials list, `GET /v1/credentials`. */
const EMPTY_CREDENTIALS = { connections: [], retained: [] };
const initialAdminPassword = "admin-password";
const updatedAdminPassword = "admin-password-updated";

async function expectDialogWithinViewport(dialog: Locator) {
  const inset = await dialog.evaluate((element) => {
    const bounds = element.getBoundingClientRect();
    return {
      top: bounds.top,
      right: window.innerWidth - bounds.right,
      bottom: window.innerHeight - bounds.bottom,
      left: bounds.left,
    };
  });
  expect(inset.top).toBeGreaterThanOrEqual(9);
  expect(inset.right).toBeGreaterThanOrEqual(9);
  expect(inset.bottom).toBeGreaterThanOrEqual(9);
  expect(inset.left).toBeGreaterThanOrEqual(9);
}

test.beforeAll(async () => {
  await fs.access(path.join(portalDist, "index.html"));
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "aab-portal-e2e-"));
  ({ child: broker, baseUrl } = await startBroker({
    binary: brokerBinary,
    configure: async (port) => {
      await writeBrokerFixture(tempDir, port);
      return path.join(tempDir, "broker.toml");
    },
    cwd: repoRoot,
    env: {
      ...process.env,
      RUST_LOG: "agent_access_broker=warn,agent_access_core=warn"
    },
    readinessHeaders: () => ({ "X-Agent-Access-Request-Id": `playwright-health-${++requestCounter}` }),
    timeoutMs: 90_000
  }));
});

test.afterAll(async ({}, testInfo) => {
  await stopBroker();
  await releaseTestRoot(tempDir, testInfo);
});

/** Options of a kit combobox (the list opens on click and closes again). */
async function comboboxOptions(page: Page, name: string) {
  const input = page.getByRole("combobox", { name, exact: true });
  await input.click();
  const options = await page.getByRole("listbox").getByRole("option").allTextContents();
  await page.keyboard.press("Escape");
  return options;
}

/** Field labels carry an "(optional)" marker. */
const GROUPS_FIELD = /^Groups ?\(optional\)$/;

/** Types into a kit combobox and picks the option with this accessible name. */
async function pickCombobox(page: Page, name: string | RegExp, query: string, option: string | RegExp = query) {
  const input = page.getByRole("combobox", typeof name === "string" ? { name, exact: true } : { name });
  await input.click();
  await input.fill(query);
  await page.getByRole("listbox").getByRole("option", typeof option === "string" ? { name: option, exact: true } : { name: option }).click();
}

/**
 * Mocked sessions carry no broker cookie: answer every API route the test does
 * not mock with a plain 404 instead of letting it reach the real broker (whose
 * 401 would sign the mocked session out). Register before specific routes.
 */
async function mockUnlistedApis(page: Page) {
  await page.route("**/v1/**", (route) => route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ ok: false, reasonCode: "not_found", error: { message: "Not mocked" } }) }));
}

// Mocked sessions carry no broker cookie, so serve the registered types directly.
async function mockResourceTypes(page: Page) {
  await page.route("**/v1/resource-types", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ resourceTypes: RESOURCE_TYPES }) }));
}

/** Opens a row or header "More actions" menu and picks an item. */
async function openMenu(page: Page, trigger: Locator, item: string) {
  await trigger.click();
  await page.getByRole("menuitem", { name: item, exact: true }).click();
}

/** A DataTable row whose row header (the primary cell, holding the row link) has this name. */
function tableRow(scope: Page | Locator, name: string | RegExp) {
  const page = "page" in scope && typeof scope.page === "function" ? scope.page() : (scope as Page);
  return scope.getByRole("row").filter({ has: page.getByRole("rowheader", typeof name === "string" ? { name, exact: true } : { name }) });
}

/** The cell of a table row under the column header with this text. */
async function columnCell(row: Locator, header: string) {
  await expect(row).toBeAttached();
  // Columns hidden by width (priority) still count, so include hidden headers.
  const headers = (await row.locator("xpath=ancestor::table[1]").getByRole("columnheader", { includeHidden: true }).allTextContents()).map((text) => text.trim());
  const index = headers.indexOf(header);
  expect(index, `column ${header} in ${headers.join(", ")}`).toBeGreaterThanOrEqual(0);
  return row.locator(":scope > th, :scope > td").nth(index);
}

/** Row-header names of a table, top to bottom. */
async function rowHeaders(table: Locator) {
  return (await table.getByRole("rowheader").allTextContents()).map((text) => text.trim());
}

async function confirmDialog(page: Page, title: string, button: string) {
  const dialog = page.getByRole("alertdialog", { name: title, exact: true });
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: button, exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

/** Opens a principal's page through the command palette (client-side navigation). */
async function openPrincipalFromPalette(page: Page, option: RegExp) {
  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog", { name: "Command palette", exact: true });
  await page.keyboard.type(option.source.replace(/^\^/, ""));
  await palette.getByRole("group", { name: "Principals" }).getByRole("option", { name: option }).first().click();
  await expect(palette).toHaveCount(0);
}

async function signOut(page: Page) {
  await openMenu(page, page.getByRole("button", { name: "Account", exact: true }), "Sign out");
  await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
}

async function expectNoHorizontalOverflow(page: Page) {
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
}

/** Records CSP violations and uncaught errors so a test can assert none happened. */
function watchPageErrors(page: Page) {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error" && /Content Security Policy|Refused to (apply|load|execute)/i.test(message.text())) errors.push(message.text());
  });
  page.on("pageerror", (error) => errors.push(error.message));
  return errors;
}

/** Picks a facet suggestion by clicking it (the list opens on click). */
async function chooseFacet(page: Page, name: string, option: string | RegExp) {
  await page.getByRole("combobox", { name, exact: true }).click();
  await page.getByRole("listbox", { name, exact: true }).getByRole("option", typeof option === "string" ? { name: option, exact: true } : { name: option }).click();
}

async function browserManagementRequest<T>(page: Page, path: string, init: { method?: string; body?: unknown } = {}) {
  return page.evaluate(
    async ({ path, init }) => {
      const sessionResponse = await fetch("/v1/auth/session", {
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      });
      const sessionEnvelope = await sessionResponse.json();
      if (!sessionResponse.ok || !sessionEnvelope.ok || !sessionEnvelope.result?.csrfHeader || !sessionEnvelope.result?.csrfToken) {
        throw new Error("Failed to load browser session for management request");
      }
      const headers: Record<string, string> = {
        Accept: "application/json",
        "X-Agent-Access-Request-Id": crypto.randomUUID()
      };
      if (init.body !== undefined) {
        headers["Content-Type"] = "application/json";
      }
      headers[sessionEnvelope.result.csrfHeader] = sessionEnvelope.result.csrfToken;
      const response = await fetch(path, {
        method: init.method ?? "GET",
        credentials: "same-origin",
        headers,
        body: init.body === undefined ? undefined : JSON.stringify(init.body)
      });
      const envelope = await response.json();
      if (!response.ok || !envelope.ok) {
        throw new Error(envelope.error?.message ?? "Management request failed");
      }
      return envelope.result;
    },
    { path, init }
  ) as Promise<T>;
}

// Signs in through the local-login API; the session cookie lands in the page's context.
async function apiSignIn(page: Page, principalId: string, password: string) {
  const response = await page.request.post(`${baseUrl}/v1/auth/local/login`, {
    headers: { Origin: baseUrl, "X-Agent-Access-Request-Id": `playwright-login-${++requestCounter}` },
    data: { principalId, password, returnTo: "/ui" }
  });
  const body = await response.json();
  return response.ok() && body.ok
    ? (body.result as { passwordChangeRequired?: boolean; csrfHeader: string; csrfToken: string })
    : null;
}

// The bootstrap admin, whether or not an earlier test already replaced its initial password.
async function signInAsAdmin(page: Page) {
  if (await apiSignIn(page, "admin", updatedAdminPassword)) return;
  const session = await apiSignIn(page, "admin", initialAdminPassword);
  expect(session?.passwordChangeRequired).toBe(true);
  const change = await page.request.post(`${baseUrl}/v1/auth/local/password/change`, {
    headers: {
      Origin: baseUrl,
      "X-Agent-Access-Request-Id": `playwright-password-${++requestCounter}`,
      [session!.csrfHeader]: session!.csrfToken
    },
    data: { currentPassword: initialAdminPassword, newPassword: updatedAdminPassword }
  });
  expect(change.ok()).toBe(true);
}

async function invokeAsAgent(token: string, service: string, action: string, inputs: Record<string, unknown>) {
  const response = await fetch(`${baseUrl}/v1/invoke/${service}/${action}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "X-Agent-Access-Request-Id": `playwright-invoke-${++requestCounter}`
    },
    body: JSON.stringify({ inputs })
  });
  return (await response.json()) as { decision: string; reasonCode?: string; brokerRequestId: string };
}

/** Adds a group or user subject in the grant editor. */
async function addGrantSubject(page: Page, kind: "Group" | "User", query: string, option: string | RegExp) {
  const subjects = page.locator("#grant-subjects");
  await subjects.getByRole("group", { name: "Subject type", exact: true }).getByRole("button", { name: kind, exact: true }).click();
  const input = subjects.getByRole("combobox", { name: kind, exact: true });
  await input.click();
  await input.fill(query);
  await page.getByRole("listbox").getByRole("option", typeof option === "string" ? { name: option, exact: true } : { name: option }).click();
}

function grantEditor(page: Page) {
  const footer = page.getByRole("region", { name: "Save grant", exact: true });
  return {
    subjects: page.getByRole("list", { name: "Grant subjects", exact: true }),
    service: page.getByRole("combobox", { name: "Service", exact: true }),
    contexts: page.getByRole("group", { name: "Execution contexts", exact: true }),
    resources: page.getByRole("group", { name: "Resources", exact: true }),
    resourceGroups: page.getByRole("group", { name: "Resource groups", exact: true }),
    preview: page.getByRole("complementary", { name: "Preview", exact: true }),
    footer,
    create: footer.getByRole("button", { name: "Create grant", exact: true }),
    save: footer.getByRole("button", { name: "Save grant", exact: true }),
    cancel: footer.getByRole("button", { name: "Cancel", exact: true })
  };
}

async function exerciseGrantResourcePicker(page: Page) {
  const resourcePath = "/v1/admin/policy/resources";
  const groupPath = "/v1/admin/policy/resource-groups";
  const grantPath = "/v1/admin/policy/grants";
  const resources = [
    { id: "picker-repository", displayName: "Picker repository", resourceType: "git_repository", selector: { kind: "all" }, allowedExecutionContexts: ["default"], enabled: true },
    { id: "picker-private", displayName: "Picker private repository", resourceType: "git_repository", selector: { kind: "exact", value: "engineering/private" }, allowedExecutionContexts: ["internal"], enabled: false },
    { id: "picker-project", displayName: "Picker Jira project", resourceType: "jira_project", selector: { kind: "exact", value: "PICKER" }, allowedExecutionContexts: ["default"], enabled: true },
  ];
  const groups = [
    { id: "picker-mixed", name: "Picker mixed group", includedResourceIds: ["picker-repository", "picker-project"], excludedResourceIds: ["picker-private"] },
    { id: "picker-exclusions", name: "Picker exclusions group", includedResourceIds: [], excludedResourceIds: ["picker-private"] },
    { id: "picker-empty", name: "Picker empty group", includedResourceIds: [], excludedResourceIds: [] },
    { id: "picker-jira", name: "Picker Jira group", includedResourceIds: ["picker-project"], excludedResourceIds: [] },
  ];
  for (const body of resources) await browserManagementRequest(page, resourcePath, { method: "POST", body });
  for (const body of groups) await browserManagementRequest(page, groupPath, { method: "POST", body });

  await page.goto(`${baseUrl}/ui/admin/policies/new`);
  const editor = grantEditor(page);
  const picker = editor.resources;
  const groupPicker = editor.resourceGroups;
  await page.getByLabel("Grant ID").fill("picker-live-groups");
  await addGrantSubject(page, "Group", "users", "User Access · ID: users");
  await editor.service.selectOption("gitlab_git");
  await page.getByRole("checkbox", { name: "repo.fetch", exact: true }).check();
  await editor.contexts.getByLabel("default", { exact: true }).check();
  await editor.contexts.getByLabel("internal", { exact: true }).uncheck();
  await editor.contexts.getByLabel("external", { exact: true }).uncheck();

  await expect(picker.getByRole("checkbox", { name: /^Picker repository/ })).toBeVisible();
  const privateRepository = picker.getByRole("checkbox", { name: /^Picker private repository/ });
  await expect(privateRepository).toBeEnabled();
  await expect(privateRepository).toHaveAccessibleDescription(/Disabled.*Not available in selected contexts/);
  await expect(picker.getByText(/Disabled.*Not available in selected contexts/)).toBeVisible();
  await expect(picker.getByRole("checkbox", { name: /^Picker Jira project/ })).toHaveCount(0);
  await expect(groupPicker.getByRole("checkbox", { name: "Picker Jira group", exact: true })).toHaveCount(0);
  for (const name of ["Picker mixed group", "Picker exclusions group", "Picker empty group"]) {
    await expect(groupPicker.getByRole("checkbox", { name, exact: true })).toBeVisible();
  }

  const mixed = page.getByTestId("grant-resource-group-picker-mixed");
  await mixed.locator("summary").click();
  await expect(mixed.getByText("Includes", { exact: true })).toBeVisible();
  await expect(mixed.getByText("Excludes", { exact: true })).toBeVisible();
  await expect(mixed.getByText(/Picker Jira project/)).toBeVisible();
  await expect(mixed.getByText(/Picker private repository/)).toBeVisible();
  await expect(mixed.getByText(/Exclusion applies regardless of enabled state or execution context/)).toBeVisible();
  await expect(mixed.getByText(/Not used by gitlab_git/)).toBeVisible();
  await expect(page.getByTestId("grant-resource-group-picker-exclusions")).toContainText("Exclusions only for gitlab_git");
  await expect(groupPicker.getByRole("checkbox", { name: "Picker exclusions group", exact: true })).toHaveAccessibleDescription(/Exclusions only for gitlab_git/);
  await expect(page.getByTestId("grant-resource-group-picker-empty")).toContainText("No visible members");
  await expect(groupPicker.getByRole("checkbox", { name: "Picker empty group", exact: true })).toHaveAccessibleDescription(/No visible members/);

  await picker.getByRole("checkbox", { name: /^Picker repository/ }).check();
  await groupPicker.getByRole("checkbox", { name: "Picker exclusions group", exact: true }).check();
  await editor.service.selectOption("jira");
  await expect(picker.getByRole("checkbox", { name: /^Picker repository/ })).toBeChecked();
  await expect(groupPicker.getByRole("checkbox", { name: "Picker exclusions group", exact: true })).toBeChecked();
  await expect(picker.getByRole("checkbox", { name: /^Picker repository/ })).toHaveAccessibleDescription(/Not used by jira/);
  await expect(groupPicker.getByRole("checkbox", { name: "Picker exclusions group", exact: true })).toHaveAccessibleDescription(/Not used by jira/);
  const mismatchWarning = page.getByText(/^Some selected resources or groups are not used by /);
  await expect(mismatchWarning).toBeVisible();
  await expect(picker.getByRole("checkbox", { name: /^Picker Jira project/ })).toBeVisible();
  await expect(groupPicker.getByRole("checkbox", { name: "Picker Jira group", exact: true })).toBeVisible();
  await page.getByRole("searchbox", { name: "Filter resources", exact: true }).fill("no matching resource");
  await expect(picker.getByRole("checkbox", { name: /^Picker repository/ })).toBeChecked();
  // Removing an incompatible selection removes its checkbox immediately.
  await picker.getByRole("checkbox", { name: /^Picker repository/ }).click();
  await groupPicker.getByRole("checkbox", { name: "Picker exclusions group", exact: true }).click();
  await expect(picker.getByRole("checkbox", { name: /^Picker repository/ })).toHaveCount(0);
  await expect(groupPicker.getByRole("checkbox", { name: "Picker exclusions group", exact: true })).toHaveCount(0);
  await page.getByRole("searchbox", { name: "Filter resources", exact: true }).fill("");

  await editor.service.selectOption("gitlab_git");
  await page.getByRole("checkbox", { name: "repo.fetch", exact: true }).check();
  await groupPicker.getByRole("checkbox", { name: "Picker mixed group", exact: true }).check();
  await groupPicker.getByRole("checkbox", { name: "Picker exclusions group", exact: true }).check();
  await groupPicker.getByRole("checkbox", { name: "Picker empty group", exact: true }).check();
  await expect(mismatchWarning).toHaveCount(0);
  // The live preview asks the broker: the disabled, internal-only exclusion still restricts this default-context grant.
  await expect(editor.preview.getByText(/All Git repositories.*except engineering\/private/).first()).toBeVisible();
  await expect(editor.preview.locator("pre")).toContainText('"picker-mixed"');
  const saved = page.waitForRequest((request) => request.method() === "POST" && new URL(request.url()).pathname === grantPath);
  await editor.create.click();
  expect((await saved).postDataJSON().resources).toEqual({ resourceIds: [], resourceGroupIds: ["picker-mixed", "picker-exclusions", "picker-empty"] });
  await expect(page).toHaveURL(/\/ui\/admin\/policies\?grant=picker-live-groups$/);
  await expect(page.getByRole("complementary", { name: "Grant picker-live-groups", exact: true })).toBeVisible();
  const persisted = await browserManagementRequest<{ resources: { resourceIds: string[]; resourceGroupIds: string[] } }>(page, `${grantPath}/picker-live-groups`);
  expect(persisted.resources).toEqual({ resourceIds: [], resourceGroupIds: ["picker-mixed", "picker-exclusions", "picker-empty"] });

  await page.goto(`${baseUrl}/ui/admin/policies/new`);
  await page.getByLabel("Grant ID").fill("picker-no-access");
  await addGrantSubject(page, "Group", "users", "User Access · ID: users");
  await editor.service.selectOption("gitlab_git");
  await page.getByRole("checkbox", { name: "repo.fetch", exact: true }).check();
  await groupPicker.getByRole("checkbox", { name: "Picker empty group", exact: true }).check();
  await expect(page.getByText(/^No eligible inclusions for the selected service and execution contexts\./)).toBeVisible();
  await expect(editor.preview.getByText("No access currently", { exact: true })).toBeVisible();
  await expect(editor.create).toBeEnabled();
  await editor.create.click();
  await expect(page).toHaveURL(/\/ui\/admin\/policies\?grant=picker-no-access$/);
  const emptyGrant = await browserManagementRequest<{ resources: { resourceIds: string[]; resourceGroupIds: string[] } }>(page, `${grantPath}/picker-no-access`);
  expect(emptyGrant.resources).toEqual({ resourceIds: [], resourceGroupIds: ["picker-empty"] });

  for (const id of ["picker-live-groups", "picker-no-access"]) await browserManagementRequest(page, `${grantPath}/${id}?expectedVersion=1`, { method: "DELETE" });
  for (const group of groups) await browserManagementRequest(page, `${groupPath}/${group.id}?expectedVersion=1`, { method: "DELETE" });
  for (const resource of resources) await browserManagementRequest(page, `${resourcePath}/${resource.id}?expectedVersion=1`, { method: "DELETE" });
}

// Credential storage remains real. Provider credential verification is represented
// at the browser boundary so this portal suite never contacts a live Jira tenant.
async function stubCredentialVerification(page: Page) {
  const records = new Map<string, Record<string, unknown>>();
  const verified = new Set<string>();
  const remember = (record: Record<string, unknown> | null) => {
    if (!record?.credentialId) return record;
    records.set(String(record.credentialId), record);
    return verified.has(String(record.credentialId)) ? { ...record, verificationStatus: "upstream_verified", lastVerifiedAt: new Date().toISOString() } : record;
  };
  await page.route(/\/v1\/(?:admin\/.*)?credentials(?:\/|\?|$)/, async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const verify = /\/credentials\/connections\/([^/]+)\/verify$/.exec(pathname);
    if (request.method() === "POST" && verify) {
      // Self-service lists key the active token by connection; administrator lists by stored service.
      const record = [...records.values()].reverse().find((entry) => (entry.connection ?? entry.service) === decodeURIComponent(verify[1]!));
      if (!record) throw new Error("Verification fixture requires a stored credential");
      verified.add(String(record.credentialId));
      await route.fulfill({ contentType: "application/json", body: JSON.stringify({ ok: true, result: { ...record, verificationStatus: "upstream_verified", lastVerifiedAt: new Date().toISOString(), probeService: verify[1] } }) });
      return;
    }
    const response = await route.fetch();
    const body = await response.json();
    if (Array.isArray(body.result)) body.result = body.result.map((record: Record<string, unknown>) => remember(record));
    else if (Array.isArray(body.result?.connections)) {
      body.result.connections = body.result.connections.map((connection: Record<string, unknown>) => ({ ...connection, credential: remember(connection.credential as Record<string, unknown> | null) }));
    }
    await route.fulfill({ response, json: body });
  });
}

test("Microsoft login uses the server start path with the current sanitized portal path", async ({ page }) => {
  await page.route("**/v1/auth/session", (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      ok: true,
      result: {
        authenticated: false,
        loginOptions: {
          localPassword: { enabled: false },
          microsoft: {
            enabled: true,
            available: true,
            displayName: "Microsoft",
            startPath: "/v1/auth/oidc/microsoft/start"
          }
        }
      }
    })
  }));
  await page.route("**/v1/auth/oidc/microsoft/start?**", (route) => route.fulfill({ status: 204 }));

  await page.goto(`${baseUrl}/ui/admin/groups/operators`);
  await expect(page.getByLabel("Principal")).toHaveCount(0);
  const requestPromise = page.waitForRequest((request) => request.url().includes("/v1/auth/oidc/microsoft/start?"));
  await page.getByRole("button", { name: "Sign in with Microsoft" }).click();
  const request = await requestPromise;
  expect(new URL(request.url()).searchParams.get("returnTo")).toBe("/ui/admin/groups/operators");
});

test("Microsoft login remains visible but disabled during a provider outage", async ({ page }) => {
  await page.route("**/v1/auth/session", (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      ok: true,
      result: {
        authenticated: false,
        loginOptions: {
          localPassword: { enabled: true },
          microsoft: {
            enabled: true,
            available: false,
            displayName: "Microsoft",
            startPath: "/v1/auth/oidc/microsoft/start"
          }
        }
      }
    })
  }));

  await page.goto(`${baseUrl}/ui/tokens`);
  await expect(page.getByRole("button", { name: "Sign in with Microsoft" })).toBeDisabled();
  await expect(page.getByText("Microsoft sign-in is temporarily unavailable.")).toBeVisible();
  await expect(page.getByLabel("Principal")).toBeVisible();
});

test("the sign-in page explains a failed Microsoft sign-in from the broker redirect", async ({ page }) => {
  await page.goto(`${baseUrl}/ui/login?error=oidc_admission_denied&requestId=req-4f2a.9`);
  const failure = page.getByRole("alert").filter({ hasText: "Microsoft sign-in failed" });
  await expect(failure).toContainText("This Microsoft account is not allowed to sign in to the broker.");
  await expect(failure).toContainText("Request ID req-4f2a.9");
  // Unknown or unsafe values are never echoed back.
  await page.goto(`${baseUrl}/ui/login?error=${encodeURIComponent("<b>boom</b>")}&requestId=${encodeURIComponent("<script>")}`);
  const unsafe = page.getByRole("alert").filter({ hasText: "Microsoft sign-in failed" });
  await expect(unsafe).toContainText("Microsoft sign-in failed.");
  await expect(unsafe).not.toContainText("boom");
  await expect(unsafe).not.toContainText("Request ID");
});

test("token boundaries use live resource references and allow empty effective access", async ({ page }) => {
  const envelope = (result: unknown) => JSON.stringify({ ok: true, result });
  const resources = [
    { id: "spaces", resourceType: "confluence_space", selector: { kind: "all" }, allowedExecutionContexts: ["internal"], enabled: true },
    { id: "eng", resourceType: "confluence_space", selector: { kind: "exact", value: "ENG" }, allowedExecutionContexts: ["internal", "external"], enabled: true },
  ];
  const options = {
    policyGeneration: 5, resources, resourceGroups: [{ id: "docs", name: "Documentation" }], executionContexts: ["internal", "external"],
    services: [{ service: "confluence", displayName: "Confluence", brokerHosts: [], executionContexts: ["internal", "external"], actions: [{ action: "page.view", description: "View pages", readOnly: true, resourceType: "confluence_space", requiredScopeTypes: ["space"], executionContexts: ["internal", "external"], effectiveAccessByExecutionContext: {
      internal: [{ included: [{ kind: "all" }], excluded: [] }],
      external: [{ included: [{ kind: "exact", value: "ENG" }], excluded: [] }]
    } }] }],
    mcp: null
  };
  await mockUnlistedApis(page);
  await mockResourceTypes(page);
  await page.route("**/v1/auth/session", (route) => route.fulfill({ contentType: "application/json", body: envelope({ role: "user", selfServiceEnabled: true, authenticated: true, principal: "boundary-user",  csrfHeader: "x-csrf-token", csrfToken: "csrf-token", tokenIssuancePolicy: { selfAgentInvoke: { defaultTtl: "1h", maxTtl: "8h", options: ["1h"] } } }) }));
  await page.route("**/v1/tokens/options", (route) => route.fulfill({ contentType: "application/json", body: envelope(options) }));
  await page.route("**/v1/tokens/effective-access", (route) => route.fulfill({ contentType: "application/json", body: envelope({ policyGeneration: 5, access: [] }) }));
  await page.route(/\/v1\/tokens(?:\?.*)?$/, async (route) => {
    const request = route.request();
    const result = request.method() === "POST" ? { token: "aab_mock_boundary_secret_value", record: { tokenId: "tok_new", principalId: "boundary-user", name: request.postDataJSON().name, tokenClass: "agent_invoke", scopes: request.postDataJSON(), createdAt: "2026-08-15T00:00:00Z", createdBy: "boundary-user" } } : [];
    await route.fulfill({ contentType: "application/json", body: envelope(result) });
  });
  for (const path of ["/v1/credentials/targets", "/v1/credentials"]) await page.route(`**${path}`, (route) => route.fulfill({ contentType: "application/json", body: envelope(path === "/v1/credentials" ? EMPTY_CREDENTIALS : []) }));
  await page.goto(`${baseUrl}/ui/access`);
  await expect(page.getByRole("main", { name: "Access", exact: true })).toBeVisible();
  const row = tableRow(page, "page.view");
  await expect(row.getByText("All Confluence spaces", { exact: true })).toBeVisible();
  await page.getByRole("radiogroup", { name: "Execution context", exact: true }).getByRole("radio", { name: "external", exact: true }).check();
  await expect(page).toHaveURL(/context=external/);
  await expect(page.getByText("All Confluence spaces", { exact: true })).toHaveCount(0);
  await expect(row.getByText("ENG", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Issue token", exact: true }).first().click();
  const dialog = page.getByRole("main", { name: "Issue agent token", exact: true });
  await dialog.getByRole("textbox", { name: "Name", exact: true }).fill("limited-docs");
  await dialog.getByRole("group", { name: "Access", exact: true }).getByRole("button", { name: "Restrict to selected", exact: true }).click();
  await dialog.getByRole("checkbox", { name: "confluence", exact: true }).check();
  await dialog.getByRole("checkbox", { name: "page.view", exact: true }).check();
  await dialog.getByRole("group", { name: "confluence resources", exact: true }).getByRole("button", { name: "Selected resources and groups", exact: true }).click();
  await dialog.getByRole("checkbox", { name: "Documentation", exact: true }).check();
  await dialog.getByRole("group", { name: "Execution contexts" }).getByLabel("internal", { exact: true }).uncheck();
  await expect(dialog.getByRole("checkbox", { name: "Documentation", exact: true })).toBeChecked();
  await expect(dialog.getByText("No access currently", { exact: true })).toBeVisible();
  await expect(dialog).toContainText("Restrictions cannot be edited after issuance.");
  const issued = page.waitForRequest((request) => request.method() === "POST" && new URL(request.url()).pathname === "/v1/tokens");
  await dialog.getByRole("button", { name: "Issue token", exact: true }).click();
  expect((await issued).postDataJSON()).toMatchObject({ allowedExecutionContexts: ["external"], serviceRestrictions: { confluence: { actions: ["page.view"], resources: { resourceIds: [], resourceGroupIds: ["docs"] } } } });
  const reveal = page.getByRole("dialog", { name: "Token created" });
  await expect(reveal.getByRole("group", { name: "confluence" }).getByText("Documentation", { exact: true })).toBeVisible();
  // No HTTP MCP endpoint accepts the token, so there is no client setup.
  await expect(reveal.getByRole("region", { name: "Connect an MCP client" })).toHaveCount(0);
  await expectNoHorizontalOverflow(page);
});

test("scoped policy managers retain self-service navigation and only receive their policy area", async ({ page }) => {
  const managementResult = (result: unknown) => JSON.stringify({
    ok: true,
    decision: "allow",
    requestId: "request-1",
    brokerRequestId: "broker-1",
    operation: "policy",
    principal: "inventory-owner",
    result
  });
  await mockUnlistedApis(page);
  await mockResourceTypes(page);
  await page.route("**/v1/auth/session", (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      ok: true,
      result: { role: "service_policy_manager", selfServiceEnabled: true,
        authenticated: true,
        principal: "inventory-owner",
        displayName: "Inventory Owner",

        policyManagementServices: ["inventory"],
        auditQueryable: true,
        csrfHeader: "x-csrf-token",
        csrfToken: "csrf-token"
      }
    })
  }));
  await page.route("**/v1/admin/policy/status", (route) => route.fulfill({
    contentType: "application/json",
    body: managementResult({
      identityAuthority: "managed",
      policyAuthority: "managed",
      writable: true,
      defaultDecision: "deny",
      configGeneration: 1,
      policyGeneration: 4,
      counts: { active: 1, disabled: 0, deleted: 0 },
      managementScope: { kind: "services", services: ["inventory"] }
    })
  }));
  await page.route("**/v1/admin/policy/catalog", (route) => route.fulfill({
    contentType: "application/json",
    body: managementResult({
      resources: [], resourceGroups: [],
      services: [{
        service: "inventory",
        displayName: "Inventory",
        surface: "http",
        actions: [{
          action: "widgets.read",
          description: "Read widgets",
          requiredScopeTypes: [],
          credentialModes: ["service"],
          lookupRequired: false,
          inputSchema: {}
        }],
        resourceScopes: {},
        configuredCredentialModes: ["service"],
        lookupCredentialConfigured: false
      }],
      executionContexts: { allowedValues: ["internal"], contextRequired: false },
      subjects: {
        users: [{ principalId: "inventory-owner", displayName: "Inventory Owner", status: "active" }, ...Array.from({ length: 25 }, (_, index) => ({ principalId: `reader-${index}`, displayName: `Reader ${index}`, status: "active" }))],
        groups: [],
        anonymous: false
      }
    })
  }));
  await page.route("**/v1/admin/policy/grants", (route) => route.fulfill({
    contentType: "application/json",
    body: managementResult([{
      grantRef: "inventory-readers",
      writable: true,
      grantId: "inventory-readers",
      subjects: ["user:inventory-owner"],
      service: "inventory",
      actions: ["widgets.read"],
      executionContexts: ["internal"],
      resources: { resourceIds: [], resourceGroupIds: [] },
      credentialMode: "service",
      status: "active",
      version: 2
    }])
  }));
  for (const path of ["/v1/credentials/targets", "/v1/credentials", "/v1/tokens", "/v1/tokens/options"]) {
    await page.route(`**${path}`, (route) => route.fulfill({
      contentType: "application/json",
      body: managementResult(path === "/v1/tokens/options" ? { policyGeneration: 1, resources: [], resourceGroups: [], executionContexts: [], services: [] } : path === "/v1/credentials" ? EMPTY_CREDENTIALS : [])
    }));
  }

  // Policy managers land in Admin with only their policy area and Audit.
  await page.goto(`${baseUrl}/ui`);
  await expect(page).toHaveURL(/\/ui\/admin\/policies$/);
  await expect(page.getByRole("main", { name: "Policies", exact: true })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Admin", exact: true }).getByRole("link")).toHaveText(["Policies", "Audit"]);
  await expect(page.getByRole("link", { name: "System", exact: true })).toHaveCount(0);
  await expect(page.getByText("Policy gen 4", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Assign service policy manager" })).toHaveCount(0);
  for (const path of ["/ui/admin/principals", "/ui/admin/catalog", "/ui/admin/system"]) {
    await page.goto(`${baseUrl}${path}`);
    await expect(page.getByRole("heading", { name: "Page not found", exact: true })).toBeVisible();
  }
  await page.goto(`${baseUrl}/ui/admin/policies`);

  // Self-service stays one click away.
  const space = page.getByRole("navigation", { name: "Space", exact: true });
  await space.getByRole("link", { name: "My access", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/access$/);
  await expect(page.getByRole("navigation", { name: "My access", exact: true }).getByRole("link")).toHaveText(["Access", "Tokens", "Credentials", "Activity"]);
  await space.getByRole("link", { name: "Admin", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/policies$/);

  // The keyboard-active subject option scrolls into view in a long list.
  const subjectFilter = page.getByRole("combobox", { name: "Subject", exact: true });
  await subjectFilter.click();
  for (let index = 0; index < 26; index += 1) await subjectFilter.press("ArrowDown");
  await expect.poll(() => subjectFilter.evaluate((input) => {
    const option = document.getElementById(input.getAttribute("aria-activedescendant") ?? "");
    const list = option?.closest(".wb-listbox");
    if (!option || !list) return false;
    const bounds = option.getBoundingClientRect();
    const container = list.getBoundingClientRect();
    return bounds.top >= container.top - 1 && bounds.bottom <= container.bottom + 1;
  })).toBe(true);
  await subjectFilter.press("Escape");
  await page.getByRole("checkbox", { name: "Inventory" }).check();
  await expect(page).toHaveURL(/service=inventory/);
  await expect(tableRow(page, "inventory-readers")).toBeVisible();
  await page.getByRole("button", { name: "Clear service filter", exact: true }).click();
  await expect(page).not.toHaveURL(/service=/);

  await page.getByRole("main").getByRole("link", { name: "Create grant", exact: true }).first().click();
  await expect(page).toHaveURL(/\/ui\/admin\/policies\/new$/);
  const editor = grantEditor(page);
  await expect(editor.service.locator("option")).toHaveText(["Choose a service", "Inventory (inventory)"]);
  await editor.cancel.click();
  await expect(page).toHaveURL(/\/ui\/admin\/policies$/);

  // The table's keyboard cursor opens the grant drawer; Escape returns focus to the row.
  const grants = page.getByRole("table", { name: "Grants", exact: true });
  await grants.click({ position: { x: 1, y: 1 } });
  await page.keyboard.press("j");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/[?&]grant=inventory-readers/);
  await expect(page.getByRole("complementary", { name: "Grant inventory-readers", exact: true })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page).not.toHaveURL(/grant=/);
  await expect(tableRow(page, "inventory-readers").getByRole("link", { name: "inventory-readers", exact: true })).toBeFocused();
  await tableRow(page, "inventory-readers").getByRole("link", { name: "Edit inventory-readers", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/policies\/inventory-readers\/edit$/);
  await expect(editor.service).toBeDisabled();
  await expect(page.getByText("Service policy managers cannot move a grant to another service.")).toBeVisible();
  await expect(editor.save).toBeDisabled();
});

test("audit navigation and pages stay hidden when the audit store cannot be queried", async ({ page }) => {
  const envelope = (result: unknown) => JSON.stringify({ ok: true, decision: "allow", requestId: "request-hidden", brokerRequestId: "broker-hidden", operation: "read", principal: "admin", result });
  await mockUnlistedApis(page);
  await mockResourceTypes(page);
  await page.route("**/v1/auth/session", (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      ok: true,
      result: { role: "admin", selfServiceEnabled: true, authenticated: true, principal: "admin",  auditQueryable: false, csrfHeader: "x-csrf-token", csrfToken: "csrf-token" }
    })
  }));
  for (const path of ["/v1/credentials/targets", "/v1/credentials", "/v1/tokens"]) {
    await page.route(`**${path}`, (route) => route.fulfill({ contentType: "application/json", body: envelope(path === "/v1/credentials" ? EMPTY_CREDENTIALS : []) }));
  }
  await page.route("**/v1/tokens/options", (route) => route.fulfill({ contentType: "application/json", body: envelope({ policyGeneration: 1, resources: [], resourceGroups: [], executionContexts: [], services: [] }) }));
  const auditRequests: string[] = [];
  page.on("request", (request) => {
    if (/\/v1\/(admin\/)?audit\//.test(new URL(request.url()).pathname)) auditRequests.push(request.url());
  });

  await page.goto(`${baseUrl}/ui`);
  await expect(page).toHaveURL(/\/ui\/admin\/policies$/);
  await expect(page.getByRole("navigation", { name: "Admin", exact: true }).getByRole("link")).toHaveText(["Policies", "Principals", "Catalog"]);
  await page.getByRole("navigation", { name: "Space", exact: true }).getByRole("link", { name: "My access", exact: true }).click();
  await expect(page.getByRole("navigation", { name: "My access", exact: true }).getByRole("link")).toHaveText(["Access", "Tokens", "Credentials"]);
  for (const path of [
    "/ui/admin/audit",
    "/ui/admin/audit?request=5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a3b",
    "/ui/activity?decision=deny",
    "/ui/activity?request=5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a3b",
    "/ui/admin/principals/alice/activity",
    "/ui/admin/principals/alice/activity?request=5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a3b&record=01a0e6ca-866f-7f43-a0a9-e86d008a8860"
  ]) {
    await page.goto(`${baseUrl}${path}`);
    await expect(page.getByRole("heading", { name: "Page not found", exact: true })).toBeVisible();
  }
  // The palette offers no audit destinations either.
  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog", { name: "Command palette", exact: true });
  await expect(palette).toBeVisible();
  await page.keyboard.type("audit");
  await expect(palette.getByRole("option", { name: /^Audit/ })).toHaveCount(0);
  await expect(palette.getByRole("option", { name: /^Activity/ })).toHaveCount(0);
  await page.keyboard.press("Escape");
  expect(auditRequests).toEqual([]);
});

test("global admins assign and revoke a service policy manager with whole-service confirmation", async ({ page }) => {
  const managementResult = (result: unknown) => JSON.stringify({
    ok: true,
    decision: "allow",
    requestId: "request-admin",
    brokerRequestId: "broker-admin",
    operation: "policy",
    principal: "admin",
    result
  });
  const assignment = {
    assignmentId: "assignment-1",
    service: "inventory",
    principalId: "inventory-owner", displayName: "Inventory Owner", principalStatus: "active",
    serviceConfigured: true,
    createdAt: "2026-08-12T12:00:00Z",
    createdBy: "admin"
  };
  let assignments: typeof assignment[] = [];
  let isAdmin = true;
  let csrfExpired = false;

  await mockUnlistedApis(page);
  await mockResourceTypes(page);
  await page.route("**/v1/admin/principals", (route) => route.fulfill({ json: { ok: true, result: [{ principalId: "inventory-owner", displayName: "Inventory Owner", role: "service_policy_manager", selfServiceEnabled: true, status: "active" }] } }));
  await page.route("**/v1/auth/session", (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      ok: true,
      result: { role: isAdmin ? "admin" : "service_policy_manager", selfServiceEnabled: true,
        authenticated: true,
        principal: "admin",
        displayName: "Administrator",

        policyManagementServices: isAdmin ? [] : ["inventory"],
        csrfHeader: "x-csrf-token",
        csrfToken: "csrf-token"
      }
    })
  }));
  await page.route("**/v1/admin/policy/status", (route) => route.fulfill({
    contentType: "application/json",
    body: managementResult({
      identityAuthority: "managed",
      policyAuthority: "managed",
      writable: true,
      defaultDecision: "deny",
      configGeneration: 1,
      policyGeneration: 4,
      counts: { active: 0, disabled: 0, deleted: 0 },
      managementScope: { kind: "global" }
    })
  }));
  await page.route("**/v1/admin/policy/catalog", (route) => route.fulfill({
    contentType: "application/json",
    body: managementResult({
      resources: [], resourceGroups: [],
      services: [{
        service: "inventory",
        displayName: "Inventory",
        surface: "http",
        actions: [],
        resourceScopes: {},
        configuredCredentialModes: ["service"],
        lookupCredentialConfigured: false
      }],
      executionContexts: { allowedValues: ["internal"], contextRequired: false },
      subjects: {
        users: [{ principalId: "inventory-owner", displayName: "Inventory Owner", status: "active" }],
        groups: [{ groupId: "inventory-team", displayName: "Inventory Team", status: "active" }],
        anonymous: false
      }
    })
  }));
  await page.route("**/v1/admin/imports", (route) => route.fulfill({
    contentType: "application/json",
    body: managementResult({ catalogRevision: 1, operatorEnabled: false, availableKinds: [], importAuthentication: [], services: [] })
  }));
  await page.route("**/v1/admin/policy/service-managers", (route) => route.fulfill({
    contentType: "application/json",
    body: managementResult(assignments)
  }));
  await page.route("**/v1/admin/policy/services/inventory/managers/inventory-owner", async (route) => {
    if (!isAdmin) {
      const reasonCode = csrfExpired ? "csrf_invalid" : "admin_required";
      csrfExpired = false;
      await route.fulfill({
        status: 403,
        contentType: "application/json",
        body: JSON.stringify({ ok: false, reasonCode, error: { message: "Global administrator access is required" } })
      });
      return;
    }
    if (route.request().method() === "PUT") {
      assignments = [assignment];
      await route.fulfill({ contentType: "application/json", body: managementResult(assignment) });
      return;
    }
    assignments = [];
    await route.fulfill({ contentType: "application/json", body: managementResult({ removed: true }) });
  });
  await page.route("**/v1/tokens/options", (route) => route.fulfill({
    contentType: "application/json",
    body: managementResult({ policyGeneration: 1, resources: [], resourceGroups: [], executionContexts: [], services: [] })
  }));

  // Managers are listed on the service's Managers tab in the Catalog.
  await page.goto(`${baseUrl}/ui/admin/catalog/services/inventory/managers`);
  await expect(page.getByRole("heading", { name: "No service policy managers", exact: true })).toBeVisible();
  await expect(page.getByText("Only global administrators manage grants for Inventory.")).toBeVisible();
  await page.getByRole("button", { name: "Assign manager", exact: true }).first().click();
  const assignDialog = page.getByRole("dialog", { name: "Assign service policy manager", exact: true });
  await expect(assignDialog.getByLabel("Service")).toHaveValue("inventory");
  await expect(assignDialog.getByLabel("Service")).toBeDisabled();
  await expect(assignDialog.getByRole("group", { name: "Holder type", exact: true })).toHaveCount(0);
  await expect(assignDialog.getByRole("combobox", { name: "Group", exact: true })).toHaveCount(0);
  await pickCombobox(page, "Principal", "inventory", "Inventory Owner · ID: inventory-owner");
  await expect(assignDialog).toContainText("inventory-owner will manage every grant for inventory");
  await expect(assignDialog).toContainText("granting access to themselves or anyone else");
  await expect(assignDialog).toContainText("authorizing configured service credentials without seeing the secrets");
  await assignDialog.getByRole("button", { name: "Assign manager", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "Service policy manager assigned" })).toBeVisible();

  const managerRow = tableRow(page, "Inventory Owner");
  await expect(managerRow).toContainText("inventory-owner");
  await managerRow.getByRole("button", { name: "Revoke inventory-owner", exact: true }).click();
  await confirmDialog(page, "Revoke service policy manager?", "Revoke manager");
  await expect(page.getByRole("status").filter({ hasText: "Service policy manager revoked" })).toBeVisible();
  await expect(managerRow).toHaveCount(0);

  // The Policies sidebar lists managed services and assigns from there too.
  await page.goto(`${baseUrl}/ui/admin/policies`);
  await expect(page.getByText("No service policy managers.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Assign service policy manager", exact: true }).click();
  await expect(assignDialog.getByLabel("Service")).toBeEnabled();
  await pickCombobox(page, "Principal", "inventory", "Inventory Owner · ID: inventory-owner");
  await assignDialog.getByRole("button", { name: "Assign manager", exact: true }).click();
  const managedService = page.getByRole("complementary", { name: "Grant filters", exact: true }).getByTitle("Managers of inventory");
  await expect(managedService).toBeVisible();
  await managedService.click();
  await expect(page).toHaveURL(/\/ui\/admin\/catalog\/services\/inventory\/managers$/);
  await expect(tableRow(page, "Inventory Owner")).toBeVisible();
  await page.goto(`${baseUrl}/ui/admin/policies`);

  // A CSRF retry refreshes capabilities and dismisses the old administrator dialog.
  // Direct service access remains for the newly selected manager role.
  await page.getByRole("button", { name: "Assign service policy manager", exact: true }).click();
  await pickCombobox(page, "Principal", "inventory", "Inventory Owner · ID: inventory-owner");
  isAdmin = false;
  csrfExpired = true;
  const refreshedSession = page.waitForResponse("**/v1/auth/session");
  await assignDialog.getByRole("button", { name: "Assign manager", exact: true }).click();
  await refreshedSession;
  await expect(assignDialog).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Assign service policy manager", exact: true })).toHaveCount(0);
  await expect(page.getByRole("navigation", { name: "Admin", exact: true }).getByRole("link")).toHaveText(["Policies"]);
  await expect(page.getByRole("combobox", { name: "Subject", exact: true })).toBeVisible();
});

test("local browser login supports administration, self-service credentials, tokens, and themes", async ({ page }, testInfo) => {
  test.setTimeout(300_000);
  const pageErrors = watchPageErrors(page);
  await stubCredentialVerification(page);
  const principalId = `alice-${testInfo.project.name}`;
  const serviceAccountId = `svc-reporter-${testInfo.project.name}`;
  const toast = (text: string) => page.getByRole("status").filter({ hasText: text });
  const adminNav = page.getByRole("navigation", { name: "Admin", exact: true });
  const selfNav = page.getByRole("navigation", { name: "My access", exact: true });
  const space = page.getByRole("navigation", { name: "Space", exact: true });
  const drawer = (name: string) => page.getByRole("complementary", { name, exact: true });
  let userPassword = "";

  await test.step("the first sign-in requires a new password and returns to the requested page", async () => {
    await page.goto(`${baseUrl}/ui/tokens`);
    await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
    await page.getByLabel("Principal").fill("admin");
    await page.getByLabel("Password").fill(initialAdminPassword);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();

    await expect(page).toHaveURL(/\/ui\/account$/);
    await expect(page.getByText("Change your password to continue", { exact: true })).toBeVisible();
    // The lock hides navigation and search until the password changes.
    await expect(space).toHaveCount(0);
    await expect(selfNav).toHaveCount(0);
    await page.evaluate(() => {
      history.pushState({}, "", "/ui/admin/principals");
      window.dispatchEvent(new PopStateEvent("popstate"));
    });
    await expect(page.getByText("Change your password to continue", { exact: true })).toBeVisible();
    await expect(page.getByRole("main", { name: "Principals" })).toHaveCount(0);
    await page.goBack();
    await expect(page).toHaveURL(/\/ui\/account$/);

    await page.getByLabel("Current password").fill(initialAdminPassword);
    await page.getByLabel("New password", { exact: true }).fill("admin-password-updated");
    await expect(page.getByText("New passwords do not match.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Update password" })).toBeDisabled();
    await page.getByLabel("Confirm new password").fill("admin-password-updated");
    await page.getByRole("button", { name: "Update password" }).click();
    await expect(page).toHaveURL(/\/ui\/tokens$/);
    await expect(page.getByRole("main", { name: "Tokens", exact: true })).toBeVisible();
    await expect(space.getByRole("link", { name: "My access", exact: true })).toHaveAttribute("aria-current", "page");
  });

  await test.step("admins create groups, a service account, and a user", async () => {
    await space.getByRole("link", { name: "Admin", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/policies$/);
    await adminNav.getByRole("link", { name: "Principals", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/principals$/);
    await expect(tableRow(page, "admin")).toBeVisible();
    // Principal columns sort, with the sort in the URL.
    const users = page.getByRole("table", { name: "Users", exact: true });
    await users.getByRole("button", { name: "Principal ID", exact: true }).click();
    await expect(page).toHaveURL(/sort=id(%3A|:)asc/);
    await expect(users.getByRole("columnheader", { name: "Principal ID" })).toHaveAttribute("aria-sort", "ascending");
    const ids = await users.getByRole("row").locator("td:nth-child(3)").allTextContents();
    expect(ids).toEqual([...ids].sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" })));
    await users.getByRole("button", { name: "Principal ID", exact: true }).click();
    await users.getByRole("button", { name: "Principal ID", exact: true }).click();
    await expect(page).not.toHaveURL(/sort=/);

    const sidebar = page.getByRole("complementary", { name: "Principal filters", exact: true });
    await sidebar.getByRole("button", { name: /^Groups/ }).click();
    await expect(page).toHaveURL(/kind=groups/);
    await page.getByRole("button", { name: "Create group", exact: true }).click();
    let dialog = page.getByRole("dialog", { name: "Create group", exact: true });
    await dialog.getByLabel("Group ID").fill("users");
    await dialog.getByLabel("Display name").fill("Users");
    await dialog.getByLabel("Description").fill("Policy users");
    await expect(dialog.getByRole("checkbox", { name: "Automatically add new Microsoft users", exact: true })).not.toBeChecked();
    await dialog.getByRole("checkbox", { name: "Automatically add new Microsoft users", exact: true }).check();
    await dialog.getByRole("button", { name: "Create group", exact: true }).click();
    await expect(toast("Group created")).toBeVisible();
    await expect(page).toHaveURL(/\/ui\/admin\/groups\/users$/);
    await expect(page.getByRole("heading", { name: "Users", exact: true })).toBeVisible();
    const enrollment = page.getByRole("checkbox", { name: "Automatically add new Microsoft users", exact: true });
    await expect(enrollment).toBeChecked();
    await page.reload();
    await expect(enrollment).toBeChecked();
    await expect(enrollment).toHaveAccessibleDescription(/does not authorize sign-in or change Microsoft admission requirements.*new accounts still require membership in an active mapped Microsoft group.*local and persists after Microsoft membership expires.*later sign-ins do not restore removed memberships/);

    await page.getByLabel("Display name").fill("User Access");
    await page.getByLabel("Description").fill("Principals with Jira access");
    await enrollment.uncheck();
    await page.getByRole("button", { name: "Save group", exact: true }).click();
    await expect(toast("Group saved")).toBeVisible();
    await expect(page.getByRole("heading", { name: "User Access", exact: true })).toBeVisible();
    expect(await browserManagementRequest(page, "/v1/admin/groups/users")).toMatchObject({ autoEnrollNewMicrosoftUsers: false });
    await page.getByRole("link", { name: "Groups", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/principals\?kind=groups$/);
    await expect(tableRow(page, "User Access")).toBeVisible();

    await page.getByRole("button", { name: "Create group", exact: true }).click();
    dialog = page.getByRole("dialog", { name: "Create group", exact: true });
    await dialog.getByLabel("Group ID").fill("operators");
    await dialog.getByLabel("Display name").fill("Operators");
    await dialog.getByRole("checkbox", { name: "Automatically add new Microsoft users", exact: true }).check();
    await dialog.getByRole("button", { name: "Create group", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/groups\/operators$/);
    await expect(enrollment).toBeChecked();
    await page.getByRole("button", { name: "Disable", exact: true }).click();
    await confirmDialog(page, "Disable group?", "Disable group");
    await expect(page.getByText("Enrollment is paused while this group is disabled.", { exact: false })).toBeVisible();
    await expect(enrollment).toBeChecked();
    expect(await browserManagementRequest(page, "/v1/admin/groups/operators")).toMatchObject({ status: "disabled", autoEnrollNewMicrosoftUsers: true });
    await page.getByRole("button", { name: "Enable", exact: true }).click();
    await expect(page.getByText("Enrollment is paused while this group is disabled.", { exact: false })).toHaveCount(0);
    await expect(enrollment).toBeChecked();
    await page.getByRole("link", { name: "Groups", exact: true }).click();
    await expect(tableRow(page, "Operators")).toBeVisible();
    // The list row opens a summary drawer; the drawer opens the full page.
    await tableRow(page, "Operators").getByRole("link", { name: "Operators", exact: true }).click();
    await expect(page).toHaveURL(/kind=groups&item=operators$/);
    await expect(drawer("Operators")).toBeVisible();
    await page.reload();
    await expect(drawer("Operators")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(drawer("Operators")).toHaveCount(0);
    await expect(page).not.toHaveURL(/item=/);

    await sidebar.getByRole("button", { name: /^Service accounts/ }).click();
    await page.getByRole("button", { name: "Create service account", exact: true }).click();
    dialog = page.getByRole("dialog", { name: "Create service account", exact: true });
    await expect(dialog).toContainText("Service accounts are noninteractive");
    await expect(dialog.getByText("Grant admin role")).toHaveCount(0);
    await dialog.getByLabel("Principal ID").fill(serviceAccountId);
    await dialog.getByLabel("Display name").fill("Reporting Service");
    await pickCombobox(page, GROUPS_FIELD, "users", /^users - User Access/);
    await page.keyboard.press("Escape");
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: "Create service account", exact: true }).click();
    await expect(toast("Service account created")).toBeVisible();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/principals/${serviceAccountId}$`));
    await expect(page.getByRole("heading", { name: "Reporting Service", exact: true })).toBeVisible();
    await expect(page.getByRole("main").getByText("Service account", { exact: true }).first()).toBeVisible();
    await expect(page.getByText(/Service accounts cannot use passwords, Microsoft sign-in/)).toBeVisible();
    await expect(page.getByRole("heading", { name: "Identity token", exact: true })).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "Identity access", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Reset local password" })).toHaveCount(0);
    const saTabs = page.getByRole("navigation", { name: "Service account sections", exact: true });
    await expect(saTabs.getByRole("link", { name: /^Groups/ })).toContainText("1");
    await saTabs.getByRole("link", { name: /^Tokens/ }).click();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/principals/${serviceAccountId}/tokens$`));
    await expect(page.getByRole("region", { name: /^Management tokens/ })).toHaveCount(0);
    await page.getByRole("main").getByRole("link", { name: "Principals", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/principals\?kind=service-accounts$/);
    await expect(tableRow(page, "Reporting Service")).toBeVisible();

    await sidebar.getByRole("button", { name: /^Users/ }).click();
    await page.getByRole("button", { name: "Create user", exact: true }).click();
    dialog = page.getByRole("dialog", { name: "Create user", exact: true });
    await expectDialogWithinViewport(dialog);
    const principalInput = dialog.getByLabel("Principal ID");
    await principalInput.pressSequentially(principalId);
    await expect(principalInput).toBeFocused();
    await dialog.getByLabel("Display name").fill("Alice Portal");
    await dialog.getByLabel("Email").fill(`${principalId}@example.com`);
    await expect(dialog.getByLabel("Enable local password sign-in", { exact: true })).not.toBeChecked();
    await dialog.getByLabel("Enable local password sign-in", { exact: true }).check();
    await expect(dialog.getByRole("button", { name: "Create user", exact: true })).toBeDisabled();
    await dialog.getByLabel("I authorize local password sign-in for this user independently of Microsoft sign-in.", { exact: true }).check();
    await expect(dialog.getByLabel("Temporary password")).toHaveCount(0);
    await pickCombobox(page, GROUPS_FIELD, "users", /^users - User Access/);
    await page.keyboard.press("Escape");
    await dialog.getByRole("button", { name: "Create user", exact: true }).click();
    await expect(toast("User created")).toBeVisible({ timeout: 30_000 });
    await expect(page).toHaveURL(new RegExp(`/ui/admin/principals/${principalId}$`));
    const created = page.getByRole("dialog", { name: "User created", exact: true });
    await expect(created).toBeVisible();
    // One-time secrets close only through their buttons.
    await page.keyboard.press("Escape");
    await expect(created).toBeVisible();
    const createdUserPassword = (await created.getByLabel("Temporary password").innerText()).trim();
    expect(createdUserPassword.length).toBeGreaterThanOrEqual(24);
    expect(createdUserPassword.toLocaleLowerCase()).not.toBe(principalId.toLocaleLowerCase());
    await created.getByRole("button", { name: "Done", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Alice Portal", exact: true })).toBeVisible();
    await expect(page.getByRole("navigation", { name: "User sections", exact: true }).getByRole("link", { name: "Overview", exact: true })).toHaveAttribute("aria-current", /page|true/);
  });

  await test.step("the user page manages identity, limits, profile, groups, and management tokens", async () => {
    // A new user's identity token exists, but revealing it takes an explicit admin action.
    await expect(page.getByRole("heading", { name: "Identity token", exact: true })).toBeVisible();
    const identityInput = page.getByLabel("Current identity token", { exact: true });
    await expect(identityInput).toHaveAttribute("type", "password");
    await page.getByRole("button", { name: "Reveal identity token", exact: true }).click();
    await expect(identityInput).toHaveValue(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    const generatedIdentity = await identityInput.inputValue();
    await page.getByRole("button", { name: "Hide identity token", exact: true }).click();
    await expect(identityInput).not.toHaveValue(generatedIdentity);

    // A revealed token, a typed replacement, or a reveal still in flight never
    // carries over to another principal's page (client-side navigation).
    const replacementInput = page.getByLabel("Existing or replacement identity token");
    await page.getByRole("button", { name: "Reveal identity token", exact: true }).click();
    await expect(identityInput).toHaveValue(generatedIdentity);
    await replacementInput.fill("cccccccc-dddd-4eee-8fff-000000000000");
    await openPrincipalFromPalette(page, /^admin/);
    await expect(page).toHaveURL(/\/ui\/admin\/principals\/admin$/);
    await expect(identityInput).toHaveAttribute("type", "password");
    await expect(identityInput).not.toHaveValue(generatedIdentity);
    await expect(replacementInput).toHaveValue("");
    const aliceReveal = new RegExp(`/v1/admin/principals/${principalId}/identity-token/reveal$`);
    let releaseReveal!: () => void;
    const revealHeld = new Promise<void>((resolve) => {
      releaseReveal = resolve;
    });
    await page.route(aliceReveal, async (route) => {
      await revealHeld;
      await route.continue();
    });
    await page.goBack();
    await expect(page.getByRole("heading", { name: "Alice Portal", exact: true })).toBeVisible();
    const revealed = page.waitForResponse(aliceReveal);
    await page.getByRole("button", { name: "Reveal identity token", exact: true }).click();
    await openPrincipalFromPalette(page, /^admin/);
    await expect(page).toHaveURL(/\/ui\/admin\/principals\/admin$/);
    releaseReveal();
    await revealed;
    await page.unroute(aliceReveal);
    await expect(identityInput).toHaveAttribute("type", "password");
    await expect(identityInput).not.toHaveValue(generatedIdentity);
    await page.goBack();
    await expect(page.getByRole("heading", { name: "Alice Portal", exact: true })).toBeVisible();
    await expect(identityInput).toHaveAttribute("type", "password");

    const identityAccess = page.getByRole("region", { name: "Identity access", exact: true });
    const accessPaths = identityAccess.getByRole("table", { name: "Access paths", exact: true });
    // The identity token is the first access path. Its settings change without touching the secret.
    const tokenPath = accessPaths.getByRole("row").nth(1);
    await expect(tokenPath).toHaveAccessibleName(/^Identity token/);
    await expect(tokenPath.getByRole("button")).toHaveCount(0);
    const tokenEnabled = tokenPath.getByRole("switch", { name: "Identity token enabled", exact: true });
    const tokenReadOnly = tokenPath.getByRole("switch", { name: "Identity token read-only", exact: true });
    await expect(tokenEnabled).toBeChecked();
    await expect(tokenReadOnly).not.toBeChecked();
    await tokenReadOnly.click();
    await expect(tokenReadOnly).toBeChecked();
    await tokenEnabled.click();
    await expect(tokenEnabled).not.toBeChecked();
    const tokenMetadataPath = `/v1/admin/principals/${principalId}/identity-token`;
    expect(await browserManagementRequest(page, tokenMetadataPath)).toMatchObject({ configured: true, enabled: false, readOnly: true });
    await expect(page.getByRole("region", { name: "Identity token", exact: true })).toContainText("This identity token is disabled in Access paths.");
    // A disabled token keeps its secret.
    await page.getByRole("button", { name: "Reveal identity token", exact: true }).click();
    await expect(identityInput).toHaveValue(generatedIdentity);
    await page.getByRole("button", { name: "Hide identity token", exact: true }).click();
    await tokenEnabled.click();
    await expect(tokenEnabled).toBeChecked();

    await identityAccess.getByLabel("Identity namespace", { exact: true }).selectOption("managed_linux");
    await identityAccess.getByLabel("Exact username", { exact: true }).fill("Alice+Portal");
    await identityAccess.getByRole("checkbox", { name: "Read-only", exact: true }).check();
    await identityAccess.getByRole("button", { name: "Add username binding", exact: true }).click();
    const bindingRow = accessPaths.getByRole("row", { name: /^managed_linux\/Alice\+Portal/ });
    const bindingEnabled = bindingRow.getByRole("switch", { name: "Binding managed_linux/Alice+Portal enabled", exact: true });
    const bindingReadOnly = bindingRow.getByRole("switch", { name: "Binding managed_linux/Alice+Portal read-only", exact: true });
    await expect(bindingEnabled).toBeChecked();
    await expect(bindingReadOnly).toBeChecked();
    await expect(identityAccess.getByRole("checkbox", { name: "Read-only", exact: true })).not.toBeChecked();
    await bindingEnabled.click();
    await expect(bindingEnabled).not.toBeChecked();
    await bindingEnabled.click();
    await expect(bindingEnabled).toBeChecked();
    await bindingReadOnly.click();
    await expect(bindingReadOnly).not.toBeChecked();
    const bindingsPath = `/v1/admin/principals/${principalId}/identity-bindings`;
    expect((await browserManagementRequest<{ bindings: unknown[] }>(page, bindingsPath)).bindings).toEqual([
      expect.objectContaining({ namespace: "managed_linux", username: "Alice+Portal", enabled: true, readOnly: false, version: 4 })
    ]);
    await page.getByRole("button", { name: "Pause identity access", exact: true }).click();
    await expect(page.getByRole("button", { name: "Resume identity access", exact: true })).toBeVisible();
    const importedIdentity = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    await page.getByLabel("Existing or replacement identity token").fill(importedIdentity);
    await page.getByRole("button", { name: "Set token", exact: true }).click();
    await confirmDialog(page, "Save this identity token?", "Save token");
    await page.reload();
    await expect(page.getByRole("button", { name: "Resume identity access", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Reveal identity token", exact: true }).click();
    await expect(identityInput).toHaveValue(importedIdentity);
    await page.getByRole("button", { name: "Remove token", exact: true }).click();
    await confirmDialog(page, "Remove identity token?", "Remove token");
    await page.reload();
    await expect(identityInput).toHaveValue("");
    await expect(page.getByRole("button", { name: "Reveal identity token", exact: true })).toBeDisabled();
    await expect(tokenPath).toContainText("Not configured");
    // Secret changes keep the token's settings.
    await expect(tokenReadOnly).toBeChecked();
    await expect(tokenEnabled).toBeChecked();
    await expect(bindingEnabled).toBeChecked();
    await expect(page.getByRole("button", { name: "Resume identity access", exact: true })).toBeVisible();
    // The gate remains usable with no fingerprint inventory and does not remove username bindings.
    await page.getByRole("button", { name: "Resume identity access", exact: true }).click();
    await expect(page.getByRole("button", { name: "Pause identity access", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Pause identity access", exact: true }).click();
    await page.getByRole("button", { name: "Generate token", exact: true }).click();
    await confirmDialog(page, "Generate a new identity token?", "Generate token");
    await page.reload();
    await expect(page.getByRole("button", { name: "Resume identity access", exact: true })).toBeVisible();
    await expect(bindingEnabled).toBeChecked();
    expect(await browserManagementRequest(page, tokenMetadataPath)).toMatchObject({ configured: true, enabled: true, readOnly: true });
    await tokenReadOnly.click();
    await expect(tokenReadOnly).not.toBeChecked();
    await page.getByRole("button", { name: "Resume identity access", exact: true }).click();
    await expect(page.getByRole("button", { name: "Pause identity access", exact: true })).toBeVisible();
    await bindingRow.getByRole("button", { name: "Delete binding managed_linux/Alice+Portal", exact: true }).click();
    await confirmDialog(page, "Delete username binding?", "Delete binding");
    await expect(identityAccess.getByText("No username bindings.", { exact: true })).toBeVisible();
    await expect(accessPaths.getByRole("row")).toHaveCount(2);

    // Managed-store service limit overrides start at the configured default and can be set and reset.
    const tabs = page.getByRole("navigation", { name: "User sections", exact: true });
    await tabs.getByRole("link", { name: "Limits", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/principals/${principalId}/limits$`));
    const jiraLimitRow = page.locator("table.service-limits").getByRole("row").filter({ has: page.getByRole("button", { name: "Edit jira limit", exact: true }) });
    await expect(jiraLimitRow).toContainText("1000 requests per 1m");
    await expect(jiraLimitRow.getByText("Default", { exact: true })).toBeVisible();
    await expect(jiraLimitRow.getByRole("button", { name: "Reset jira limit to default", exact: true })).toBeDisabled();
    await jiraLimitRow.getByRole("button", { name: "Edit jira limit", exact: true }).click();
    const limitEditor = page.getByRole("dialog", { name: "Edit jira limit", exact: true });
    await expect(limitEditor.getByLabel("Requests", { exact: true })).toHaveValue("1000");
    await expect(limitEditor.getByLabel("Window", { exact: true })).toHaveValue("1m");
    await limitEditor.getByLabel("Requests", { exact: true }).fill("0");
    await expect(limitEditor.getByText("Requests must be a whole number from 1 to 1,000,000.", { exact: true })).toBeVisible();
    await expect(limitEditor.getByRole("button", { name: "Save override", exact: true })).toBeDisabled();
    await limitEditor.getByLabel("Requests", { exact: true }).fill("10");
    await limitEditor.getByLabel("Window", { exact: true }).fill("25h");
    await expect(limitEditor.getByText("Window must be from 1s to 1d.", { exact: true })).toBeVisible();
    await expect(limitEditor.getByRole("button", { name: "Save override", exact: true })).toBeDisabled();
    await limitEditor.getByLabel("Window", { exact: true }).fill("90s");
    await limitEditor.getByRole("button", { name: "Save override", exact: true }).click();
    await expect(toast("Override saved: jira is limited to 10 requests per 90s.")).toBeVisible();
    await expect(limitEditor).toHaveCount(0);
    await expect(jiraLimitRow).toContainText("10 requests per 90s");
    await expect(jiraLimitRow.getByText("Override", { exact: true })).toBeVisible();
    await jiraLimitRow.getByRole("button", { name: "Reset jira limit to default", exact: true }).click();
    await confirmDialog(page, "Reset to the default limit?", "Reset limit");
    await expect(toast("Override removed: jira uses the default limit of 1000 requests per 1m.")).toBeVisible();
    await expect(jiraLimitRow).toContainText("1000 requests per 1m");
    await expect(jiraLimitRow.getByText("Default", { exact: true })).toBeVisible();

    await tabs.getByRole("link", { name: "Overview", exact: true }).click();
    await page.getByLabel("Display name").fill("Alice Updated");
    await page.getByLabel("Email").fill(`${principalId}.updated@example.com`);
    await page.getByRole("button", { name: "Save profile", exact: true }).click();
    await expect(toast("Profile saved")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Alice Updated", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Save profile", exact: true })).toBeDisabled();

    await tabs.getByRole("link", { name: /^Groups/ }).click();
    await expect(tableRow(page, "User Access")).toBeVisible();
    await pickCombobox(page, "Group", "operators", /^operators - Operators/);
    await page.getByRole("button", { name: "Add group", exact: true }).click();
    await expect(toast("Group added")).toBeVisible();
    const removeOperators = page.getByRole("button", { name: "Remove operators", exact: true });
    await removeOperators.click();
    await confirmDialog(page, "Remove group?", "Remove group");
    await expect(toast("Group removed")).toBeVisible();
    await expect(removeOperators).toHaveCount(0);

    await tabs.getByRole("link", { name: "Tokens", exact: true }).click();
    const management = page.getByRole("region", { name: /^Management tokens/ });
    await expect(management.getByRole("button", { name: "Issue setup token", exact: true })).toBeEnabled();
    await expect(management.getByRole("button", { name: "Issue admin token", exact: true })).toBeDisabled();
    await management.getByRole("button", { name: "Issue setup token", exact: true }).click();
    const setupDialog = page.getByRole("dialog", { name: "Issue setup token", exact: true });
    const setupLifetime = setupDialog.getByLabel("Lifetime");
    await expect(setupLifetime).toHaveValue("41m");
    await expect.poll(() => setupLifetime.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value))).toEqual(["41m"]);
    await expect(setupDialog.getByText("user_manage tokens always expire.", { exact: false })).toBeVisible();
    await setupDialog.getByRole("textbox", { name: "Name", exact: true }).fill(`setup-token-${testInfo.project.name}`);
    await expect(setupDialog.getByLabel("jira")).toHaveCount(0);
    await setupDialog.getByRole("button", { name: "Issue setup token", exact: true }).click();
    const setupReveal = page.getByRole("dialog", { name: "Token created", exact: true });
    await expect(setupReveal.getByText(principalId, { exact: true })).toBeVisible();
    await expect(setupReveal.getByText("user_manage", { exact: true })).toBeVisible();
    await expect(setupReveal.getByText("Token ID", { exact: true })).toBeVisible();
    await expect(setupReveal.getByText("Expires", { exact: true })).toBeVisible();
    expect(await setupReveal.innerText()).toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/);
    const setupRawToken = (await setupReveal.getByLabel("Token", { exact: true }).innerText()).trim();
    expect(setupRawToken).toMatch(/^aab_um_/);
    await expect(setupReveal.getByRole("region", { name: "Connect an MCP client", exact: true })).toHaveCount(0);
    expect(page.url()).not.toContain(setupRawToken.slice(0, 12));
    expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain(setupRawToken);
    expect(await page.evaluate(() => JSON.stringify(sessionStorage))).not.toContain(setupRawToken);
    await setupReveal.getByRole("button", { name: "Done", exact: true }).click();
    await expect(page.getByText(setupRawToken, { exact: true })).toHaveCount(0);
    const setupRow = tableRow(management, `setup-token-${testInfo.project.name}`);
    await setupRow.getByRole("link").click();
    const setupDetails = drawer(`Token setup-token-${testInfo.project.name}`);
    await expect(setupDetails.getByText("user_manage").first()).toBeVisible();
    await expect(setupDetails.getByText("All configured", { exact: true })).toHaveCount(0);
    await expect(page.getByText(setupRawToken, { exact: true })).toHaveCount(0);
    await setupDetails.getByRole("button", { name: "Close", exact: true }).click();
    await expect(setupDetails).toHaveCount(0);
    await setupRow.getByRole("button", { name: `Revoke setup-token-${testInfo.project.name}`, exact: true }).click();
    await confirmDialog(page, "Revoke token?", "Revoke token");
    await expect(toast("Token revoked")).toBeVisible();
    await expect(setupRow.getByText("Revoked", { exact: true })).toBeVisible();

    const moreActions = page.getByRole("main").getByRole("button", { name: "More actions", exact: true });
    await openMenu(page, moreActions, "Account access");
    await page.getByLabel("Role", { exact: true }).selectOption("admin");
    await page.getByRole("button", { name: "Save access", exact: true }).click();
    await confirmDialog(page, "Update account access?", "Update access");
    await expect(toast("Account access updated")).toBeVisible();
    await page.goto(`${baseUrl}/ui/admin/principals/${principalId}/tokens`);
    await expect(management.getByRole("button", { name: "Issue admin token", exact: true })).toBeEnabled();
    await management.getByRole("button", { name: "Issue admin token", exact: true }).click();
    const adminDialog = page.getByRole("dialog", { name: "Issue admin token", exact: true });
    const adminLifetime = adminDialog.getByLabel("Lifetime");
    await expect(adminLifetime).toHaveValue("43m");
    await expect.poll(() => adminLifetime.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value))).toEqual(["43m"]);
    await expect(adminDialog.getByText("admin tokens always expire.", { exact: false })).toBeVisible();
    await adminDialog.getByRole("textbox", { name: "Name", exact: true }).fill(`admin-token-${testInfo.project.name}`);
    await adminDialog.getByRole("button", { name: "Issue admin token", exact: true }).click();
    const adminReveal = page.getByRole("dialog", { name: "Token created", exact: true });
    await expect(adminReveal.getByText(principalId, { exact: true })).toBeVisible();
    await expect(adminReveal.getByText("admin", { exact: true })).toBeVisible();
    const adminRawToken = (await adminReveal.getByLabel("Token", { exact: true }).innerText()).trim();
    expect(adminRawToken).toMatch(/^aab_ad_/);
    expect(page.url()).not.toContain(adminRawToken.slice(0, 12));
    expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain(adminRawToken);
    expect(await page.evaluate(() => JSON.stringify(sessionStorage))).not.toContain(adminRawToken);
    await adminReveal.getByRole("button", { name: "Done", exact: true }).click();
    await expect(page.getByText(adminRawToken, { exact: true })).toHaveCount(0);
    const adminRow = tableRow(management, `admin-token-${testInfo.project.name}`);
    await adminRow.getByRole("button", { name: `Revoke admin-token-${testInfo.project.name}`, exact: true }).click();
    await confirmDialog(page, "Revoke token?", "Revoke token");
    await expect(adminRow.getByText("Revoked", { exact: true })).toBeVisible();
    await openMenu(page, moreActions, "Account access");
    await page.getByLabel("Role", { exact: true }).selectOption("user");
    await page.getByRole("button", { name: "Save access", exact: true }).click();
    await confirmDialog(page, "Update account access?", "Update access");
    await expect(toast("Account access updated")).toBeVisible();
    await page.goto(`${baseUrl}/ui/admin/principals/${principalId}/tokens`);
    await expect(management.getByRole("button", { name: "Issue admin token", exact: true })).toBeDisabled();

    await page.getByRole("button", { name: "Disable user", exact: true }).click();
    await confirmDialog(page, "Disable user?", "Disable user");
    await expect(toast("Principal disabled")).toBeVisible();
    await expect(page.getByRole("button", { name: "Enable user", exact: true })).toBeVisible();
    await expect(management.getByRole("button", { name: "Issue setup token", exact: true })).toBeDisabled();
    await expect(setupRow.getByRole("link")).toBeVisible();
    await page.getByRole("button", { name: "Enable user", exact: true }).click();
    await expect(toast("Principal enabled")).toBeVisible();

    await page.getByRole("link", { name: "Overview", exact: true }).click();
    await page.getByRole("button", { name: "Reset local password", exact: true }).click();
    await confirmDialog(page, "Reset local password?", "Reset local password");
    const reset = page.getByRole("dialog", { name: "Local password reset", exact: true });
    userPassword = (await reset.getByLabel("Temporary password").innerText()).trim();
    expect(userPassword.length).toBeGreaterThanOrEqual(24);
    expect(userPassword.toLocaleLowerCase()).not.toBe(principalId.toLocaleLowerCase());
    await reset.getByRole("button", { name: "Done", exact: true }).click();
  });

  await test.step("System shows the runtime and reloads the configuration", async () => {
    await page.getByRole("link", { name: "System", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/system$/);
    await expect(page.getByRole("heading", { name: "System", exact: true })).toBeVisible();
    await expect(page.getByRole("main").getByText("managed", { exact: true })).toHaveCount(2);
    const refreshedSession = page.waitForResponse((response) => response.request().method() === "GET" && new URL(response.url()).pathname === "/v1/auth/session");
    await page.getByRole("button", { name: "Reload config", exact: true }).click();
    await confirmDialog(page, "Reload broker configuration?", "Reload config");
    await refreshedSession;
    await expect(toast("Config reloaded")).toBeVisible();
  });

  await test.step("resources for grants", async () => {
    // The Catalog pages have their own test; these entries feed the grants below.
    const resourcePath = "/v1/admin/policy/resources";
    await browserManagementRequest(page, resourcePath, { method: "POST", body: { id: "portal-project", displayName: "Portal project", resourceType: "jira_project", selector: { kind: "exact", value: "PORTAL" }, allowedExecutionContexts: ["default", "internal", "external"], enabled: true } });
    await browserManagementRequest(page, resourcePath, { method: "POST", body: { id: "all-jira", resourceType: "jira_project", selector: { kind: "all" }, allowedExecutionContexts: ["default", "internal", "external"], enabled: true } });
    await browserManagementRequest(page, resourcePath, { method: "POST", body: { id: "secret-project", resourceType: "jira_project", selector: { kind: "exact", value: "SECRET" }, allowedExecutionContexts: ["internal"], enabled: false } });
    await browserManagementRequest(page, "/v1/admin/policy/resource-groups", { method: "POST", body: { id: "portal-resources", name: "Portal resources", includedResourceIds: ["all-jira"], excludedResourceIds: ["secret-project"] } });
    await exerciseGrantResourcePicker(page);
  });

  let grantRef = "";
  await test.step("policies filter, create, edit, disable, duplicate, and delete grants", async () => {
    await page.goto(`${baseUrl}/ui/admin/principals`);
    await adminNav.getByRole("link", { name: "Policies", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/policies$/);
    await expect(page.getByRole("main", { name: "Policies", exact: true })).toBeVisible();
    await expect.poll(() => comboboxOptions(page, "Action")).toEqual(expect.arrayContaining(["issue.view", "page.view", "repo.fetch", "repo.push"]));
    await page.getByRole("checkbox", { name: /^Jira/ }).check();
    expect(await comboboxOptions(page, "Action")).toEqual(expect.arrayContaining(["issue.view"]));
    expect(await comboboxOptions(page, "Action")).not.toContain("page.view");
    await pickCombobox(page, "Action", "issue.view");
    await page.getByRole("checkbox", { name: /^Jira/ }).uncheck();
    await page.getByRole("checkbox", { name: /^Confluence/ }).check();
    expect(await comboboxOptions(page, "Action")).toEqual(expect.arrayContaining(["issue.view (outside selected services)", "page.view"]));
    await expect(page.getByText("issue.view is outside the selected services.", { exact: true })).toBeVisible();
    await pickCombobox(page, "Action", "page.view");
    await expect(page.getByText("issue.view is outside the selected services.", { exact: true })).toHaveCount(0);
    await expect(page).toHaveURL(/service=confluence&action=page\.view$/);
    await page.getByRole("button", { name: "Clear service filter", exact: true }).click();
    await page.getByRole("button", { name: "Clear selection" }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/policies$/);

    const editor = grantEditor(page);
    await page.getByRole("main").getByRole("link", { name: "Create grant", exact: true }).first().click();
    await expect(page).toHaveURL(/\/ui\/admin\/policies\/new$/);
    const grantId = page.getByLabel("Grant ID");
    await grantId.pressSequentially("portal-grant");
    await expect(grantId).toBeFocused();
    await addGrantSubject(page, "Group", "users", "User Access · ID: users");
    await editor.service.selectOption("gitlab_git");
    await page.getByRole("checkbox", { name: "repo.fetch", exact: true }).check();
    await expect(editor.resourceGroups).toBeVisible();
    // Leaving with unsaved changes asks first.
    await editor.cancel.click();
    await confirmDialog(page, "Discard changes?", "Discard changes");
    await expect(page).toHaveURL(/\/ui\/admin\/policies$/);
    // Browser Back asks too; discarding completes the replayed history navigation.
    await page.getByRole("main").getByRole("link", { name: "Create grant", exact: true }).first().click();
    await grantId.pressSequentially("discarded-by-back");
    await page.goBack();
    await confirmDialog(page, "Discard changes?", "Discard changes");
    await expect(page).toHaveURL(/\/ui\/admin\/policies$/);
    await expect(page.getByRole("alertdialog", { name: "Discard changes?", exact: true })).toHaveCount(0);

    await page.getByRole("main").getByRole("link", { name: "Create grant", exact: true }).first().click();
    await expect(editor.create).toBeDisabled();
    await expect(editor.contexts.getByRole("checkbox")).toHaveCount(3);
    expect(await editor.contexts.getByRole("checkbox").evaluateAll((boxes) => boxes.map((box) => box.getAttribute("aria-label")))).toEqual(["default", "internal", "external"]);
    await expect(editor.contexts.getByLabel("default", { exact: true })).toBeChecked();
    await expect(editor.contexts.getByLabel("internal", { exact: true })).not.toBeChecked();
    await expect(editor.contexts.getByLabel("external", { exact: true })).not.toBeChecked();
    await editor.contexts.getByLabel("internal", { exact: true }).check();
    await addGrantSubject(page, "Group", "users", "User Access · ID: users");
    await expect(editor.subjects.getByText("User Access · ID: group:users", { exact: true })).toBeVisible();
    await page.locator("#grant-subjects").getByRole("combobox", { name: "Group", exact: true }).click();
    await expect(page.getByRole("option", { name: "User Access · ID: users", exact: true })).toHaveAttribute("aria-disabled", "true");
    await page.keyboard.press("Escape");
    await editor.subjects.getByRole("button", { name: "Remove group:users", exact: true }).click();
    await expect(editor.subjects.getByText("No subjects yet.")).toBeVisible();
    await expect(editor.create).toBeDisabled();
    await addGrantSubject(page, "Group", "users", "User Access · ID: users");
    await addGrantSubject(page, "User", principalId, `Alice Updated · ID: ${principalId}`);
    await expect(editor.subjects.getByText(`Alice Updated · ID: user:${principalId}`, { exact: true })).toBeVisible();
    await editor.service.selectOption("jira");
    await page.getByRole("checkbox", { name: "issue.view", exact: true }).check();
    await editor.resources.getByRole("checkbox", { name: /^Portal project/ }).check();
    await editor.resourceGroups.getByRole("checkbox", { name: "Portal resources", exact: true }).check();
    await expect(editor.preview.getByText(/All Jira projects.*except SECRET/).first()).toBeVisible();
    await page.getByLabel("Description").fill("Portal policy source");
    await expect(editor.preview.locator("pre")).toContainText('"description": "Portal policy source"');
    await editor.create.click();
    await expect(toast("Policy grant created")).toBeVisible();
    await expect(page).toHaveURL(/\/ui\/admin\/policies\?grant=/);
    grantRef = new URL(page.url()).searchParams.get("grant")!;
    let grantDrawer = drawer(`Grant ${grantRef}`);
    await expect(grantDrawer.getByRole("heading", { name: "Portal policy source" })).toBeVisible();
    // Scope lists the contexts; the effective-access table merges them when their resources match.
    await expect(grantDrawer.getByRole("region", { name: "Scope" }).getByText("default, internal", { exact: true })).toBeVisible();
    await expect(grantDrawer.getByRole("table").getByRole("cell").filter({ hasText: /^default, internal$/ })).toBeVisible();
    await expect(grantDrawer.getByText(/Portal project.*Portal resources/)).toBeVisible();
    const grantRow = tableRow(page, grantRef);
    await expect(await columnCell(grantRow, "Subjects")).toHaveText("User Access, Alice Updated");
    await expect(grantRow.getByRole("link", { name: `Edit ${grantRef}`, exact: true })).toBeAttached();

    await grantDrawer.getByRole("link", { name: "Edit", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/policies/${grantRef}/edit$`));
    await expect(editor.save).toBeDisabled();
    await expect(editor.contexts.getByLabel("internal", { exact: true })).toBeChecked();
    await editor.contexts.getByLabel("external", { exact: true }).check();
    await page.getByLabel("Priority").fill("10");
    await editor.save.click();
    await expect(toast("Policy grant updated")).toBeVisible();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/policies\\?grant=${grantRef}$`));
    grantDrawer = drawer(`Grant ${grantRef}`);
    await expect(grantDrawer.getByRole("region", { name: "Scope" }).getByText("default, internal, external", { exact: true })).toBeVisible();
    await expect(grantRow.getByText("P10", { exact: true })).toBeVisible();
    await openMenu(page, grantRow.getByRole("button", { name: `More actions for ${grantRef}`, exact: true }), "Disable");
    await expect(toast("Policy grant disabled")).toBeVisible();
    await expect(grantRow.getByText("Disabled", { exact: true })).toBeVisible();
    await expect(grantDrawer.getByText("No access currently: this grant is disabled.")).toBeVisible();
    await openMenu(page, grantRow.getByRole("button", { name: `More actions for ${grantRef}`, exact: true }), "Enable");
    await expect(toast("Policy grant enabled")).toBeVisible();

    await openMenu(page, grantRow.getByRole("button", { name: `More actions for ${grantRef}`, exact: true }), "Duplicate");
    await expect(page).toHaveURL(new RegExp(`/ui/admin/policies/new\\?from=${grantRef}$`));
    await expect(page.getByRole("heading", { name: "Duplicate grant", exact: true })).toBeVisible();
    await page.getByLabel("Description").fill("Portal policy copy");
    await editor.create.click();
    await expect(toast("Policy grant created")).toBeVisible();
    const copyRef = new URL(page.url()).searchParams.get("grant")!;
    expect(copyRef).not.toBe(grantRef);
    await page.getByRole("searchbox", { name: "Filter grants by subject, action, scope…" }).fill("Portal policy copy");
    const copyRow = tableRow(page, copyRef);
    await expect(copyRow).toBeVisible();
    await expect(tableRow(page, grantRef)).toHaveCount(0);
    // Sorting is kept in the URL and cycles ascending, descending, unsorted.
    await page.getByRole("searchbox", { name: "Filter grants by subject, action, scope…" }).fill("");
    // The search field publishes after its debounce; wait for both created
    // grants before taking the ascending snapshot used by the reverse check.
    await expect.poll(() => new URL(page.url()).searchParams.get("q")).toBeNull();
    await expect(tableRow(page, grantRef)).toBeVisible();
    await expect(copyRow).toBeVisible();
    const grantsTable = page.getByRole("table", { name: "Grants", exact: true });
    const sortByGrant = grantsTable.getByRole("button", { name: "Grant", exact: true });
    await sortByGrant.click();
    await expect(page).toHaveURL(/sort=grant%3Aasc|sort=grant:asc/);
    await expect(grantsTable.getByRole("columnheader", { name: "Grant" })).toHaveAttribute("aria-sort", "ascending");
    const ascending = await rowHeaders(grantsTable);
    expect(ascending).toEqual([...ascending].sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" })));
    await sortByGrant.click();
    await expect(grantsTable.getByRole("columnheader", { name: "Grant" })).toHaveAttribute("aria-sort", "descending");
    expect(await rowHeaders(grantsTable)).toEqual([...ascending].reverse());
    await sortByGrant.click();
    await expect(page).not.toHaveURL(/sort=/);
    // Grouping by service adds a group header row per service.
    await page.getByRole("button", { name: "Group", exact: true }).click();
    await page.getByRole("menuitemradio", { name: "Service", exact: true }).click();
    await expect(page).toHaveURL(/group=service/);
    await expect(grantsTable.getByRole("rowheader", { name: /^Jira/ })).toBeVisible();
    await expect(grantsTable.getByRole("columnheader", { name: "Service" })).toHaveCount(0);
    await page.getByRole("button", { name: "Group", exact: true }).click();
    await expect(page.getByRole("menuitemradio", { name: "Service", exact: true })).toHaveAttribute("aria-checked", "true");
    await page.getByRole("menuitemradio", { name: "None", exact: true }).click();
    await expect(page).not.toHaveURL(/group=/);
    await page.getByRole("searchbox", { name: "Filter grants by subject, action, scope…" }).fill("Portal policy copy");
    await openMenu(page, copyRow.getByRole("button", { name: `More actions for ${copyRef}`, exact: true }), "Delete");
    await confirmDialog(page, "Delete policy grant?", "Delete grant");
    await expect(toast("Policy grant deleted")).toBeVisible();
    await expect(copyRow).toHaveCount(0);
    await page.getByRole("group", { name: "Grant status", exact: true }).getByRole("button", { name: /^Deleted/ }).click();
    await expect(copyRow).toBeVisible();
    await page.getByRole("group", { name: "Grant status", exact: true }).getByRole("button", { name: /^Current/ }).click();
  });

  await test.step("group pages show members and grants, and edit grants in place", async () => {
    await page.goto(`${baseUrl}/ui/admin/groups/users/members`);
    await expect(page.getByRole("heading", { name: "User Access", exact: true })).toBeVisible();
    await expect(tableRow(page, "Alice Updated").getByRole("button", { name: `Remove ${principalId}`, exact: true })).toBeAttached();
    const tabs = page.getByRole("navigation", { name: "Group sections", exact: true });
    await tabs.getByRole("link", { name: /^Grants/ }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/groups\/users\/grants$/);
    const reference = tableRow(page, grantRef);
    await expect(reference).toContainText("issue.view");
    await expect(reference).toContainText(/Portal project.*/);
    await reference.getByRole("link", { name: `Edit ${grantRef}`, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/policies/${grantRef}/edit\\?returnTo=`));
    const editor = grantEditor(page);
    await expect(editor.subjects.getByText("User Access · ID: group:users", { exact: true })).toBeVisible();
    await expect(editor.subjects.getByText(`Alice Updated · ID: user:${principalId}`, { exact: true })).toBeVisible();
    await page.getByLabel("Description").fill("Group reference edit preserves subjects");
    await editor.save.click();
    await expect(toast("Policy grant updated")).toBeVisible();
    await expect(page).toHaveURL(/\/ui\/admin\/groups\/users\/grants$/);
    await expect(tableRow(page, grantRef)).toBeVisible();
    // Opening a reference shows the grant drawer on the group page; Escape returns focus to the row.
    await tableRow(page, grantRef).getByRole("link", { name: grantRef, exact: true }).click();
    await expect(drawer(`Grant ${grantRef}`).getByRole("heading", { name: "Group reference edit preserves subjects" })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(tableRow(page, grantRef).getByRole("link", { name: grantRef, exact: true })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(drawer(`Grant ${grantRef}`)).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(tableRow(page, grantRef).getByRole("link", { name: grantRef, exact: true })).toBeFocused();
    await page.getByRole("main").getByRole("link", { name: "Create grant", exact: true }).first().click();
    await expect(page).toHaveURL(/\/ui\/admin\/policies\/new\?subject=group%3Ausers/);
    await expect(editor.subjects.getByText("User Access · ID: group:users", { exact: true })).toBeVisible();
    await editor.cancel.click();
    await expect(page).toHaveURL(/\/ui\/admin\/groups\/users\/grants$/);

    await page.goto(`${baseUrl}/ui/admin/groups/operators/members`);
    await pickCombobox(page, "Principal to add", principalId, new RegExp(`^Alice Updated · ID: ${principalId}`));
    await page.getByRole("button", { name: "Add member", exact: true }).click();
    await expect(toast("Member added")).toBeVisible();
    const member = tableRow(page, "Alice Updated");
    await expect(member).toBeVisible();
    await member.getByRole("button", { name: `Remove ${principalId}`, exact: true }).click();
    await confirmDialog(page, "Remove member?", "Remove member");
    await expect(toast("Member removed")).toBeVisible();
    await expect(member).toHaveCount(0);

    await page.goto(`${baseUrl}/ui/admin/principals/${principalId}`);
    await openMenu(page, page.getByRole("main").getByRole("button", { name: "More actions", exact: true }), "Create grant for this principal");
    await expect(editor.subjects.getByText(`Alice Updated · ID: user:${principalId}`, { exact: true })).toBeVisible();
    await editor.cancel.click();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/principals/${principalId}/grants$`));
    await expect(page.getByText("No grants name this user directly.")).toHaveCount(0);
    // Each grant is one row, whichever sections name it.
    const references = page.getByRole("table", { name: "Grants", exact: true });
    await expect(tableRow(references, grantRef)).toHaveCount(1);
    // The keyboard cursor opens a reference's grant drawer; Escape returns focus to its row.
    const firstReference = (await references.getByRole("rowheader").getByRole("link").first().textContent())!.trim();
    await references.click({ position: { x: 1, y: 1 } });
    await page.keyboard.press("j");
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(new RegExp(`[?&]grant=${firstReference}`));
    await expect(drawer(`Grant ${firstReference}`)).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page).not.toHaveURL(/grant=/);
    await expect(tableRow(references, firstReference).getByRole("link", { name: firstReference, exact: true })).toBeFocused();
  });

  await test.step("admins issue and manage agent tokens for a user", async () => {
    const tabs = page.getByRole("navigation", { name: "User sections", exact: true });
    await tabs.getByRole("link", { name: "Tokens", exact: true }).click();
    await page.getByRole("button", { name: "Issue token", exact: true }).first().click();
    const dialog = page.getByRole("main", { name: "Issue agent token", exact: true });
    await expect(dialog).toContainText("For ");
    await expect(dialog).toContainText(principalId);
    const lifetime = dialog.getByLabel("Lifetime");
    await expect(lifetime).toHaveValue("37m");
    await expect.poll(() => lifetime.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value))).toEqual(["37m", "never"]);
    await expect(dialog).not.toContainText("longest finite lifetime");
    await lifetime.selectOption("never");
    await expect(dialog.getByText(/This token stays active until it is revoked\./)).toBeVisible();
    await dialog.getByRole("textbox", { name: "Name", exact: true }).fill(`managed-token-${testInfo.project.name}`);
    const contexts = dialog.getByRole("group", { name: "Execution contexts" });
    expect(await contexts.getByRole("checkbox").evaluateAll((boxes) => boxes.map((box) => box.getAttribute("aria-label")))).toEqual(["default", "internal", "external"]);
    for (const context of ["default", "internal", "external"]) await expect(contexts.getByLabel(context, { exact: true })).toBeChecked();
    await expect(dialog.getByLabel("jira")).toHaveCount(0);
    await contexts.getByLabel("external", { exact: true }).uncheck();
    await dialog.getByRole("group", { name: "Access", exact: true }).getByRole("button", { name: "Restrict to selected", exact: true }).click();
    const issue = dialog.getByRole("button", { name: "Issue token", exact: true });
    await expect(issue).toBeDisabled();
    await dialog.getByRole("checkbox", { name: "jira", exact: true }).check();
    await expect(issue).toBeDisabled();
    await dialog.getByRole("searchbox", { name: "Filter jira actions", exact: true }).fill("issue");
    await dialog.getByRole("checkbox", { name: "issue.view", exact: true }).check();
    await expect(issue).toBeEnabled();
    await expect(dialog).toContainText("Restrictions cannot be edited after issuance.");
    // Leaving an owner-scoped draft requires an explicit discard.
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    const discard = page.getByRole("alertdialog", { name: "Discard changes?", exact: true });
    await expect(discard).toBeVisible();
    await discard.getByRole("button", { name: "Keep editing", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/principals/${principalId}/tokens/new`));
    await expect(dialog.getByRole("textbox", { name: "Name", exact: true })).toHaveValue(`managed-token-${testInfo.project.name}`);
    const issueRequest = page.waitForRequest((request) => request.method() === "POST" && new URL(request.url()).pathname === `/v1/admin/principals/${principalId}/agent-tokens`);
    await dialog.getByRole("button", { name: "Issue token", exact: true }).click();
    expect((await issueRequest).postDataJSON()).toEqual({
      name: `managed-token-${testInfo.project.name}`,
      never: true,
      allowedServices: ["jira"],
      allowedExecutionContexts: ["default", "internal"],
      serviceRestrictions: { jira: { actions: ["issue.view"] } }
    });
    const reveal = page.getByRole("dialog", { name: "Token created", exact: true });
    await expect(reveal.getByText(principalId, { exact: true })).toBeVisible();
    await expect(reveal.getByText("Never", { exact: true })).toBeVisible();
    await expect(reveal.getByText("default, internal", { exact: true }).first()).toBeVisible();
    const managedRawToken = await reveal.getByLabel("Token", { exact: true }).innerText();
    expect(managedRawToken.length).toBeGreaterThan(20);
    const managedMcp = reveal.getByRole("region", { name: "Connect an MCP client", exact: true });
    await expect(managedMcp.getByText(`export AGENT_ACCESS_TOKEN=${managedRawToken}`, { exact: true })).toBeVisible();
    await reveal.getByRole("button", { name: "Done", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/principals/${principalId}/tokens\\?token=`));
    const row = tableRow(page, `managed-token-${testInfo.project.name}`);
    await expect(await columnCell(row, "Expires")).toHaveText("Never");
    await page.screenshot({ path: testInfo.outputPath("token-actions.png"), fullPage: true });

    // Agent and management tokens share one drawer: opening one closes the other.
    const management = page.getByRole("region", { name: /^Management tokens/ });
    await tableRow(management, `setup-token-${testInfo.project.name}`).getByRole("link").click();
    await expect(page).toHaveURL(/[?&]mtoken=/);
    await expect(drawer(`Token setup-token-${testInfo.project.name}`)).toBeVisible();
    await row.getByRole("link", { name: `managed-token-${testInfo.project.name}`, exact: true }).click();
    await expect(page).toHaveURL(/[?&]token=/);
    await expect(page).not.toHaveURL(/[?&]mtoken=/);
    await expect(drawer(`Token managed-token-${testInfo.project.name}`)).toBeVisible();
    await expect(drawer(`Token setup-token-${testInfo.project.name}`)).toHaveCount(0);
    await tableRow(management, `setup-token-${testInfo.project.name}`).getByRole("link").click();
    await expect(page).toHaveURL(/[?&]mtoken=/);
    await expect(page).not.toHaveURL(/[?&]token=/);
    await expect(drawer(`Token setup-token-${testInfo.project.name}`)).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(drawer(`Token setup-token-${testInfo.project.name}`)).toHaveCount(0);

    // A slow token list for one principal never shows another principal's tokens.
    const isolatedPrincipalId = `isolated-${testInfo.project.name}`;
    await browserManagementRequest(page, "/v1/admin/principals", { method: "POST", body: { principalId: isolatedPrincipalId, kind: "user", displayName: "Cache Isolation" } });
    let releaseIsolatedTokens!: () => void;
    const isolatedTokensBlocked = new Promise<void>((resolve) => {
      releaseIsolatedTokens = resolve;
    });
    const isolatedAgentTokensPattern = new RegExp(`/v1/admin/principals/${isolatedPrincipalId}/agent-tokens(?:\\?.*)?$`);
    await page.route(isolatedAgentTokensPattern, async (route) => {
      await isolatedTokensBlocked;
      await route.continue();
    });
    await page.goto(`${baseUrl}/ui/admin/principals/${isolatedPrincipalId}/tokens`);
    await expect(page.getByRole("heading", { name: "Cache Isolation", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Issue token", exact: true })).toBeDisabled();
    await expect(tableRow(page, `managed-token-${testInfo.project.name}`)).toHaveCount(0, { timeout: 250 });
    await space.getByRole("link", { name: "My access", exact: true }).click();
    await expect(page.getByRole("main", { name: "Access", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Issue token", exact: true })).toBeDisabled();
    await expect(page.getByText(`managed-token-${testInfo.project.name}`)).toHaveCount(0, { timeout: 250 });
    const isolatedTokensResponse = page.waitForResponse((response) => new URL(response.url()).pathname === `/v1/admin/principals/${isolatedPrincipalId}/agent-tokens`);
    releaseIsolatedTokens();
    await isolatedTokensResponse;
    await page.unroute(isolatedAgentTokensPattern);

    await page.goto(`${baseUrl}/ui/admin/principals/${principalId}/tokens`);
    await row.getByRole("button", { name: `Pause managed-token-${testInfo.project.name}`, exact: true }).click();
    await expect(toast("Token paused")).toBeVisible();
    await expect(row.getByText("Paused", { exact: true })).toBeVisible();
    await expect(row.getByRole("button", { name: `Resume managed-token-${testInfo.project.name}`, exact: true })).toBeAttached();
    await row.getByRole("link", { name: `managed-token-${testInfo.project.name}`, exact: true }).click();
    const details = drawer(`Token managed-token-${testInfo.project.name}`);
    await expect(details.getByText(principalId, { exact: true }).first()).toBeVisible();
    await expect(details.getByText("default, internal", { exact: true })).toBeVisible();
    await expect(details.getByText("Paused", { exact: true }).first()).toBeVisible();
    await expect(details.getByText("No access currently: this token is paused.")).toBeVisible();
    await details.getByRole("button", { name: "Resume token", exact: true }).click();
    await expect(toast("Token resumed")).toBeVisible();
    await expect(details.getByText("Active", { exact: true }).first()).toBeVisible();
    await expect(page.getByText(managedRawToken, { exact: true })).toHaveCount(0);
    await details.getByRole("button", { name: "Revoke", exact: true }).click();
    await confirmDialog(page, "Revoke token?", "Revoke token");
    await expect(toast("Token revoked")).toBeVisible();
  });

  await test.step("admins manage a user's credentials and see the user's access", async () => {
    const tabs = page.getByRole("navigation", { name: "User sections", exact: true });
    await tabs.getByRole("link", { name: "Credentials", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/principals/${principalId}/credentials$`));
    // The jira connection, shown under its configured display name.
    const row = page.getByRole("row").filter({ has: page.getByRole("link", { name: "Jira", exact: true }) });
    await expect(row).toContainText("atlassian-api-token");
    await row.getByRole("link").click();
    const details = page.getByRole("complementary", { name: / credential$/ });
    await details.getByLabel(/username/i).fill("alice@example.test");
    await details.getByLabel(/token/i).first().fill("ghp_managed_portal_e2e_token_value");
    await details.getByRole("button", { name: "Save credential", exact: true }).click();
    await expect(toast("Credential saved")).toBeVisible();
    await expect(row.getByText("Not verified", { exact: true })).toBeVisible();
    await details.getByRole("button", { name: "Verify", exact: true }).click();
    await expect(toast("Credential verified")).toBeVisible();
    await expect(row.getByText("Upstream verified", { exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("credential-actions.png"), fullPage: true });
    await details.getByRole("button", { name: "Delete", exact: true }).click();
    await confirmDialog(page, "Delete credential?", "Delete credential");
    await expect(toast("Credential deleted")).toBeVisible();
    await expect(row.getByText("Not saved", { exact: true })).toBeVisible();

    await tabs.getByRole("link", { name: "Access", exact: true }).click();
    await expect(tableRow(page, "issue.view").getByRole("link", { name: "issue.view", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Issue token", exact: true })).toBeEnabled();
    await expectNoHorizontalOverflow(page);
    await signOut(page);
  });

  await test.step("a user signs in with the temporary password and must change it", async () => {
    await page.goto(`${baseUrl}/ui/tokens`);
    await page.getByLabel("Principal").fill(principalId);
    await page.getByLabel("Password").fill(userPassword);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/account$/);
    await expect(page.getByText("Change your password to continue", { exact: true })).toBeVisible();
    await expect(page.getByRole("banner").getByText(principalId, { exact: true })).toHaveCount(0);
    const profile = page.getByRole("region", { name: "Profile" });
    await expect(profile.getByText("Alice Updated", { exact: true })).toBeVisible();
    await expect(profile.getByText(`${principalId}.updated@example.com`, { exact: true })).toBeVisible();
    await expect(profile.getByText(principalId, { exact: true })).toBeVisible();
    await expect(space).toHaveCount(0);
    await page.getByLabel("Current password").fill(userPassword);
    await page.getByLabel("New password", { exact: true }).fill("alice-password-updated");
    await page.getByLabel("Confirm new password").fill("alice-password-updated");
    await page.getByRole("button", { name: "Update password", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/tokens$/);
    await expect(page.getByRole("main", { name: "Tokens", exact: true })).toBeVisible();
    // Regular users have one space and no admin navigation.
    await expect(space).toHaveCount(0);
    await expect(adminNav).toHaveCount(0);
    await expect(page.getByRole("link", { name: "System", exact: true })).toHaveCount(0);
    await expect(selfNav.getByRole("link")).toHaveText(["Access", "Tokens", "Credentials", "Activity"]);
  });

  let rawToken = "";
  await test.step("a user filters access and issues, pauses, and revokes tokens", async () => {
    await selfNav.getByRole("link", { name: "Access", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/access$/);
    const accessRow = tableRow(page, "issue.view").getByRole("link", { name: "issue.view", exact: true });
    await expect(accessRow).toBeVisible();
    const context = page.getByRole("radiogroup", { name: "Execution context", exact: true });
    await expect(context.getByRole("radio", { name: "All contexts", exact: true })).toBeChecked();
    await context.getByRole("radio", { name: "external", exact: true }).check();
    await expect(context.getByRole("radio", { name: "external", exact: true })).toBeChecked();
    await expect(accessRow).toBeVisible();
    const filter = page.getByRole("searchbox", { name: "Filter actions, resources…" });
    await filter.fill("no-such-action");
    await expect(page.getByRole("heading", { name: "No matching access", exact: true })).toBeVisible();
    await filter.fill("");
    await expect(accessRow).toBeVisible();
    // Grouping by service adds a header row per service and drops the Service column.
    const accessTable = page.getByRole("table", { name: "Access", exact: true });
    await page.getByRole("button", { name: "Group", exact: true }).click();
    await page.getByRole("menuitemradio", { name: "Service", exact: true }).click();
    await expect(page).toHaveURL(/group=service/);
    await expect(accessTable.getByRole("rowheader", { name: /^Jira/ })).toBeVisible();
    await expect(accessTable.getByRole("columnheader", { name: "Service" })).toHaveCount(0);
    await page.getByRole("button", { name: "Group", exact: true }).click();
    await page.getByRole("menuitemradio", { name: "None", exact: true }).click();
    await expect(page).not.toHaveURL(/group=/);
    await accessRow.click();
    const accessDrawer = page.getByRole("complementary", { name: /^issue\.view on / });
    await expect(accessDrawer.getByText(/All Jira projects/).first()).toBeVisible();
    await page.keyboard.press("Escape");

    await page.getByRole("button", { name: "Issue token", exact: true }).first().click();
    const dialog = page.getByRole("main", { name: "Issue agent token", exact: true });
    const lifetime = dialog.getByLabel("Lifetime");
    await expect(lifetime).toHaveValue("37m");
    await expect.poll(() => lifetime.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value))).toEqual(["37m", "5h", "never"]);
    await expect(dialog.getByText(/the longest finite lifetime is 5 hours/)).toBeVisible();
    await expect(lifetime.locator("option:checked")).toHaveText("37 minutes");
    await dialog.getByRole("textbox", { name: "Name", exact: true }).fill(`portal-e2e-${testInfo.project.name}`);
    const contexts = dialog.getByRole("group", { name: "Execution contexts" });
    await expect(contexts.getByRole("checkbox")).toHaveCount(3);
    for (const item of ["default", "internal", "external"]) await expect(contexts.getByLabel(item, { exact: true })).toBeChecked();
    await expect(dialog.getByRole("button", { name: "Review", exact: true })).toHaveCount(0);
    await expect(dialog.getByLabel("jira")).toHaveCount(0);
    const issueRequest = page.waitForRequest((request) => request.method() === "POST" && new URL(request.url()).pathname === "/v1/tokens");
    await dialog.getByRole("button", { name: "Issue token", exact: true }).click();
    expect((await issueRequest).postDataJSON()).toEqual({
      name: `portal-e2e-${testInfo.project.name}`,
      ttl: "37m",
      allowedExecutionContexts: ["default", "internal", "external"]
    });
    const reveal = page.getByRole("dialog", { name: "Token created", exact: true });
    await expect(reveal.getByText("default, internal, external", { exact: true })).toBeVisible();
    await expect(reveal.getByText("All actions and resources allowed by current grants.", { exact: true })).toBeVisible();
    rawToken = await reveal.getByLabel("Token", { exact: true }).innerText();
    expect(rawToken.length).toBeGreaterThan(20);

    // Connecting MCP clients: snippets name the token's variable; only the environment line holds the token.
    const mcpUrl = `${baseUrl}/mcp`;
    const mcp = reveal.getByRole("region", { name: "Connect an MCP client", exact: true });
    await expect(mcp.getByText(mcpUrl, { exact: true })).toBeVisible();
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"], { origin: baseUrl });
    const clipboard = () => page.evaluate(() => navigator.clipboard.readText());
    await mcp.getByRole("button", { name: "Copy server URL", exact: true }).click();
    await expect.poll(clipboard).toBe(mcpUrl);
    await expect(mcp.getByText(`export AGENT_ACCESS_TOKEN=${rawToken}`, { exact: true })).toBeVisible();
    await mcp.getByRole("group", { name: "Operating system", exact: true }).getByRole("button", { name: "Windows PowerShell", exact: true }).click();
    await mcp.getByRole("button", { name: "Copy the Windows PowerShell line", exact: true }).click();
    await expect.poll(clipboard).toBe(`setx AGENT_ACCESS_TOKEN ${rawToken}; $env:AGENT_ACCESS_TOKEN = "${rawToken}"`);
    const clients = mcp.getByRole("tablist", { name: "MCP client", exact: true });
    await expect(clients.getByRole("tab")).toHaveText(["Pi", "OpenCode", "Claude Code", "Codex", "Cursor"]);
    await expect(clients.getByRole("tab", { name: "Pi", exact: true })).toHaveAttribute("aria-selected", "true");
    await clients.getByRole("tab", { name: "Codex", exact: true }).click();
    await expect(mcp.getByText("~/.codex/config.toml", { exact: true })).toBeVisible();
    await mcp.getByRole("button", { name: "Copy the Codex config file", exact: true }).click();
    await expect.poll(clipboard).toBe(`[mcp_servers.agent_access]\nurl = "${mcpUrl}"\nbearer_token_env_var = "AGENT_ACCESS_TOKEN"`);
    await expect(mcp.getByRole("tabpanel")).not.toContainText(rawToken);
    // Claude Code: only the user-scope command, which covers all projects; no configuration file.
    await clients.getByRole("tab", { name: "Claude Code", exact: true }).click();
    const claude = mcp.getByRole("tabpanel");
    await expect(claude.getByText("Command (adds it for all your projects)", { exact: true })).toBeVisible();
    await claude.getByRole("button", { name: "Copy the Claude Code command", exact: true }).click();
    await expect.poll(clipboard).toBe(`claude mcp add --scope user --transport http agent_access ${mcpUrl} --header 'Authorization: Bearer \${AGENT_ACCESS_TOKEN}'`);
    await expect(claude.getByRole("button", { name: "Copy the Claude Code config file", exact: true })).toHaveCount(0);
    await expect(claude).not.toContainText("Or add it to");
    await clients.getByRole("tab", { name: "Cursor", exact: true }).click();
    await expect(mcp.getByRole("link", { name: "Add to Cursor", exact: true })).toHaveAttribute("href", /^cursor:\/\/anysphere\.cursor-deeplink\/mcp\/install\?name=agent_access&config=[^&]+$/);
    await expect(mcp.getByRole("tabpanel")).not.toContainText(rawToken);
    // Snippets wrap instead of hiding text behind a horizontal scroll.
    const overflowingSnippets = () => mcp.evaluate((section) => [...section.querySelectorAll("code, pre")].filter((element) => element.scrollWidth > element.clientWidth + 1).map((element) => element.textContent));
    for (const name of ["Pi", "OpenCode", "Claude Code", "Codex", "Cursor"]) {
      await clients.getByRole("tab", { name, exact: true }).click();
      expect(await overflowingSnippets(), name).toEqual([]);
    }
    expect(await page.evaluate(() => localStorage.getItem("aab.portal.mcp-client"))).toBe("cursor");
    await expectNoHorizontalOverflow(page);

    expect(page.url()).not.toContain(rawToken.slice(0, 12));
    expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain(rawToken);
    expect(await page.evaluate(() => JSON.stringify(sessionStorage))).not.toContain(rawToken);

    // Browser Back discards the one-time secret.
    await page.goBack();
    await expect(reveal).toHaveCount(0);
    await expect(page.getByText(rawToken, { exact: true })).toHaveCount(0);
    await selfNav.getByRole("link", { name: "Tokens", exact: true }).click();
    await expect(page.getByRole("main", { name: "Tokens", exact: true })).toBeVisible();
    expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain(rawToken);
    expect(await page.evaluate(() => JSON.stringify(sessionStorage))).not.toContain(rawToken);
    const name = `portal-e2e-${testInfo.project.name}`;
    const row = tableRow(page, name);
    await expect(await columnCell(row, "Contexts")).toHaveText("default, internal, external");
    await expect(await columnCell(row, "Status")).toHaveText("Active");
    await row.getByRole("button", { name: `Pause ${name}`, exact: true }).click();
    await expect(toast("Token paused")).toBeVisible();
    await expect(row.getByText("Paused", { exact: true })).toBeVisible();
    await expect(row.getByRole("button", { name: `Resume ${name}`, exact: true })).toBeAttached();
    await row.getByRole("link", { name, exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/tokens\?token=/);
    const details = drawer(`Token ${name}`);
    await expect(details.getByText("Paused", { exact: true }).first()).toBeVisible();
    await expect(details.getByText("No access currently: this token is paused.", { exact: true })).toBeVisible();
    await expect(details.getByText("All actions and resources allowed by current grants.", { exact: true })).toBeVisible();
    await details.getByRole("button", { name: "Resume token", exact: true }).click();
    await expect(toast("Token resumed")).toBeVisible();
    await expect(details.getByText("Active", { exact: true }).first()).toBeVisible();
    await details.getByText("Show what this token can reach now", { exact: true }).click();
    await expect(details.getByText(/All Jira projects.*except SECRET/).first()).toBeVisible();
    await expect(page.getByText(rawToken, { exact: true })).toHaveCount(0);
    await details.getByRole("button", { name: "Close", exact: true }).click();

    await row.getByRole("button", { name: `Revoke ${name}`, exact: true }).click();
    await confirmDialog(page, "Revoke token?", "Revoke token");
    await expect(toast("Token revoked")).toBeVisible();
    await expect(row).toHaveCount(0);
    const status = page.getByRole("group", { name: "Token status", exact: true });
    await status.getByRole("button", { name: /^Revoked/ }).click();
    await expect(row.getByText("Revoked", { exact: true })).toBeVisible();
    await expect(row.getByRole("button")).toHaveCount(0);

    await status.getByRole("button", { name: /^Current/ }).click();
    await page.getByRole("button", { name: "Issue token", exact: true }).first().click();
    await expect.poll(() => lifetime.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value))).toEqual(["37m", "5h", "never"]);
    await lifetime.selectOption("never");
    await expect(dialog.getByText(/This token stays active until it is revoked\./)).toBeVisible();
    const neverName = `portal-never-${testInfo.project.name}`;
    await dialog.getByRole("textbox", { name: "Name", exact: true }).fill(neverName);
    await contexts.getByLabel("internal", { exact: true }).uncheck();
    await contexts.getByLabel("external", { exact: true }).uncheck();
    await dialog.getByRole("group", { name: "Access", exact: true }).getByRole("button", { name: "Restrict to selected", exact: true }).click();
    const issue = dialog.getByRole("button", { name: "Issue token", exact: true });
    await expect(issue).toBeDisabled();
    await dialog.getByRole("checkbox", { name: "jira", exact: true }).check();
    await expect(issue).toBeDisabled();
    await dialog.getByRole("checkbox", { name: "issue.view", exact: true }).check();
    await expect(issue).toBeEnabled();
    await dialog.getByRole("button", { name: "Issue token", exact: true }).click();
    await expect(reveal.getByText("Never", { exact: true })).toBeVisible();
    await reveal.getByRole("button", { name: "Done", exact: true }).click();
    const neverRow = tableRow(page, neverName);
    await expect(await columnCell(neverRow, "Expires")).toHaveText("Never");
    await neverRow.getByRole("button", { name: `Revoke ${neverName}`, exact: true }).click();
    await confirmDialog(page, "Revoke token?", "Revoke token");
    await expect(toast("Token revoked")).toBeVisible();
    await status.getByRole("button", { name: /^Revoked/ }).click();
    await expect(neverRow.getByText("Revoked", { exact: true })).toBeVisible();
  });

  await test.step("a user saves, verifies, and deletes a credential", async () => {
    await selfNav.getByRole("link", { name: "Credentials", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/credentials$/);
    const row = page.getByRole("row").filter({ has: page.getByRole("link", { name: "Jira", exact: true }) });
    await expect(row.getByText("Not saved", { exact: true })).toBeVisible();
    await row.getByRole("link").click();
    await expect(page).toHaveURL(/\/ui\/credentials\?credential=jira$/);
    const details = page.getByRole("complementary", { name: / credential$/ });
    const tokenInput = details.getByLabel(/token/i).first();
    const hiddenSecretState = await tokenInput.evaluate((element) => {
      const input = element as HTMLInputElement;
      return { cssMasked: CSS.supports("-webkit-text-security", "disc"), type: input.type, masked: input.classList.contains("pt-secret"), autocomplete: input.autocomplete };
    });
    expect(hiddenSecretState.autocomplete).toBe("new-password");
    if (hiddenSecretState.cssMasked) expect(hiddenSecretState).toMatchObject({ type: "text", masked: true });
    else expect(hiddenSecretState).toMatchObject({ type: "password", masked: false });
    await details.getByLabel(/username/i).fill("alice@example.test");
    await tokenInput.fill("jira_portal_e2e_token_value");
    await details.getByRole("button", { name: "Save credential", exact: true }).click();
    await expect(toast("Credential saved")).toBeVisible();
    await expect(row.getByText("Not verified", { exact: true })).toBeVisible();
    // Unverified credentials are counted on the Credentials tab.
    await expect(selfNav.getByRole("link", { name: /^Credentials/ })).toContainText("1");
    await details.getByRole("button", { name: "Verify", exact: true }).click();
    await expect(toast("Credential verified")).toBeVisible();
    await expect(row.getByText("Upstream verified", { exact: true })).toBeVisible();
    await details.getByRole("button", { name: "Delete", exact: true }).click();
    await confirmDialog(page, "Delete credential?", "Delete credential");
    await expect(toast("Credential deleted")).toBeVisible();
    await expect(row.getByText("Not saved", { exact: true })).toBeVisible();
  });

  await test.step("account settings show own limits and switch themes", async () => {
    await openMenu(page, page.getByRole("button", { name: "Account", exact: true }), "Account settings");
    await expect(page).toHaveURL(/\/ui\/account$/);
    const limits = page.locator("table.own-service-limits");
    await expect(limits.getByRole("row").filter({ hasText: "jira" })).toContainText("1000 requests per 1m");
    await expect(limits.getByText(/^(Default|Override)$/)).toHaveCount(0);
    const theme = page.getByRole("group", { name: "Theme", exact: true });
    await theme.getByRole("button", { name: "Dark", exact: true }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await expect(theme.getByRole("button", { name: "Dark", exact: true })).toHaveAttribute("aria-pressed", "true");
    await theme.getByRole("button", { name: "Light", exact: true }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.emulateMedia({ colorScheme: "dark" });
    await theme.getByRole("button", { name: "System", exact: true }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await page.emulateMedia({ colorScheme: "light" });
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await expectNoHorizontalOverflow(page);

    // The top bar stays in place while the page content scrolls.
    const topbar = page.getByRole("banner");
    const scroller = page.getByRole("main").locator(".wb-scroll");
    const top = await topbar.evaluate((node) => node.getBoundingClientRect().top);
    await scroller.evaluate((node) => {
      const spacer = document.createElement("div");
      spacer.dataset.scrollRegressionSpacer = "true";
      spacer.className = "h-[2000px]";
      node.append(spacer);
      node.scrollTo({ top: node.scrollHeight });
    });
    await expect.poll(() => scroller.evaluate((node) => node.scrollTop)).toBeGreaterThan(0);
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
    await expect.poll(() => topbar.evaluate((node) => node.getBoundingClientRect().top)).toBe(top);
    await scroller.evaluate((node) => node.querySelector('[data-scroll-regression-spacer="true"]')?.remove());
    await signOut(page);
  });

  await test.step("admins see a user's management tokens, never browser sessions", async () => {
    await page.getByLabel("Principal").fill("admin");
    await page.getByLabel("Password").fill("admin-password-updated");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(adminNav.getByRole("link", { name: "Principals", exact: true })).toBeVisible();
    await page.goto(`${baseUrl}/ui/admin/principals/${principalId}/tokens`);
    const management = page.getByRole("region", { name: /^Management tokens/ });
    await expect(tableRow(management, `setup-token-${testInfo.project.name}`)).toBeVisible();
    await expect(tableRow(management, `admin-token-${testInfo.project.name}`)).toBeVisible();
    await expect(page.getByText("local_password:browser-session")).toHaveCount(0);
    await expectNoHorizontalOverflow(page);
    await signOut(page);
    await page.goto(`${baseUrl}/ui/tokens`);
    await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
  });

  expect(pageErrors).toEqual([]);
});

test("the catalog adds, filters, groups, and deletes resources with live references", async ({ page }, testInfo) => {
  const pageErrors = watchPageErrors(page);
  const toast = (text: string) => page.getByRole("status").filter({ hasText: text });
  await signInAsAdmin(page);
  await page.goto(`${baseUrl}/ui/admin/policies`);
  await page.getByRole("navigation", { name: "Admin", exact: true }).getByRole("link", { name: "Catalog", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/catalog$/);
  const sidebar = page.getByRole("complementary").filter({ has: page.getByRole("link", { name: /^Resource groups/ }) });
  await sidebar.getByRole("link", { name: /^Resources/ }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/catalog\/resources$/);
  await expect(page.getByRole("main", { name: "Resources", exact: true })).toBeVisible();

  const addResource = async () => {
    await page.getByRole("main").getByRole("button", { name: "Add resource", exact: true }).first().click();
    const editor = page.getByRole("complementary", { name: "Add resource", exact: true });
    await expect(editor).toBeVisible();
    await expect(page).toHaveURL(/item=new/);
    return editor;
  };
  let editor = await addResource();
  await editor.getByLabel("Resource type").selectOption("git_repository");
  await expect(editor.getByLabel("Coverage").locator("option")).toHaveText(["Specific resource", "Repositories under a namespace", "All Git repositories"]);
  await expect(editor.getByLabel("Canonical identifier")).toHaveAttribute("placeholder", "engineering/payments");
  await editor.getByLabel("Resource type").selectOption("jira_project");
  await expect(editor.getByLabel("Coverage").locator("option")).toHaveText(["Specific resource", "All Jira projects"]);
  await expect(editor.getByLabel("Canonical identifier")).toHaveAttribute("placeholder", "ENG");
  // Required fields are explained on save.
  await editor.getByRole("button", { name: "Save resource", exact: true }).click();
  await expect(editor.getByText("Enter the canonical identifier.")).toBeVisible();
  await expect(editor.getByText("Select at least one execution context.")).toBeVisible();
  await editor.getByLabel("Canonical identifier").fill("CATALOG");
  await editor.getByLabel("Display name").fill("Catalog project");
  const contexts = editor.getByRole("group", { name: "Allowed execution contexts" });
  for (const context of ["default", "internal", "external"]) await contexts.getByLabel(context, { exact: true }).check();
  await editor.getByRole("button", { name: "Save resource", exact: true }).click();
  await expect(toast("Resource added")).toBeVisible();
  const catalogDetails = page.getByRole("complementary", { name: "Resource Catalog project", exact: true });
  await expect(catalogDetails.getByText("default, internal, external", { exact: true }).first()).toBeVisible();
  await expect(tableRow(page, "Catalog project")).toBeVisible();

  editor = await addResource();
  await editor.getByLabel("Resource type").selectOption("confluence_space");
  await editor.getByLabel("Coverage").selectOption("all");
  await expect(editor.getByLabel("Canonical identifier")).toHaveCount(0);
  for (const context of ["default", "internal", "external"]) await editor.getByRole("group", { name: "Allowed execution contexts" }).getByLabel(context, { exact: true }).check();
  await editor.getByRole("button", { name: "Save resource", exact: true }).click();
  await expect(tableRow(page, "All Confluence spaces")).toBeVisible();

  editor = await addResource();
  await editor.getByLabel("Resource type").selectOption("confluence_space");
  await editor.getByLabel("Canonical identifier").fill("HIDDEN");
  await editor.getByRole("group", { name: "Allowed execution contexts" }).getByLabel("internal", { exact: true }).check();
  await editor.getByRole("switch", { name: "Enabled" }).or(editor.getByRole("checkbox", { name: "Enabled" })).uncheck();
  await editor.getByRole("button", { name: "Save resource", exact: true }).click();
  const hiddenRow = tableRow(page, "HIDDEN");
  await expect(hiddenRow.getByText("Disabled", { exact: true })).toBeVisible();

  // Filters live in the URL.
  const search = page.getByRole("searchbox", { name: "Filter resources…" });
  await search.fill("confluence");
  await expect(tableRow(page, "Catalog project")).toHaveCount(0);
  await expect(tableRow(page, "All Confluence spaces")).toBeVisible();
  const entries = await browserManagementRequest<{ id: string; displayName: string | null }[]>(page, "/v1/admin/policy/resources");
  await search.fill(entries.find((resource) => resource.displayName === "Catalog project")!.id);
  await expect(page.getByRole("table", { name: "Resources", exact: true }).getByRole("rowheader")).toHaveCount(1);
  await expect(tableRow(page, "Catalog project")).toBeVisible();
  await search.fill("");
  const typeFilter = page.getByRole("main").getByRole("combobox", { name: "Resource type", exact: true });
  await typeFilter.selectOption("git_repository");
  await expect(page).toHaveURL(/type=git_repository/);
  await expect(page.getByRole("heading", { name: "No matching resources", exact: true })).toBeVisible();
  await typeFilter.selectOption("confluence_space");
  const status = page.getByRole("group", { name: "Resource status", exact: true });
  await status.getByRole("button", { name: /^Disabled/ }).click();
  await expect(page.getByRole("table", { name: "Resources", exact: true }).getByRole("rowheader")).toHaveCount(1);
  await hiddenRow.getByRole("button", { name: "Enable HIDDEN", exact: true }).click();
  await expect(toast("Resource enabled")).toBeVisible();
  await expect(page.getByRole("heading", { name: "No matching resources", exact: true })).toBeVisible();
  await status.getByRole("button", { name: /^All/ }).click();
  await expect(hiddenRow.getByText("Disabled", { exact: true })).toHaveCount(0);
  await hiddenRow.getByRole("button", { name: "Disable HIDDEN", exact: true }).click();
  await expect(hiddenRow.getByText("Disabled", { exact: true })).toBeVisible();
  await page.reload();
  await expect(page).toHaveURL(/type=confluence_space/);
  await expect(typeFilter).toHaveValue("confluence_space");
  const resourcesTable = page.getByRole("table", { name: "Resources", exact: true });
  await page.getByRole("button", { name: "Group", exact: true }).click();
  await page.getByRole("menuitemradio", { name: "Type", exact: true }).click();
  await expect(page).toHaveURL(/group=type/);
  await expect(resourcesTable.getByRole("rowgroup").filter({ hasText: /^Confluence spaces/ }).getByRole("rowheader", { name: "HIDDEN", exact: true })).toBeVisible();
  await resourcesTable.getByRole("button", { name: "Name", exact: true }).click();
  await expect(page).toHaveURL(/sort=name(%3A|:)asc/);

  await sidebar.getByRole("link", { name: /^Resource groups/ }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/catalog\/resource-groups$/);
  await page.getByRole("main").getByRole("button", { name: "Add resource group", exact: true }).first().click();
  let groupEditor = page.getByRole("complementary", { name: "Add resource group", exact: true });
  await groupEditor.getByLabel("Group name").fill("Catalog spaces");
  await groupEditor.getByRole("group", { name: "Included resources", exact: true }).getByRole("checkbox", { name: /All Confluence spaces/ }).check();
  await groupEditor.getByRole("group", { name: "Excluded resources", exact: true }).getByRole("checkbox", { name: /HIDDEN/ }).check();
  await groupEditor.getByRole("button", { name: "Save resource group", exact: true }).click();
  await expect(toast("Resource group added")).toBeVisible();
  const groupDetails = page.getByRole("complementary", { name: "Resource group Catalog spaces", exact: true });
  await expect(groupDetails.getByRole("region", { name: /^Includes/ })).toContainText("All Confluence spaces");
  await expect(groupDetails.getByRole("region", { name: /^Excludes/ })).toContainText("HIDDEN");
  await expect(groupDetails.getByText("No references. This entry can be deleted.")).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("resource-groups.png"), fullPage: true });

  await page.getByRole("main").getByRole("button", { name: "Add resource group", exact: true }).first().click();
  groupEditor = page.getByRole("complementary", { name: "Add resource group", exact: true });
  await groupEditor.getByLabel("Group name").fill("Unused group");
  await groupEditor.getByRole("button", { name: "Save resource group", exact: true }).click();
  const unused = page.getByRole("complementary", { name: "Resource group Unused group", exact: true });
  await expect(unused.getByText("No references. This entry can be deleted.")).toBeVisible();
  const deleteButton = unused.getByRole("button", { name: "Delete", exact: true });
  await deleteButton.click();
  const confirmation = page.getByRole("alertdialog", { name: "Delete resource group?", exact: true });
  await expect(confirmation).toContainText("Delete Unused group?");
  // Escape closes only the confirmation and returns focus to its opener.
  await page.keyboard.press("Escape");
  await expect(confirmation).toHaveCount(0);
  await expect(unused).toBeVisible();
  await expect(deleteButton).toBeFocused();
  await deleteButton.click();
  await confirmation.getByRole("button", { name: "Delete resource group", exact: true }).click();
  await expect(toast("Resource group deleted")).toBeVisible();
  await expect(unused).toHaveCount(0);
  await expect(tableRow(page, "Unused group")).toHaveCount(0);

  // A referenced resource lists its references and cannot be deleted.
  await sidebar.getByRole("link", { name: /^Resources/ }).click();
  await hiddenRow.getByRole("link", { name: "HIDDEN", exact: true }).click();
  const hidden = page.getByRole("complementary", { name: "Resource HIDDEN", exact: true });
  const usedBy = hidden.getByRole("region", { name: /^Used by/ });
  await expect(usedBy).toContainText("Resource group");
  await expect(usedBy).toContainText("direct reference");
  await expect(hidden.getByRole("button", { name: "Delete", exact: true })).toBeDisabled();
  await expect(hidden.getByRole("region", { name: /^Resource groups/ }).getByRole("link", { name: "Catalog spaces", exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("resource-catalog.png"), fullPage: true });
  expect(pageErrors).toEqual([]);
});

test("the catalog preserves personal Confluence space keys through creation, editing, and grants", async ({ page }) => {
  const pageErrors = watchPageErrors(page);
  const resourcePath = "/v1/admin/policy/resources";
  const grantPath = "/v1/admin/policy/grants";
  const grantId = "personal-confluence-search";
  await signInAsAdmin(page);
  await page.goto(`${baseUrl}/ui/admin/catalog/resources`);

  // These are real catalog mutations; the fixture never contacts Confluence.
  await page.getByRole("main").getByRole("button", { name: "Add resource", exact: true }).first().click();
  const add = page.getByRole("complementary", { name: "Add resource", exact: true });
  await add.getByLabel("Resource type").selectOption("confluence_space");
  await add.getByLabel("Coverage").selectOption("exact");
  await add.getByLabel("Canonical identifier").fill("~alice");
  await add.getByLabel("Display name").fill("Alice personal space");
  await add.getByRole("group", { name: "Allowed execution contexts" }).getByLabel("default", { exact: true }).check();
  await add.getByRole("button", { name: "Save resource", exact: true }).click();
  const details = page.getByRole("complementary", { name: "Resource Alice personal space", exact: true });
  await expect(details.getByText("~alice", { exact: true })).toBeVisible();
  const resourceId = new URL(page.url()).searchParams.get("item");
  expect(resourceId).not.toBeNull();
  expect(await browserManagementRequest(page, `${resourcePath}/${resourceId}`)).toMatchObject({
    resourceType: "confluence_space", selector: { kind: "exact", value: "~alice" }
  });

  await details.getByRole("button", { name: "Edit", exact: true }).click();
  const edit = page.getByRole("complementary", { name: "Edit resource Alice personal space", exact: true });
  await expect(edit.getByLabel("Canonical identifier")).toHaveValue("~alice");
  await edit.getByLabel("Canonical identifier").fill("~Alice");
  await edit.getByLabel("Display name").fill("Alice personal documentation");
  await edit.getByRole("button", { name: "Save resource", exact: true }).click();
  const renamed = page.getByRole("complementary", { name: "Resource Alice personal documentation", exact: true });
  await expect(renamed.getByText("~Alice", { exact: true })).toBeVisible();
  await page.reload();
  await expect(renamed.getByText("~Alice", { exact: true })).toBeVisible();
  expect(await browserManagementRequest(page, `${resourcePath}/${resourceId}`)).toMatchObject({
    resourceType: "confluence_space", selector: { kind: "exact", value: "~Alice" },
    displayName: "Alice personal documentation", version: 2
  });

  await page.goto(`${baseUrl}/ui/admin/policies/new`);
  const grant = grantEditor(page);
  await page.getByLabel("Grant ID").fill(grantId);
  await addGrantSubject(page, "User", "admin", /^admin/);
  await grant.service.selectOption("confluence");
  await page.getByRole("checkbox", { name: "search", exact: true }).check();
  await grant.resources.getByRole("checkbox", { name: /^Alice personal documentation/ }).check();
  await grant.create.click();
  await expect(page).toHaveURL(new RegExp(`/ui/admin/policies\\?grant=${grantId}$`));
  expect(await browserManagementRequest(page, `${grantPath}/${grantId}`)).toMatchObject({
    subjects: ["user:admin"], service: "confluence", actions: ["search"],
    resources: { resourceIds: [resourceId], resourceGroupIds: [] }
  });

  await browserManagementRequest(page, `${grantPath}/${grantId}?expectedVersion=1`, { method: "DELETE" });
  await browserManagementRequest(page, `${resourcePath}/${resourceId}?expectedVersion=2`, { method: "DELETE" });
  expect(pageErrors).toEqual([]);
});

test("audit and activity show real broker records by visibility tier", async ({ page }, testInfo) => {
  const suffix = testInfo.project.name;
  const userId = `audit-user-${suffix}`;
  const ownerId = `audit-owner-${suffix}`;
  const password = "audit-viewer-password";
  const tokenName = `audit-agent-${suffix}`;
  const jiraCalls = 52;
  const confluenceCalls = 3;
  let tokenId = "";
  let confluenceRequestId = "";
  const rows = page.getByRole("main").getByRole("rowheader").getByRole("link");
  // Record rows (each day's group row is also a row header, without a link).
  const recordRows = page.getByRole("main").getByRole("row").filter({ has: page.getByRole("rowheader").getByRole("link") });
  const adminNav = page.getByRole("navigation", { name: "Admin", exact: true });

  await test.step("real actions write records", async () => {
    await signInAsAdmin(page);
    await page.goto(`${baseUrl}/ui`);
    for (const principalId of [userId, ownerId]) {
      await browserManagementRequest(page, "/v1/admin/principals", { method: "POST", body: { principalId, kind: "user", displayName: principalId, role: principalId === ownerId ? "service_policy_manager" : "user" } });
      await browserManagementRequest(page, `/v1/admin/principals/${principalId}/login-methods/local-password/enable`, {
        method: "POST",
        body: { password, mustChangePassword: false, acknowledgeSeparateSignIn: true }
      });
    }
    await browserManagementRequest(page, `/v1/admin/policy/services/jira/managers/${ownerId}`, { method: "PUT" });
    const resource = await browserManagementRequest<{ record: { id: string } }>(page, "/v1/admin/policy/resources", {
      method: "POST",
      body: { resourceType: "jira_project", selector: { kind: "exact", value: "AUDIT" }, displayName: `Audit ${suffix}`, allowedExecutionContexts: ["default"], enabled: true }
    });
    await browserManagementRequest(page, "/v1/admin/policy/grants", {
      method: "POST",
      body: {
        grantId: `audit-${suffix}`,
        subjects: [`user:${userId}`],
        service: "jira",
        actions: ["issue.view"],
        executionContexts: ["default"],
        resources: { resourceIds: [resource.record.id], resourceGroupIds: [] },
        credentialMode: "per_user",
        status: "active"
      }
    });

    await page.context().clearCookies();
    expect(await apiSignIn(page, userId, password)).not.toBeNull();
    await page.goto(`${baseUrl}/ui`);
    const issued = await browserManagementRequest<{ token: string; record: { tokenId: string } }>(page, "/v1/tokens", {
      method: "POST",
      body: { name: tokenName, ttl: "37m", allowedExecutionContexts: ["default"] }
    });
    tokenId = issued.record.tokenId;
    // The grant matches but no per-user Jira credential exists; Confluence has no grant.
    for (let index = 0; index < jiraCalls; index += 1) {
      expect((await invokeAsAgent(issued.token, "jira", "issue.view", { issue: `AUDIT-${index + 1}` })).decision).toBe("deny");
    }
    for (let index = 0; index < confluenceCalls; index += 1) {
      const denied = await invokeAsAgent(issued.token, "confluence", "page.view", { pageId: String(1000 + index) });
      expect(denied.decision).toBe("deny");
      confluenceRequestId = denied.brokerRequestId;
    }
  });

  await test.step("admins filter, search, page, and open a record with its request timeline", async () => {
    await page.context().clearCookies();
    await signInAsAdmin(page);
    await page.goto(`${baseUrl}/ui`);
    await adminNav.getByRole("link", { name: "Audit", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/audit$/);
    await expect(page.getByRole("main", { name: "Audit", exact: true })).toBeVisible();
    await expect(page.getByText("Every broker audit record.", { exact: true })).toBeVisible();
    await expect(page.getByTestId("audit-range")).toContainText("from");
    await expect(rows.filter({ hasText: "issue.view on jira" }).first()).toBeVisible();
    expect((await comboboxOptions(page, "Service"))[0]).toMatch(/^broker/);
    await chooseFacet(page, "Service", /^broker/);
    await expect(page).toHaveURL(/service=broker/);
    await expect(rows.filter({ hasText: "auth.local.login on broker" }).first()).toBeVisible();
    await expect(rows.filter({ hasNotText: / on broker$/ })).toHaveCount(0);
    expect(await comboboxOptions(page, "Action")).toContain("auth.local.login");
    await page.getByRole("button", { name: "Clear all", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/audit$/);

    const firstPage = page.waitForRequest((request) => {
      const url = new URL(request.url());
      return url.pathname === "/v1/admin/audit/events" && url.searchParams.get("principal") === userId;
    });
    await page.getByRole("combobox", { name: "Principal", exact: true }).fill(userId);
    await page.getByRole("combobox", { name: "Principal", exact: true }).press("Enter");
    const firstParams = new URL((await firstPage).url()).searchParams;
    // The 24-hour preset is resolved to an absolute UTC `from` for the session; `to` stays open.
    expect(Math.abs(Date.now() - 86_400_000 - Date.parse(firstParams.get("from")!))).toBeLessThan(120_000);
    expect(firstParams.get("from")).toMatch(/Z$/);
    expect(firstParams.has("to")).toBe(false);
    await expect(page).toHaveURL(new RegExp(`principal=${userId}`));
    const denied = page.getByRole("button", { name: /^Denied/ });
    await denied.click();
    await expect(denied).toHaveAttribute("aria-current", "true");
    await expect(page).toHaveURL(/decision=deny/);
    await expect(rows).toHaveCount(50);
    await expect(recordRows.filter({ hasNotText: "Denied" })).toHaveCount(0);

    const action = page.getByRole("combobox", { name: "Action", exact: true });
    await action.fill("page.view");
    await action.press("Enter");
    await expect(page).toHaveURL(/action=page\.view/);
    await expect(rows).toHaveCount(confluenceCalls);
    await action.locator("xpath=..").getByRole("button", { name: "Clear selection" }).click();
    const search = page.getByRole("searchbox", { name: "Search", exact: true });
    await search.fill("confluence");
    await search.press("Enter");
    await expect(page).toHaveURL(/q=confluence/);
    await expect(rows).toHaveCount(confluenceCalls);
    await expect(rows.filter({ hasNotText: / on confluence$/ })).toHaveCount(0);
    await search.fill("");
    await search.press("Enter");
    await expect(rows).toHaveCount(50);

    const nextPage = page.waitForRequest((request) => {
      const url = new URL(request.url());
      return url.pathname === "/v1/admin/audit/events" && url.searchParams.has("cursor");
    });
    await page.getByRole("button", { name: "Load more records", exact: true }).click();
    expect([...new URL((await nextPage).url()).searchParams.keys()].sort()).toEqual(["cursor", "limit"]);
    await expect(rows).toHaveCount(jiraCalls + confluenceCalls);
    await expect(page.getByRole("button", { name: "Load more records", exact: true })).toHaveCount(0);

    await rows.filter({ hasText: "page.view on confluence" }).first().click();
    await expect(page).toHaveURL(/request=.*&record=|record=.*&request=/);
    const detail = page.getByRole("complementary", { name: "Denied: page.view on confluence", exact: true });
    await expect(detail).toContainText("Broker request ID");
    await expect(detail).toContainText(tokenId);
    await expect(detail).toContainText("scope_unresolved");
    await detail.getByRole("tab", { name: "Raw", exact: true }).click();
    await expect(detail.getByRole("button", { name: "Copy JSON", exact: true })).toBeVisible();
    await detail.getByText("Record JSON", { exact: true }).click();
    await expect(detail.locator("pre").last()).toContainText('"auditId"');
    await page.keyboard.press("Escape");
    await expect(detail).toHaveCount(0);

    // A token issuance writes a preflight and a success record under one request.
    await page.getByRole("button", { name: /^All decisions/ }).click();
    await action.fill("tokens.issue");
    await action.press("Enter");
    await expect(rows).toHaveCount(2);
    await rows.first().click();
    const issued = page.getByRole("complementary", { name: /tokens\.issue on broker$/ });
    await issued.getByRole("tab", { name: /^Timeline/ }).click();
    const timeline = issued.getByRole("list", { name: "Request timeline", exact: true }).getByRole("button");
    await expect(timeline).toHaveCount(2);
    await expect(timeline.nth(0)).toContainText("preflight");
    await expect(timeline.nth(0)).toContainText("start");
    await expect(timeline.nth(1)).toContainText("success");
    await expect(timeline.nth(1)).toContainText(/\+\d/);
    // The open record is a deep link.
    await page.reload();
    await expect(page.getByRole("complementary", { name: /tokens\.issue on broker$/ })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page).toHaveURL(new RegExp(`/ui/admin/audit\\?.*principal=${userId}`));
    await expect(action).toHaveValue("tokens.issue");
    await expect(rows).toHaveCount(2);

    await page.getByRole("button", { name: /More filters/ }).click();
    await page.getByLabel("Phase", { exact: true }).selectOption("success");
    await expect(page).toHaveURL(/phase=success/);
    await expect(rows).toHaveCount(1);

    await page.goto(`${baseUrl}/ui/admin/principals/${userId}`);
    await openMenu(page, page.getByRole("main").getByRole("button", { name: "More actions", exact: true }), "View in Audit");
    await expect(page).toHaveURL(new RegExp(`/ui/admin/audit\\?principal=${userId}$`));
    await expect(page.getByRole("combobox", { name: "Principal", exact: true })).toHaveValue(userId);
    // The user page's Activity tab shows the same records in place.
    await page.goto(`${baseUrl}/ui/admin/principals/${userId}/activity`);
    await expect(rows.filter({ hasText: "issue.view on jira" }).first()).toBeVisible();
    await rows.filter({ hasText: "issue.view on jira" }).first().click();
    await expect(page.getByRole("complementary", { name: /issue\.view on jira$/ })).toContainText(tokenId);
  });

  await test.step("service policy managers see Policies and Audit, scoped to their services", async () => {
    await page.context().clearCookies();
    expect(await apiSignIn(page, ownerId, password)).not.toBeNull();
    await page.goto(`${baseUrl}/ui`);
    await expect(adminNav.getByRole("link")).toHaveText(["Policies", "Audit"]);
    await adminNav.getByRole("link", { name: "Audit", exact: true }).click();
    await expect(page.getByText("Audit records for the services you manage: jira.", { exact: true })).toBeVisible();
    const services = await comboboxOptions(page, "Service");
    expect(services).toHaveLength(2);
    expect(services[0]).toMatch(/^broker/);
    expect(services[1]).toMatch(/^jira/);
    await expect(rows.filter({ hasText: "issue.view on jira" }).first()).toBeVisible();
    await expect(rows.filter({ hasText: "auth.local.login" })).toHaveCount(0);
    await chooseFacet(page, "Service", /^broker/);
    await expect(page).toHaveURL(/service=broker/);
    await expect(rows.filter({ hasText: "admin.policy.grants.create on broker" }).first()).toBeVisible();
    await expect(rows.filter({ hasNotText: / on broker$/ })).toHaveCount(0);
    await expect(rows.filter({ hasText: "auth.local.login" })).toHaveCount(0);
    await expect(page.getByRole("main").getByText("Related service: jira", { exact: true }).first()).toBeVisible();
    expect(await comboboxOptions(page, "Action")).toContain("admin.policy.grants.create");
    await chooseFacet(page, "Service", /^jira/);
    await expect(rows.filter({ hasText: "issue.view on jira" }).first()).toBeVisible();
    await expect(rows.filter({ hasNotText: / on jira$/ })).toHaveCount(0);
    const search = page.getByRole("searchbox", { name: "Search", exact: true });
    await search.fill("confluence");
    await search.press("Enter");
    await expect(page.getByText("No matching records", { exact: true })).toBeVisible();
    await page.goto(`${baseUrl}/ui/admin/audit?request=${confluenceRequestId}`);
    await expect(page.getByText("No audit records you can see have this request ID.")).toBeVisible();
    await page.getByRole("navigation", { name: "Space", exact: true }).getByRole("link", { name: "My access", exact: true }).click();
    await expect(page.getByRole("navigation", { name: "My access", exact: true }).getByRole("link", { name: "Activity", exact: true })).toBeVisible();
  });

  await test.step("users see only their own records in Activity, with token names", async () => {
    await page.context().clearCookies();
    expect(await apiSignIn(page, userId, password)).not.toBeNull();
    await page.goto(`${baseUrl}/ui`);
    await expect(page).toHaveURL(/\/ui\/access$/);
    await expect(adminNav).toHaveCount(0);
    const selfNav = page.getByRole("navigation", { name: "My access", exact: true });
    await selfNav.getByRole("link", { name: "Activity", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/activity$/);
    await expect(page.getByRole("main", { name: "Activity", exact: true })).toBeVisible();
    await expect(page.getByText("Your own broker activity, including requests made with your agent tokens.", { exact: true })).toBeVisible();
    await expect(page.getByRole("combobox", { name: "Principal", exact: true })).toHaveCount(0);
    const invocation = tableRow(page.getByRole("main"), "issue.view on jira").first();
    await expect(await columnCell(invocation, "Token")).toHaveText(tokenName);
    await chooseFacet(page, "Service", /^broker/);
    await expect(page).toHaveURL(/service=broker/);
    await expect(rows.filter({ hasText: "auth.local.login on broker" }).first()).toBeVisible();
    await expect(rows.filter({ hasNotText: / on broker$/ })).toHaveCount(0);
    expect(await comboboxOptions(page, "Action")).toContain("tokens.issue");
    // The admin's records about this user belong to the admin.
    const action = page.getByRole("combobox", { name: "Action", exact: true });
    await action.fill("admin.principals.create");
    await action.press("Enter");
    await expect(page.getByText("No matching records", { exact: true })).toBeVisible();

    await selfNav.getByRole("link", { name: "Tokens", exact: true }).click();
    await tableRow(page, tokenName).getByRole("link", { name: tokenName, exact: true }).click();
    await page.getByRole("complementary", { name: `Token ${tokenName}`, exact: true }).getByRole("link", { name: "View activity", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/ui/activity\\?range=1h&tokenId=${tokenId}$`));
    await expect(rows.first()).toBeVisible();
    await expect(recordRows.filter({ hasNotText: tokenName })).toHaveCount(0);
    await expectNoHorizontalOverflow(page);
  });
});

/** An admin session on Policies with one managed grant (jira-readers), every other API mocked. */
async function mockPolicyGrants(page: Page) {
  const managementResult = (result: unknown) => JSON.stringify({
    ok: true,
    decision: "allow",
    requestId: "request-compact-list",
    brokerRequestId: "broker-compact-list",
    operation: "policy",
    principal: "admin",
    result,
  });
  await mockUnlistedApis(page);
  await mockResourceTypes(page);
  await page.route("**/v1/auth/session", (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      ok: true,
      result: { role: "admin", selfServiceEnabled: true,
        authenticated: true,
        principal: "admin",
        displayName: "Administrator",

        policyManagementServices: [],
        csrfHeader: "x-csrf-token",
        csrfToken: "csrf-token",
      },
    }),
  }));
  for (const path of ["/v1/credentials/targets", "/v1/credentials", "/v1/tokens"]) {
    await page.route(`**${path}`, (route) => route.fulfill({ contentType: "application/json", body: managementResult(path === "/v1/credentials" ? EMPTY_CREDENTIALS : []) }));
  }
  await page.route("**/v1/tokens/options", (route) => route.fulfill({
    contentType: "application/json",
    body: managementResult({ policyGeneration: 1, resources: [], resourceGroups: [], executionContexts: [], services: [] }),
  }));
  await page.route("**/v1/admin/policy/status", (route) => route.fulfill({
    contentType: "application/json",
    body: managementResult({
      identityAuthority: "managed",
      policyAuthority: "managed",
      writable: true,
      defaultDecision: "deny",
      configGeneration: 1,
      policyGeneration: 1,
      counts: { active: 1, disabled: 0, deleted: 0 },
      managementScope: { kind: "global" },
    }),
  }));
  await page.route("**/v1/admin/policy/catalog", (route) => route.fulfill({
    contentType: "application/json",
    body: managementResult({
      resources: [], resourceGroups: [],
      services: [{
        service: "jira",
        displayName: "Jira",
        surface: "http",
        actions: [{
          action: "issue.view",
          description: "List issues",
          requiredScopeTypes: [],
          credentialModes: ["user"],
          lookupRequired: false,
          inputSchema: {},
        }],
        resourceScopes: {},
        configuredCredentialModes: ["user"],
        lookupCredentialConfigured: false,
      }],
      executionContexts: { allowedValues: ["default", "internal", "external"], contextRequired: false },
      subjects: {
        users: [{ principalId: "alice", displayName: "Alice Updated", status: "active" }],
        groups: [{ groupId: "users", displayName: "User Access", status: "active" }],
        anonymous: false,
      },
    }),
  }));
  await page.route("**/v1/admin/policy/grants", (route) => route.fulfill({
    contentType: "application/json",
    body: managementResult([{
      grantRef: "jira-readers",
      writable: true,
      grantId: "jira-readers",
      subjects: ["group:users", "user:alice"],
      service: "jira",
      actions: ["issue.view"],
      executionContexts: ["default", "internal", "external"],
      resources: { resourceIds: [], resourceGroupIds: [] },
      credentialMode: "user",
      status: "active",
      version: 1,
    }]),
  }));
  await page.route("**/v1/admin/policy/service-managers", (route) => route.fulfill({
    contentType: "application/json",
    body: managementResult([]),
  }));
  await page.route("**/v1/admin/config/status", (route) => route.fulfill({ contentType: "application/json", body: managementResult({ generation: 1, loadedAt: "2026-08-15T00:00:00Z", identityAuthority: "managed", policyAuthority: "managed" }) }));
  return managementResult;
}

test("row menus and grant summaries work without the native Popover API", async ({ page }) => {
  await page.addInitScript(() => {
    Reflect.deleteProperty(HTMLElement.prototype, "popover");
    Reflect.deleteProperty(HTMLElement.prototype, "showPopover");
  });
  await mockPolicyGrants(page);
  await page.goto(`${baseUrl}/ui/admin/policies`);

  const row = tableRow(page, "jira-readers");
  await expect(await columnCell(row, "Subjects")).toHaveText("User Access, Alice Updated");
  await expect(await columnCell(row, "Contexts")).toHaveText("default, internal, external");
  await openMenu(page, row.getByRole("button", { name: "More actions for jira-readers", exact: true }), "Duplicate");
  await expect(page).toHaveURL(/\/ui\/admin\/policies\/new\?from=jira-readers$/);
  await page.goBack();
  await row.getByRole("link", { name: "jira-readers", exact: true }).click();
  const drawer = page.getByRole("complementary", { name: "Grant jira-readers", exact: true });
  await expect(drawer.getByText("User Access · ID: group:users")).toBeVisible();
  await expect(drawer.getByText("Alice Updated · ID: user:alice")).toBeVisible();
  await expect(drawer.getByRole("region", { name: "Scope" }).getByText("default, internal, external", { exact: true })).toBeVisible();
  // The account menu is a popover too.
  await openMenu(page, page.getByRole("button", { name: "Account", exact: true }), "Account settings");
  await expect(page).toHaveURL(/\/ui\/account$/);
});

test("a grant's effective access merges only identical contexts into compact rows", async ({ page }) => {
  const managementResult = await mockPolicyGrants(page);
  const all = [{ included: [{ kind: "all" }], excluded: [{ kind: "exact", value: "SECRET" }] }];
  const eng = [{ included: [{ kind: "exact", value: "ENG" }], excluded: [], excludedRequests: [{ included: [{ kind: "exact", value: "ENG-PRIVATE" }], excluded: [] }] }];
  await page.route("**/v1/admin/policy/effective-access", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: managementResult({
        policyGeneration: 7,
        access: [
          { service: "jira", action: "issue.view", executionContext: "default", resourceType: "jira_project", clauses: all },
          { service: "jira", action: "issue.view", executionContext: "internal", resourceType: "jira_project", clauses: all },
          { service: "jira", action: "issue.view", executionContext: "external", resourceType: "jira_project", clauses: eng }
        ]
      })
    })
  );
  await page.goto(`${baseUrl}/ui/admin/policies?grant=jira-readers`);
  const drawer = page.getByRole("complementary", { name: "Grant jira-readers", exact: true });
  const table = drawer.getByRole("table");
  await expect(table.getByRole("columnheader")).toHaveText(["Actions", "Contexts", "Resources"]);
  // default and internal share their clauses: one row. external differs: its own row, with its whole-request condition.
  const rows = table.locator("tbody tr");
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(0).getByRole("rowheader")).toHaveText("issue.view");
  await expect(rows.nth(0).getByRole("cell").nth(0)).toHaveText("default, internal");
  await expect(rows.nth(0).getByRole("cell").nth(1)).toContainText(/All Jira projects.*except SECRET/);
  await expect(rows.nth(1).getByRole("cell").nth(0)).toHaveText("external");
  await expect(rows.nth(1).getByRole("cell").nth(1)).toContainText("ENG");
  await expect(rows.nth(1).getByRole("cell").nth(1)).toContainText("Does not apply when every requested resource is within: ENG-PRIVATE.");
});

test("effective access keeps long merged contexts inside the drawer and lists all granted actions from the keyboard", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 900 });
  const managementResult = await mockPolicyGrants(page);
  const contexts = ["internal-production", "external-production", "development", "staging", "default"];
  // Routes registered later run first: this grant has two actions in five long contexts.
  await page.route("**/v1/admin/policy/grants", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: managementResult([{
        grantRef: "jira-readers",
        writable: true,
        grantId: "jira-readers",
        subjects: ["group:users"],
        service: "jira",
        actions: ["issue.view", "search"],
        executionContexts: contexts,
        resources: { resourceIds: [], resourceGroupIds: [] },
        credentialMode: "user",
        status: "active",
        version: 1,
      }]),
    })
  );
  const clauses = [{ included: [{ kind: "all" }], excluded: [{ kind: "exact", value: "SECRET" }] }];
  await page.route("**/v1/admin/policy/effective-access", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: managementResult({
        policyGeneration: 7,
        access: ["issue.view", "search"].flatMap((action) =>
          contexts.map((executionContext) => ({ service: "jira", action, executionContext, resourceType: "jira_project", clauses }))
        )
      })
    })
  );
  await page.goto(`${baseUrl}/ui/admin/policies?grant=jira-readers`);
  const drawer = page.getByRole("complementary", { name: "Grant jira-readers", exact: true });
  const table = drawer.getByRole("table");
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table.getByRole("cell").first()).toHaveText(contexts.join(", "));
  await expect(table.getByText(/All Jira projects.*except SECRET/)).toBeVisible();
  // The table (contexts and resources included) stays within the drawer.
  const [tableBox, drawerBox] = await Promise.all([table.boundingBox(), drawer.boundingBox()]);
  expect(tableBox!.x + tableBox!.width).toBeLessThanOrEqual(drawerBox!.x + drawerBox!.width + 1);
  // Every granted action: collapsed, and revealed from the keyboard.
  const all = table.getByText("All 2 granted actions", { exact: true });
  await expect(all).toBeVisible();
  await expect(table.getByText("search", { exact: true })).toBeHidden();
  await all.focus();
  await page.keyboard.press("Enter");
  await expect(table.getByText("search", { exact: true })).toBeVisible();
  await expect(table.getByRole("rowheader")).toContainText("issue.view");
});

test("a failed deleted-grants read shows its error and Retry above the current grants", async ({ page }) => {
  const managementResult = await mockPolicyGrants(page);
  let fail = true;
  await page.route((url) => url.pathname === "/v1/admin/policy/grants" && url.searchParams.get("status") === "deleted", (route) =>
    fail
      ? route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ ok: false, reasonCode: "internal_error", error: { message: "Store unavailable" } }) })
      : route.fulfill({
          contentType: "application/json",
          body: managementResult([{
            grantRef: "retired-readers",
            writable: true,
            grantId: "retired-readers",
            subjects: ["group:users"],
            service: "jira",
            actions: ["issue.view"],
            executionContexts: ["default"],
            resources: { resourceIds: [], resourceGroupIds: [] },
            credentialMode: "user",
            status: "deleted",
            version: 2,
          }]),
        }));
  await page.goto(`${baseUrl}/ui/admin/policies`);
  const table = page.getByRole("table", { name: "Grants", exact: true });
  await expect(tableRow(table, "jira-readers")).toBeVisible();
  await page.getByRole("group", { name: "Grant status", exact: true }).getByRole("button", { name: /^All/ }).click();
  // The current grants stay, with the failed read and its Retry above them.
  await expect(table.getByText("Store unavailable")).toBeVisible();
  await expect(tableRow(table, "jira-readers")).toBeVisible();
  fail = false;
  await table.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(tableRow(table, "retired-readers")).toBeVisible();
  await expect(table.getByText("Store unavailable")).toHaveCount(0);
  await expect(tableRow(table, "jira-readers")).toBeVisible();
});

test("access resource details disclose exclusions with their own alternative", async ({ page }) => {
  const envelope = (result: unknown) => JSON.stringify({ ok: true, result });
  await mockUnlistedApis(page);
  await mockResourceTypes(page);
  await page.route("**/v1/auth/session", (route) => route.fulfill({
    contentType: "application/json",
    body: envelope({ role: "user", selfServiceEnabled: true, authenticated: true, principal: "reader",  })
  }));
  await page.route("**/v1/tokens/options", (route) => route.fulfill({
    contentType: "application/json",
    body: envelope({
      policyGeneration: 1, resources: [], resourceGroups: [], executionContexts: ["internal", "external"],
      services: [{ service: "jira", displayName: "Jira", brokerHosts: [], executionContexts: ["internal"], actions: [{
        action: "issue.view", description: "View issues", readOnly: true, resourceType: "jira_project", executionContexts: ["internal"],
        effectiveAccessByExecutionContext: { internal: [
          { included: [{ kind: "all" }], excluded: [], excludedRequests: [{ included: [{ kind: "exact", value: "SECRET" }], excluded: [] }] },
          { included: [{ kind: "exact", value: "ENG" }], excluded: [] }
        ] }
      }] }, { service: "confluence", displayName: "Confluence", brokerHosts: [], executionContexts: ["external"], actions: [{
        action: "page.view", description: "View pages", readOnly: true, resourceType: "confluence_space", executionContexts: ["external"],
        effectiveAccessByExecutionContext: { external: [
          { included: [{ kind: "all" }], excluded: [], excludedRequests: [{ included: [{ kind: "exact", value: "PRIVATE" }], excluded: [] }] }
        ] }
      }] }]
    })
  }));
  for (const path of ["/v1/credentials/targets", "/v1/credentials", "/v1/tokens"]) {
    await page.route(`**${path}`, (route) => route.fulfill({ contentType: "application/json", body: envelope(path === "/v1/credentials" ? EMPTY_CREDENTIALS : []) }));
  }
  await page.goto(`${baseUrl}/ui/access`);
  // The row shows the first alternative and how many more there are.
  const row = tableRow(page, "issue.view");
  await expect(row).toContainText("All Jira projects");
  await expect(row).toContainText("+1 alternative");
  await row.getByRole("link", { name: "issue.view", exact: true }).click();
  // Services are named from the token options.
  const details = page.getByRole("complementary", { name: "issue.view on Jira", exact: true });
  await expect(details.getByText("Every resource in a request must fit the same alternative.", { exact: true })).toBeVisible();
  await expect(details.getByRole("listitem")).toHaveText([
    "All Jira projectsDoes not apply when every requested resource is within: SECRET.",
    "Or: ENG"
  ]);
  await details.getByRole("button", { name: "Close", exact: true }).click();
  // A context without the chosen service clears the service filter.
  await page.getByRole("complementary", { name: "Access filters", exact: true }).getByRole("button", { name: /^Jira/ }).click();
  await expect(page).toHaveURL(/service=jira/);
  await page.getByRole("radiogroup", { name: "Execution context", exact: true }).getByRole("radio", { name: "external", exact: true }).check();
  await expect(page).not.toHaveURL(/service=/);
  await tableRow(page, "page.view").getByRole("link", { name: "page.view", exact: true }).click();
  await expect(page.getByRole("complementary", { name: "page.view on Confluence", exact: true })).toContainText(
    /All Confluence spaces\s*Does not apply when every requested resource is within: PRIVATE\./
  );
});

function brokerSecrets(root: string) {
  return {
    credentialKey: path.join(root, "credential-key"),
    hashKey: path.join(root, "hash-key"),
    csrfKey: path.join(root, "csrf-key"),
    passwordPepper: path.join(root, "password-pepper"),
    auditToken: path.join(root, "audit-token"),
    gitToken: path.join(root, "git-token"),
    trustedCaller: path.join(root, "trusted-caller")
  };
}

test("grant action columns preserve hidden selections and show write capability", async ({ page }, testInfo) => {
  await signInAsAdmin(page);
  await page.goto(`${baseUrl}/ui/admin/policies`);
  await browserManagementRequest(page, "/v1/admin/policy/resources", { method: "POST", body: {
    id: "classified-project", displayName: "Classified project", resourceType: "jira_project",
    selector: { kind: "exact", value: "CLASSIFIED" }, allowedExecutionContexts: ["default"], enabled: true
  } });
  await page.goto(`${baseUrl}/ui/admin/policies/new`);
  const editor = grantEditor(page);
  await page.getByLabel("Grant ID").fill("classified-actions");
  await addGrantSubject(page, "User", "admin", /^admin/);
  await editor.service.selectOption("jira");
  const reads = page.getByRole("group", { name: "Read-only", exact: true });
  const writes = page.getByRole("group", { name: "Write-capable", exact: true });
  const search = page.getByRole("searchbox", { name: "Filter actions", exact: true });
  for (const category of ["read-only", "write-capable"]) {
    await expect(page.getByRole("button", { name: `Select all matching ${category} actions`, exact: true })).toHaveCount(1);
    await expect(page.getByRole("button", { name: `Select none of the matching ${category} actions`, exact: true })).toHaveCount(1);
  }
  await expect(reads.getByLabel("issue.view", { exact: true })).toBeVisible();
  await expect(writes.getByLabel("issue.create", { exact: true })).toBeVisible();
  await expect(reads.getByLabel("issue.create", { exact: true })).toHaveCount(0);
  await expect(writes.getByLabel("issue.view", { exact: true })).toHaveCount(0);
  const columnBounds = await Promise.all([reads, writes].map((column) => column.boundingBox()));
  expect(columnBounds[1]!.x).toBeGreaterThan(columnBounds[0]!.x);
  expect(Math.abs(columnBounds[0]!.y - columnBounds[1]!.y)).toBeLessThan(2);
  await search.fill("issue.view");
  await reads.getByRole("button", { name: "Select all matching read-only actions", exact: true }).click();
  await search.fill("");
  await reads.getByLabel("comment.view", { exact: true }).check();
  await writes.getByLabel("issue.create", { exact: true }).check();
  await writes.getByLabel("issue.update", { exact: true }).check();
  await search.fill("issue.create");
  await writes.getByRole("button", { name: "Select none of the matching write-capable actions", exact: true }).click();
  await search.fill("issue.view");
  await reads.getByRole("button", { name: "Select none of the matching read-only actions", exact: true }).click();
  await search.fill("");
  await expect(reads.getByLabel("comment.view", { exact: true })).toBeChecked();
  await expect(writes.getByLabel("issue.update", { exact: true })).toBeChecked();
  await expect(reads.getByLabel("issue.view", { exact: true })).not.toBeChecked();
  await expect(writes.getByLabel("issue.create", { exact: true })).not.toBeChecked();
  await expect(reads.getByText(/^1 of \d+$/)).toBeVisible();
  await expect(writes.getByText(/^1 of \d+$/)).toBeVisible();
  // The card header summarizes the selection.
  await expect(page.locator("#grant-service").getByText("Writes: 1 read-only action, 1 write-capable action")).toBeVisible();
  await reads.scrollIntoViewIfNeeded();
  await page.screenshot({ path: testInfo.outputPath("grant-action-picker.png"), fullPage: true });
  await search.fill("no-such-action");
  await expect(reads.getByRole("button", { name: "Select all matching read-only actions", exact: true })).toBeDisabled();
  await expect(writes.getByRole("button", { name: "Select none of the matching write-capable actions", exact: true })).toBeDisabled();
  await search.fill("");
  await editor.resources.getByRole("checkbox", { name: /^Classified project/ }).check();
  const creating = page.waitForRequest((request) => request.method() === "POST" && new URL(request.url()).pathname === "/v1/admin/policy/grants");
  await editor.create.click();
  expect((await creating).postDataJSON().actions.sort()).toEqual(["comment.view", "issue.update"]);
  await expect(page).toHaveURL(/\/ui\/admin\/policies\?grant=classified-actions$/);
  const row = tableRow(page, "classified-actions");
  // The open drawer narrows the table, so the Actions column may be hidden; its content stays.
  await expect(await columnCell(row, "Actions")).toContainText("Writes");
  const drawer = page.getByRole("complementary", { name: "Grant classified-actions", exact: true });
  await expect(drawer.getByText("Writes: 1 read-only action, 1 write-capable action")).toBeVisible();
  const grantActions = drawer.getByRole("region", { name: "Actions", exact: true });
  await expect(grantActions.getByText("comment.view", { exact: true })).toBeVisible();
  await expect(grantActions.getByText("issue.update", { exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("grant-write-capability.png"), fullPage: true });

  await page.goto(`${baseUrl}/ui/admin/principals/admin/grants`);
  await expect(tableRow(page, "classified-actions").getByText("Writes", { exact: true })).toBeVisible();
  await page.goto(`${baseUrl}/ui/admin/policies/classified-actions/edit`);
  await writes.getByRole("button", { name: "Select none of the matching write-capable actions", exact: true }).click();
  await expect(page.locator("#grant-service").getByTitle("1 read-only action, 0 write-capable actions")).toHaveText("Read-only");
  const saving = page.waitForRequest((request) => request.method() === "PATCH" && new URL(request.url()).pathname === "/v1/admin/policy/grants/classified-actions");
  await editor.save.click();
  expect((await saving).postDataJSON().actions).toEqual(["comment.view"]);
  await expect(page).toHaveURL(/\/ui\/admin\/policies\?grant=classified-actions$/);
  await expect(await columnCell(row, "Actions")).not.toContainText("Writes");
  await expectNoHorizontalOverflow(page);
});

test("the command palette finds a stored resource group and opens its details", async ({ page }) => {
  const pageErrors = watchPageErrors(page);
  await signInAsAdmin(page);
  await page.goto(`${baseUrl}/ui/account`);
  const resourcePath = "/v1/admin/policy/resources/palette-repository";
  const groupPath = "/v1/admin/policy/resource-groups/palette-collection";
  await browserManagementRequest(page, "/v1/admin/policy/resources", { method: "POST", body: {
    id: "palette-repository", displayName: "Searchable repository", resourceType: "git_repository",
    selector: { kind: "exact", value: "engineering/palette" }, allowedExecutionContexts: ["default"], enabled: true
  } });
  try {
    await browserManagementRequest(page, "/v1/admin/policy/resource-groups", { method: "POST", body: {
      id: "palette-collection", name: "Searchable collection", includedResourceIds: ["palette-repository"], excludedResourceIds: []
    } });
    try {
      // A fresh page ensures the palette loads these records from the broker.
      await page.goto(`${baseUrl}/ui/account`);
      await expect(page.getByRole("main")).toBeVisible();
      await page.keyboard.press("Control+k");
      const palette = page.getByRole("dialog", { name: "Command palette", exact: true });
      await palette.getByRole("combobox").fill("Searchable collection");
      const groups = palette.getByRole("group", { name: "Resource groups", exact: true });
      await expect(groups.getByRole("option", { name: /Searchable collection/ })).toBeVisible();
      await palette.getByRole("combobox").fill("engineering/palette");
      await groups.getByRole("option", { name: /Searchable collection/ }).click();
      await expect(page).toHaveURL(/\/ui\/admin\/catalog\/resource-groups\?item=palette-collection$/);
      const drawer = page.getByRole("complementary", { name: "Resource group Searchable collection", exact: true });
      await expect(drawer).toBeVisible();
      await expect(drawer.getByRole("link", { name: /Searchable repository/ })).toBeVisible();
      expect(pageErrors).toEqual([]);
    } finally {
      await browserManagementRequest(page, `${groupPath}?expectedVersion=1`, { method: "DELETE" });
    }
  } finally {
    await browserManagementRequest(page, `${resourcePath}?expectedVersion=1`, { method: "DELETE" });
  }
});

test("the portal fits a 1024px window and the command palette navigates", async ({ page }) => {
  const pageErrors = watchPageErrors(page);
  await page.setViewportSize({ width: 1024, height: 768 });
  await signInAsAdmin(page);
  for (const path of ["/ui/admin/policies", "/ui/admin/principals", "/ui/admin/catalog", "/ui/admin/audit", "/ui/access", "/ui/tokens", "/ui/admin/principals/admin"]) {
    await page.goto(`${baseUrl}${path}`);
    await expect(page.getByRole("main")).toBeVisible();
    await expectNoHorizontalOverflow(page);
    // Every top-bar control stays inside the window, and nothing in the bar
    // (tabs, runtime status) is scrolled or truncated out of view.
    const clipped = await page.getByRole("banner").evaluate((bar) => [
      ...[...bar.querySelectorAll("a, button, input")]
        .filter((element) => element.getClientRects().length > 0)
        .filter((element) => {
          const bounds = element.getBoundingClientRect();
          return bounds.right > window.innerWidth + 1 || bounds.left < -1;
        }),
      ...[...bar.querySelectorAll("*")]
        .filter((element) => element.getClientRects().length > 0 && getComputedStyle(element).overflowX !== "visible")
        // Visually hidden text (1px boxes) is intentional; anything else must fit.
        .filter((element) => element.clientWidth > 1 && element.scrollWidth > element.clientWidth + 1)
    ].map((element) => element.textContent || element.getAttribute("aria-label")));
    expect(clipped, path).toEqual([]);
  }
  await page.goto(`${baseUrl}/ui/admin/policies`);
  await expect(page.getByRole("main", { name: "Policies", exact: true })).toBeVisible();
  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog", { name: "Command palette", exact: true });
  await expect(palette).toBeVisible();
  await page.keyboard.type("principals");
  await expect(palette.getByRole("option").first()).toBeVisible();
  await palette.getByRole("option", { name: /^Principals/ }).first().click();
  await expect(page).toHaveURL(/\/ui\/admin\/principals/);
  await page.keyboard.press("Control+k");
  await page.keyboard.type("admin");
  await palette.getByRole("option", { name: /admin/ }).first().click();
  await expect(palette).toHaveCount(0);
  expect(pageErrors).toEqual([]);
});

async function writeBrokerFixture(root: string, port: number) {
  const secrets = brokerSecrets(root);
  await fs.writeFile(secrets.credentialKey, base64UrlByte(3));
  await fs.writeFile(secrets.hashKey, base64UrlByte(4));
  await fs.writeFile(secrets.csrfKey, base64UrlByte(5));
  await fs.writeFile(secrets.passwordPepper, base64UrlByte(6));
  await fs.writeFile(secrets.auditToken, "audit-service-token");
  await fs.writeFile(secrets.gitToken, "git-service-token");
  await fs.writeFile(secrets.trustedCaller, "portal-test-managed-client");
  await writeBrokerConfig(root, port);
}

async function writeBrokerConfig(root: string, port: number) {
  await fs.writeFile(
    path.join(root, "broker.toml"),
    brokerConfig({
      port,
      root,
      secrets: brokerSecrets(root)
    })
  );
}

function brokerConfig({
  port,
  root,
  secrets
}: {
  port: number;
  root: string;
  secrets: Record<string, string>;
}) {
  return `
[deployment]
environment = "development"

[identity]
mode = "required"
authority = "managed"

[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"

[identity.trusted_callers.portal_managed_client]
credential_ref = "file:${secrets.trustedCaller}"
credential_transport = "authorization_user"
username_namespace = "managed_linux"
context_mode = "fixed"
execution_context = "default"

[managed_store]
type = "sqlite"
path = ${tomlString(path.join(root, "managed-store.sqlite3"))}
require_registered_principal_for_invocation = false
auto_migrate = true

[execution_context]
allowed_values = ["default", "internal", "external"]
default_context = "default"

[credential_encryption]
active_key = "k1"

[[credential_encryption.keys]]
id = "k1"
provider = "file"
path = ${tomlString(secrets.credentialKey)}

[broker_tokens]
hash_key_ref = "file:${secrets.hashKey}"
default_agent_invoke_ttl = "37m"
default_user_manage_ttl = "41m"
default_admin_ttl = "43m"
max_self_issued_agent_invoke_ttl = "5h"
self_agent_invoke_ttl_options = ["37m", "5h", "never"]
admin_agent_invoke_ttl_options = ["37m", "never"]
user_manage_ttl_options = ["41m"]
admin_ttl_options = ["43m"]

[browser_auth]
enabled = true
public_origin = "http://127.0.0.1:${port}"
session_cookie_name = "aab_session"
csrf_header = "X-Agent-Access-CSRF"
csrf_key_ref = "file:${secrets.csrfKey}"
session_ttl = "8h"
allowed_return_paths = ["/ui"]

[browser_auth.local_password]
enabled = true
pepper_ref = "file:${secrets.passwordPepper}"
min_password_length = 8
max_failed_attempts = 3
lockout_ttl = "15m"

[portal]
enabled = true
mount_path = "/ui"
static_dir = ${tomlString(portalDist)}

[management]
enabled = true

[management.initial_admin]
mode = "create_if_empty"
principal_id = "admin"
initial_password = ${tomlString(initialAdminPassword)}

[mcp]
enabled = true
public_url = "http://127.0.0.1:${port}/mcp"

[credentials.connections.jira]
display_name = "Jira"
token_profile = "atlassian-api-token"

[credentials.per_user.jira]
type = "connection"
connection = "jira"

[credentials.service.confluence]
type = "basic_api_token"
username_ref = "file:${secrets.auditToken}"
token_ref = "file:${secrets.auditToken}"

[credentials.service.gitlab_git]
type = "bearer_token"
token_ref = "file:${secrets.gitToken}"

[providers.jira]
tenant_host = "jira.example.test"
allowed_upstream_hosts = ["https://jira.example.test/**"]

[providers.confluence]
tenant_host = "wiki.example.test"
allowed_upstream_hosts = ["https://wiki.example.test/**"]

[gateways.gitlab_git]
kind = "git_http"
display_name = "GitLab Git"
broker_hosts = ["git.local.test"]
upstream_base_url = "https://gitlab.example.test"
allowed_upstream_hosts = ["https://gitlab.example.test/**"]
auth_modes = ["basic_broker_token"]
credential_modes = ["service"]

[gateways.gitlab_git.git]
allow_fetch = true
allow_push = true

[policy]
authority = "managed"
default_decision = "deny"

[audit]
type = "sqlite"
path = ${tomlString(path.join(root, "audit.sqlite"))}

[limits]
upload_spool_dir = ${tomlString(path.join(root, "upload-spool"))}

[limits.invocations]
default = { requests = 1000, window = "1m" }
`;
}

async function stopBroker() {
  if (!broker || broker.exitCode !== null) return;
  broker.kill("SIGTERM");
  const timeout = delay(5_000).then(() => {
    if (broker && broker.exitCode === null) broker.kill("SIGKILL");
  });
  await Promise.race([once(broker, "exit"), timeout]);
}

function base64UrlByte(value: number) {
  return Buffer.from(Array(32).fill(value)).toString("base64url");
}

function tomlString(value: string) {
  return JSON.stringify(value);
}

function delay(ms: number) {
  return new Promise<void>((resolve) => setTimeout(resolve, ms));
}
