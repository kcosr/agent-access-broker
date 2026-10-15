import { expect, test, type Page } from "@playwright/test";
import { COMMAND_RESOURCE_TYPES, REFRESHED_RESOURCE_TYPES, commandAccepted, commandDiscovered, commandPolicyService, commandRefreshed } from "../unit/command-import.fixture";
import { mockCommandImportApi } from "./support/command-import-api";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

// These exercise the command import editor, preview, Import tab and Actions
// tab against explicit management API fixtures shaped like a command import of
// the reference command. No Broker starts and no command runs.
let assets: PortalAssets;
let baseUrl: string;

test.beforeAll(async () => {
  assets = await servePortalAssets();
  baseUrl = assets.baseUrl;
});
test.afterAll(async () => {
  await assets.close();
});

const review = (page: Page) => page.getByRole("dialog", { name: "Review discovered actions", exact: true });
const actionRow = (page: Page, action: string) => review(page).locator(".pt-catalog-review-item").filter({ has: page.getByRole("checkbox", { name: `Accept ${action}`, exact: true }) });

test("new imports pick an approved command by name, with credential modes or none", async ({ page }) => {
  const api = await mockCommandImportApi(page);
  await page.goto(`${baseUrl}/ui/admin/catalog?import=1`);
  const dialog = page.getByRole("dialog", { name: "Import service", exact: true });
  await dialog.getByLabel("Import type", { exact: true }).selectOption("command");
  const command = dialog.getByLabel("Command", { exact: true });
  await expect(command.locator("option")).toHaveText(["Select an approved command", "ticketing", "deploy-tools"]);
  await expect(dialog).not.toContainText("/opt/");
  await command.selectOption("ticketing");
  // The service ID follows the command name until edited.
  await expect(dialog.getByLabel("Service ID", { exact: true })).toHaveValue("ticketing");
  await dialog.getByLabel("Display name", { exact: true }).fill("Ticketing");
  await expect(dialog).toContainText("No credential: for a command that needs none.");
  await dialog.getByLabel("Shared service credential", { exact: true }).check();
  await dialog.getByLabel("Personal credentials for each user", { exact: true }).check();
  await dialog.getByRole("button", { name: "Create draft", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/catalog\/services\/ticketing\/import$/);
  expect(api.created).toEqual([
    {
      service: "ticketing",
      displayName: "Ticketing",
      adapterKind: "command",
      endpoint: "command:ticketing",
      connectionSettings: {},
      executionBindings: [
        { ownerMode: "service", mechanism: "static_token", delivery: { kind: "stdin" }, status: "configured" },
        { ownerMode: "per_user", mechanism: "static_token", delivery: { kind: "stdin" }, status: "configured" }
      ],
      discovery: { kind: "anonymous" },
      transportAuth: false
    }
  ]);
  const main = page.getByRole("main", { name: "Ticketing", exact: true });
  await expect(main).toContainText("Each agent call runs the approved command once, with the request on its stdin.");
  await expect(main).toContainText("Accept a discovery preview first");
  await expect(main.getByRole("button", { name: "Set execution credential", exact: true })).toBeDisabled();
  await expect(main).toContainText("Accept the command's manifest first; it declares the credential kind.");
  expect(api.errors).toEqual([]);
});

test("a credential-free draft binds no credential", async ({ page }) => {
  const api = await mockCommandImportApi(page);
  api.commandImports = ["ticketing"];
  await page.goto(`${baseUrl}/ui/admin/catalog?import=1`);
  const dialog = page.getByRole("dialog", { name: "Import service", exact: true });
  await dialog.getByLabel("Import type", { exact: true }).selectOption("command");
  // A single approved command is preselected.
  await expect(dialog.getByLabel("Command", { exact: true })).toHaveValue("ticketing");
  await dialog.getByLabel("Service ID", { exact: true }).fill("ticketing-notes");
  await dialog.getByLabel("Display name", { exact: true }).fill("Ticketing notes");
  await dialog.getByRole("button", { name: "Create draft", exact: true }).click();
  await expect.poll(() => api.created.length).toBe(1);
  expect(api.created[0]).toMatchObject({ service: "ticketing-notes", endpoint: "command:ticketing", executionBindings: [], discovery: { kind: "anonymous" } });
  expect(api.errors).toEqual([]);
});

test("without approved commands the editor explains the operator step", async ({ page }) => {
  const api = await mockCommandImportApi(page);
  api.commandImports = [];
  await page.goto(`${baseUrl}/ui/admin/catalog?import=1`);
  const dialog = page.getByRole("dialog", { name: "Import service", exact: true });
  await dialog.getByLabel("Import type", { exact: true }).selectOption("command");
  await expect(dialog).toContainText("No approved commands");
  await expect(dialog).toContainText("[command_imports.<name>]");
  await expect(dialog.getByRole("button", { name: "Create draft", exact: true })).toBeDisabled();
  expect(api.errors).toEqual([]);
});

test("discovery previews the manifest, editable type IDs and who checks each action's resources", async ({ page }) => {
  const api = await mockCommandImportApi(page, commandDiscovered());
  api.current!.preview = null;
  api.discoveries.push(commandDiscovered());
  api.acceptances.push({ result: commandAccepted() });
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
  await page.getByRole("button", { name: "Discover actions", exact: true }).click();
  const dialog = review(page);
  await expect(dialog).toBeVisible();
  const manifest = dialog.getByRole("region", { name: "Command manifest", exact: true });
  await expect(manifest).toContainText("1.4.0");
  await expect(manifest).toContainText("Username and token · shared or personal");
  await expect(manifest).toContainText("Supported");
  await expect(actionRow(page, "issue.view")).toContainText("Resources checked by: Broker · Project, from project");
  await expect(actionRow(page, "issue.search")).toContainText("Resources checked by: Command · Projects");
  await expect(actionRow(page, "whoami")).toContainText("Resources checked by: Command · no resource type");
  await expect(actionRow(page, "issue.search").getByText("Resources checked by:")).toHaveAccessibleDescription(/the Broker cannot check that/);
  // A draft needs a selection; invalid Broker type IDs block acceptance.
  await expect(dialog.getByRole("button", { name: "Accept selected actions", exact: true })).toBeDisabled();
  const typeId = dialog.getByLabel("Broker type ID for project", { exact: true });
  await expect(typeId).toHaveValue("ticketing_project");
  await typeId.fill("Tickets");
  await dialog.getByRole("checkbox", { name: "Accept issue.view", exact: true }).check();
  await expect(dialog.getByRole("button", { name: "Accept selected actions", exact: true })).toBeDisabled();
  await expect(manifest).toContainText("Use up to 64 lowercase letters");
  await typeId.fill("tickets_project");
  await dialog.getByLabel("Effects for issue.view", { exact: true }).selectOption("read");
  await dialog.getByRole("checkbox", { name: "Accept issue.search", exact: true }).check();
  await dialog.getByRole("button", { name: "Accept selected actions", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(api.accepted).toEqual([
    {
      expectedVersion: 2,
      expectedCatalogRevision: 4,
      manifestHash: "manifest-1.4.0",
      selections: [
        { source: { name: "issue.view" }, action: "issue.view", readOnly: true },
        { source: { name: "issue.search" }, action: "issue.search", readOnly: false }
      ],
      confirmAffectedGrants: false,
      resourceTypeIds: { project: "tickets_project" }
    }
  ]);
  expect(api.errors).toEqual([]);
});

test("a refresh lists type changes and may accept only the metadata and type changes", async ({ page }) => {
  const api = await mockCommandImportApi(page, commandAccepted());
  api.discoveries.push(commandRefreshed());
  api.acceptances.push({ result: commandAccepted(), effects: { deletedAttributeValues: [], droppedTypes: ["ticketing_queue"] } });
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
  const main = page.getByRole("main", { name: "Ticketing", exact: true });
  await expect(main).toContainText("Imported at version");
  await expect(main).toContainText("Queue ticketing_queue");
  await page.getByRole("button", { name: "Refresh discovery", exact: true }).click();
  const dialog = review(page);
  const manifest = dialog.getByRole("region", { name: "Command manifest", exact: true });
  await expect(manifest).toContainText("This command declares OAuth, which this Broker does not support yet; static credentials still work.");
  await expect(manifest).toContainText("1.5.0 · imported at version 1.4.0");
  const project = manifest.getByRole("group", { name: "Resource type project", exact: true });
  await expect(project).toContainText("Changed: new optional attribute.");
  await expect(project).toContainText("Applied on acceptance.");
  await expect(project).toContainText("Broker type ID ticketing_project");
  const queue = manifest.getByRole("group", { name: "Resource type queue", exact: true });
  await expect(queue).toContainText("Removed");
  await expect(queue).toContainText("Kept for its 1 resource; it accepts no new resources.");
  await expect(queue).toContainText("Resources: triage-queue.");
  await expect(actionRow(page, "issue.search")).toContainText("Changed");
  await expect(dialog.getByRole("region", { name: "Unavailable actions and retained identities", exact: true })).toContainText("whoami · Removed");
  // Deselecting every action leaves a metadata-only acceptance.
  for (const action of ["issue.view", "issue.create"]) await dialog.getByRole("checkbox", { name: `Accept ${action}`, exact: true }).uncheck();
  await expect(dialog).toContainText("No actions selected: accepting applies only the command's metadata and resource type changes.");
  await dialog.getByRole("button", { name: "Accept selected actions", exact: true }).click();
  await expect(page.getByText("Command metadata and type changes accepted; dropped ticketing_queue", { exact: true })).toBeVisible();
  expect(api.accepted).toEqual([{ expectedVersion: 5, expectedCatalogRevision: 6, manifestHash: "manifest-1.5.0", selections: [], confirmAffectedGrants: false }]);
  expect(api.errors).toEqual([]);
});

test("a refused acceptance lists the retained grants or the stored resources to fix", async ({ page }) => {
  const api = await mockCommandImportApi(page, commandRefreshed());
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  const dialog = review(page);
  const alert = dialog.getByRole("alert");
  // Retained grants the change would leave invalid, each once by reference.
  api.acceptBlocked = {
    affectedGrants: [
      { id: "grant-search", reasonCode: "credential_mode_unsupported", reason: "issue.search no longer supports per_user" },
      { id: "toml:0", reasonCode: "credential_mode_invalid", reason: "policy.grants[0] subjects[0] ...; policy.grants[0] subjects[1] ..." }
    ]
  };
  await dialog.getByRole("button", { name: "Accept selected actions", exact: true }).click();
  await expect(alert).toContainText("This change would leave retained grants invalid. Update or remove them first:");
  await expect(alert).not.toContainText("Stored resources");
  await expect(alert.getByRole("listitem")).toHaveText(["grant-search: issue.search no longer supports per_user", "toml:0: policy.grants[0] subjects[0] ...; policy.grants[0] subjects[1] ..."]);
  await expect(alert.getByRole("link", { name: "grant-search", exact: true })).toHaveAttribute("href", "/ui/admin/policies?grant=grant-search");
  await expect(alert.getByRole("link", { name: "toml:0", exact: true })).toHaveAttribute("href", "/ui/admin/policies?grant=toml%3A0");
  // Stored resources the type changes no longer fit, in a separate refusal.
  api.acceptBlocked = { resources: [{ type: "ticketing_project", id: "legacy" }, { type: "ticketing_project", id: "web" }] };
  await dialog.getByRole("button", { name: "Accept selected actions", exact: true }).click();
  await expect(alert).toContainText("Stored resources no longer fit these resource type changes.");
  await expect(alert).not.toContainText("retained grants");
  await expect(alert.getByRole("listitem")).toHaveText(["Projects ticketing_project: legacy, web"]);
  await expect(alert.getByRole("link", { name: "legacy", exact: true })).toHaveAttribute("href", "/ui/admin/catalog/resources?item=legacy");
  expect(api.errors).toEqual([]);
});

test("the Actions tab shows who checks each action's resources", async ({ page }) => {
  const api = await mockCommandImportApi(page, commandAccepted());
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing`);
  const table = page.getByRole("table", { name: "Ticketing actions", exact: true });
  await expect(table.getByRole("columnheader", { name: "Resources checked by", exact: true })).toBeVisible();
  await expect(table.getByRole("columnheader", { name: "Scope", exact: true })).toHaveCount(0);
  await expect(table.getByRole("row", { name: /issue\.view/ })).toContainText("Broker · Project");
  await expect(table.getByRole("row", { name: /issue\.search/ })).toContainText("Command · Projects");
  await expect(table.getByRole("row", { name: /whoami/ })).toContainText("Command · no resource type");
  await table.getByRole("link", { name: "issue.search", exact: true }).click();
  const drawer = page.getByRole("complementary", { name: "Action issue.search", exact: true });
  await expect(drawer).toContainText("Checked by");
  await expect(drawer).toContainText("Projects ticketing_project");
  await expect(drawer).toContainText("the Broker cannot check that");
  expect(api.errors).toEqual([]);
});

test("the Actions tab takes who checks resources from the Broker's policy catalog", async ({ page }) => {
  const api = await mockCommandImportApi(page, commandAccepted());
  // The Broker's answer wins over the portal's reading of the stored declaration.
  const catalog = commandPolicyService(commandAccepted());
  catalog.actions = catalog.actions.map((action) => (action.action === "issue.view" ? { ...action, resourcesCheckedBy: "command" as const } : action));
  await page.route("**/v1/admin/policy/catalog", (route) =>
    route.fulfill({ json: { ok: true, result: { services: [catalog], resources: [], resourceGroups: [], executionContexts: { allowedValues: ["internal", "external"], defaultContext: "internal", contextRequired: false }, subjects: { users: [], groups: [], anonymous: false } } } })
  );
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing`);
  const table = page.getByRole("table", { name: "Ticketing actions", exact: true });
  await expect(table.getByRole("row", { name: /issue\.view/ })).toContainText("Command · Projects");
  await expect(table.getByRole("row", { name: /issue\.create/ })).toContainText("Broker · Project");
  expect(api.errors).toEqual([]);
});

test("a username-and-token execution credential is saved with its username", async ({ page }) => {
  const api = await mockCommandImportApi(page, commandAccepted());
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
  await page.getByRole("button", { name: "Rotate execution credential", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Rotate execution credential", exact: true });
  await expect(dialog.getByRole("button", { name: "Save credential", exact: true })).toBeDisabled();
  await dialog.getByLabel("Token", { exact: true }).fill("svc-example");
  await expect(dialog.getByRole("button", { name: "Save credential", exact: true })).toBeDisabled();
  await dialog.getByLabel("Username", { exact: true }).fill("svc-tickets");
  await dialog.getByRole("button", { name: "Save credential", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(api.credentials).toEqual([{ purpose: "execution", body: { expectedVersion: 5, expectedCatalogRevision: 6, token: "svc-example", username: "svc-tickets" } }]);
  expect(api.errors).toEqual([]);
});

test("a token execution credential is saved without a username", async ({ page }) => {
  const accepted = commandAccepted();
  accepted.service.acceptedMetadata = { ...accepted.service.acceptedMetadata!, credential: { kind: "token", modes: ["service", "per_user"] } };
  const api = await mockCommandImportApi(page, accepted);
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
  await page.getByRole("button", { name: "Rotate execution credential", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Rotate execution credential", exact: true });
  await expect(dialog.getByLabel("Username", { exact: true })).toHaveCount(0);
  await dialog.getByLabel("Token", { exact: true }).fill("svc-token-only");
  await dialog.getByRole("button", { name: "Save credential", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(api.credentials).toEqual([{ purpose: "execution", body: { expectedVersion: 5, expectedCatalogRevision: 6, token: "svc-token-only" } }]);
  expect(api.errors).toEqual([]);
});

test("accepted resource types reach the resource editor without a reload", async ({ page }) => {
  // Before the first acceptance the Broker registers none of the command's types.
  const api = await mockCommandImportApi(page, commandDiscovered());
  api.resourceTypes = [];
  api.acceptances.push({ result: commandAccepted(), resourceTypes: COMMAND_RESOURCE_TYPES });
  api.discoveries.push(commandRefreshed());
  api.acceptances.push({ result: commandAccepted(), resourceTypes: REFRESHED_RESOURCE_TYPES });
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
  await page.evaluate(() => Object.assign(window, { loadedOnce: true }));
  const sidebar = page.getByRole("complementary", { name: "Catalog", exact: true });
  const addResource = async () => {
    await sidebar.getByRole("link", { name: /^Resources/ }).click();
    await page.getByRole("main", { name: "Resources", exact: true }).getByRole("button", { name: "Add resource", exact: true }).first().click();
    return page.getByRole("complementary", { name: "Add resource", exact: true });
  };

  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  await review(page).getByRole("checkbox", { name: "Accept issue.view", exact: true }).check();
  await review(page).getByLabel("Effects for issue.view", { exact: true }).selectOption("read");
  await review(page).getByRole("button", { name: "Accept selected actions", exact: true }).click();
  await expect(page.getByText("1 action accepted", { exact: true })).toBeVisible();
  // Client-side navigation: the new type and its attributes are offered.
  let drawer = await addResource();
  const type = drawer.getByLabel("Resource type", { exact: true });
  await type.selectOption("ticketing_project");
  await expect(drawer.getByLabel("Region", { exact: true })).toBeVisible();
  await expect(drawer.getByLabel("Webhook secret", { exact: true })).toBeVisible();
  await drawer.getByLabel("Canonical identifier", { exact: true }).fill("OPS");
  await drawer.getByLabel("Region", { exact: true }).fill("eu-1");
  await drawer.getByRole("checkbox", { name: "internal", exact: true }).check();
  await drawer.getByRole("button", { name: "Save resource", exact: true }).click();
  await expect(page.getByText("Resource added", { exact: true })).toBeVisible();
  expect(api.createdResources).toEqual([
    { resourceType: "ticketing_project", selector: { kind: "exact", value: "OPS" }, displayName: null, allowedExecutionContexts: ["internal"], enabled: true, attributes: { region: "eu-1" } }
  ]);

  // A metadata-only acceptance of the `v2` refresh adds an attribute and
  // retires `queue`; the editor follows without a reload as well.
  await sidebar.getByRole("link", { name: /^Ticketing/ }).click();
  await page.getByRole("navigation", { name: "Ticketing sections", exact: true }).getByRole("link", { name: "Import", exact: true }).click();
  await page.getByRole("button", { name: "Refresh discovery", exact: true }).click();
  for (const action of ["issue.view", "issue.create"]) await review(page).getByRole("checkbox", { name: `Accept ${action}`, exact: true }).uncheck();
  await review(page).getByRole("button", { name: "Accept selected actions", exact: true }).click();
  await expect(page.getByText("Command metadata and type changes accepted", { exact: true })).toBeVisible();
  drawer = await addResource();
  await expect(drawer.getByLabel("Resource type", { exact: true }).locator('option[value="ticketing_queue"]')).toHaveCount(0);
  await drawer.getByLabel("Resource type", { exact: true }).selectOption("ticketing_project");
  await expect(drawer.getByLabel("Owner", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => (window as unknown as { loadedOnce?: boolean }).loadedOnce)).toBe(true);
  expect(api.errors).toEqual([]);
});

test("a removed imported type accepts no new resources", async ({ page }) => {
  const api = await mockCommandImportApi(page, commandAccepted());
  api.resourceTypes = REFRESHED_RESOURCE_TYPES;
  await page.goto(`${baseUrl}/ui/admin/catalog/resources?item=new`);
  const type = page.getByRole("complementary", { name: "Add resource", exact: true }).getByLabel("Resource type", { exact: true });
  await expect(type.locator('option[value="ticketing_project"]')).toHaveText("Project");
  await expect(type.locator('option[value="ticketing_queue"]')).toHaveCount(0);
  expect(api.errors).toEqual([]);
});
