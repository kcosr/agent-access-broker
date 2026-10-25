import { TOKEN_INPUT } from "../unit/credential-input.fixture";
import { expect, test, type Page } from "@playwright/test";
import {
  COMMAND_RESOURCE_TYPES,
  PROTOTYPE_NAMES,
  PROTOTYPE_RESOURCE_TYPES,
  REFRESHED_RESOURCE_TYPES,
  commandAccepted,
  commandDiscovered,
  commandPolicyService,
  commandRefreshed,
  prototypeNamedDiscovered
} from "../unit/command-import.fixture";
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
  await expect(main).toContainText("Accept the command manifest before setting its credential");
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

test("acceptance confirmation lists classification changes and the broker's refusal list is authoritative", async ({ page }) => {
  const api = await mockCommandImportApi(page, commandRefreshed());
  api.acceptances.push({ result: commandAccepted() });
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  const dialog = review(page);
  const accept = dialog.getByRole("button", { name: "Accept selected actions", exact: true });
  const confirmation = dialog.getByLabel("I reviewed the affected grants and approve these action changes.", { exact: true });
  const changes = dialog.getByRole("list", { name: "Classification changes", exact: true });
  // A grant on the changed issue.search needs confirmation, which lists the class changes.
  await dialog.getByRole("checkbox", { name: "Accept issue.search", exact: true }).check();
  await expect(dialog.getByText("Existing grants to review: grant-search", { exact: true })).toBeVisible();
  await expect(changes.getByRole("listitem")).toHaveText(["issue.search changes from read to write"]);
  await expect(dialog.getByText(/^Read-only identity access will include/)).toHaveCount(0);
  await dialog.getByLabel("Effects for issue.search", { exact: true }).selectOption("read");
  await dialog.getByRole("checkbox", { name: "Accept issue.comment", exact: true }).check();
  await dialog.getByLabel("Effects for issue.comment", { exact: true }).selectOption("read");
  await dialog.getByLabel("Effects for issue.create", { exact: true }).selectOption("read");
  // Unchanged issue.view is omitted; the added action comes from no class.
  await expect(changes.getByRole("listitem")).toHaveText(["issue.comment is added as a read", "issue.create changes from write to read"]);
  await expect(dialog.getByText("Read-only identity access will include: issue.comment, issue.create.", { exact: true })).toBeVisible();
  await expect(accept).toBeDisabled();
  // Without a grant the portal can see, no confirmation is asked for before the Broker decides.
  await dialog.getByRole("checkbox", { name: "Accept issue.search", exact: true }).uncheck();
  await expect(dialog.getByText(/^Existing grants to review/)).toHaveCount(0);
  await expect(accept).toBeEnabled();
  // The Broker refuses for a grant the preview did not list; its classification changes replace the portal's.
  api.acceptConfirmation = [
    { action: "issue.comment", from: null, to: "read" },
    { action: "issue.create", from: "write", to: "read" },
    { action: "issue.view", from: "write", to: "read" }
  ];
  await accept.click();
  await expect(dialog.getByRole("alert")).toHaveText("The broker found existing grants that these changes affect. Review the changes and confirm to accept them.");
  await expect(changes.getByRole("listitem")).toHaveText(["issue.comment is added as a read", "issue.create changes from write to read", "issue.view changes from write to read"]);
  await expect(dialog.getByText("Read-only identity access will include: issue.comment, issue.create, issue.view.", { exact: true })).toBeVisible();
  await expect(confirmation).not.toBeChecked();
  await expect(accept).toBeDisabled();
  // Editing the selections drops the refusal; the next acceptance asks the Broker again.
  await dialog.getByLabel("Effects for issue.create", { exact: true }).selectOption("write");
  await expect(dialog.getByText(/^Existing grants to review/)).toHaveCount(0);
  await dialog.getByLabel("Effects for issue.create", { exact: true }).selectOption("read");
  await accept.click();
  await expect(changes.getByRole("listitem")).toHaveCount(3);
  await confirmation.check();
  await accept.click();
  await expect(dialog).toHaveCount(0);
  const selections = [
    { source: { name: "issue.view" }, action: "issue.view", readOnly: true },
    { source: { name: "issue.create" }, action: "issue.create", readOnly: true },
    { source: { name: "issue.comment" }, action: "issue.comment", readOnly: true }
  ];
  expect(api.accepted.map((body) => [body.selections, body.confirmAffectedGrants])).toEqual([[selections, false], [selections, false], [selections, true]]);
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
  await dialog.getByLabel("Username", { exact: true }).fill(" ");
  await expect(dialog.getByRole("button", { name: "Save credential", exact: true })).toBeDisabled();
  await dialog.getByLabel("Username", { exact: true }).fill(" svc-tickets ");
  await dialog.getByRole("button", { name: "Save credential", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(api.credentials).toEqual([{ purpose: "execution", body: { expectedVersion: 5, expectedCatalogRevision: 6, token: "svc-example", username: "svc-tickets" } }]);
  expect(api.errors).toEqual([]);
});

test("a token execution credential is saved without a username", async ({ page }) => {
  const accepted = commandAccepted();
  accepted.service.acceptedMetadata = { ...accepted.service.acceptedMetadata!, credential: { kind: "token", modes: ["service", "per_user"] } };
  accepted.service.credentialInputs.execution = { ...TOKEN_INPUT, inputPolicy: "command_stdin" };
  const api = await mockCommandImportApi(page, accepted);
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
  await page.getByRole("button", { name: "Rotate execution credential", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Rotate execution credential", exact: true });
  await expect(dialog.getByLabel("Username", { exact: true })).toHaveCount(0);
  await dialog.getByLabel("Token", { exact: true }).fill(" ");
  await expect(dialog.getByRole("button", { name: "Save credential", exact: true })).toBeDisabled();
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

test("type ids and attribute names that are Object.prototype members are previewed, accepted and edited", async ({ page }) => {
  const api = await mockCommandImportApi(page, prototypeNamedDiscovered());
  api.acceptances.push({ result: commandAccepted(), resourceTypes: [...COMMAND_RESOURCE_TYPES, ...PROTOTYPE_RESOURCE_TYPES] });
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  const dialog = review(page);
  // The proposed Broker type IDs are kept: no override is sent.
  for (const [id, brokerType] of [["constructor", "ticketing_constructor"], ["__proto__", "ticketing_proto__"], ["toString", "ticketing_tostring"]]) {
    await expect(dialog.getByLabel(`Broker type ID for ${id}`, { exact: true })).toHaveValue(brokerType);
  }
  await dialog.getByRole("checkbox", { name: "Accept issue.view", exact: true }).check();
  await dialog.getByLabel("Effects for issue.view", { exact: true }).selectOption("read");
  await dialog.getByRole("button", { name: "Accept selected actions", exact: true }).click();
  await expect(page.getByText("1 action accepted", { exact: true })).toBeVisible();
  expect(api.accepted).toHaveLength(1);
  expect(api.accepted[0]).not.toHaveProperty("resourceTypeIds");

  // Attributes named after prototype members start empty, and a required one is asked for.
  await page.getByRole("complementary", { name: "Catalog", exact: true }).getByRole("link", { name: /^Resources/ }).click();
  await page.getByRole("main", { name: "Resources", exact: true }).getByRole("button", { name: "Add resource", exact: true }).first().click();
  const drawer = page.getByRole("complementary", { name: "Add resource", exact: true });
  await drawer.getByLabel("Resource type", { exact: true }).selectOption("ticketing_constructor");
  for (const name of PROTOTYPE_NAMES) await expect(drawer.getByLabel(`Attribute ${name}`, { exact: true })).toHaveValue("");
  await drawer.getByLabel("Canonical identifier", { exact: true }).fill("C1");
  await drawer.getByRole("checkbox", { name: "internal", exact: true }).check();
  await drawer.getByRole("button", { name: "Save resource", exact: true }).click();
  await expect(drawer).toContainText("Enter the attribute tostring.");
  expect(api.createdResources).toEqual([]);
  await drawer.getByLabel("Attribute toString", { exact: true }).fill("ts-value");
  await drawer.getByLabel("Attribute __proto__", { exact: true }).fill("proto-value");
  await drawer.getByRole("button", { name: "Save resource", exact: true }).click();
  await expect(page.getByText("Resource added", { exact: true })).toBeVisible();
  expect(JSON.stringify(api.createdResources[0]?.attributes)).toBe('{"__proto__":"proto-value","toString":"ts-value"}');
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

test("an exclusion opt-out explains blocking group memberships and prevents acceptance", async ({ page }) => {
  const data = commandRefreshed();
  data.preview!.manifest.serviceMetadata!.resourceTypes[0]!.supportsExclusions = false;
  data.resourceTypeChanges = [{ ...data.resourceTypeChanges![0]!, details: ["exclusions_unsupported"], blocked: true, blockingGroups: [{ id: "engineering", resourceIds: ["ops"] }] }];
  const api = await mockCommandImportApi(page, data);
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  const dialog = review(page);
  const project = dialog.getByRole("group", { name: "Resource type project", exact: true });
  await expect(project).toContainText("exclusions not supported (inclusions only)");
  await expect(project).toContainText("Changed: exclusions no longer supported.");
  await expect(project).toContainText("remove the listed exclusions from these groups");
  await expect(project.getByRole("link", { name: "engineering", exact: true })).toHaveAttribute("href", "/ui/admin/catalog/resource-groups?item=engineering");
  await expect(project.getByRole("link", { name: "ops", exact: true })).toHaveAttribute("href", "/ui/admin/catalog/resources?item=ops");
  await expect(dialog.getByRole("button", { name: "Accept selected actions", exact: true })).toBeDisabled();
  expect(api.accepted).toEqual([]);
  expect(api.errors).toEqual([]);
});

test("a transactional exclusion blocker identifies group memberships to remove", async ({ page }) => {
  const api = await mockCommandImportApi(page, commandRefreshed());
  api.acceptBlocked = { resourceGroups: [{ type: "ticketing_project", id: "engineering", resourceIds: ["ops"] }] };
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  const dialog = review(page);
  await dialog.getByRole("button", { name: "Accept selected actions", exact: true }).click();
  const alert = dialog.getByRole("alert");
  await expect(alert).toContainText("Remove the listed exclusions from these groups, then refresh the preview");
  await expect(alert).not.toContainText("Edit or delete them");
  await expect(alert.getByRole("link", { name: "engineering", exact: true })).toHaveAttribute("href", "/ui/admin/catalog/resource-groups?item=engineering");
  await expect(alert.getByRole("link", { name: "ops", exact: true })).toHaveAttribute("href", "/ui/admin/catalog/resources?item=ops");
  expect(api.errors).toEqual([]);
});


for (const [before, after] of [[false, true], [true, false]] as const) {
  test(`download output changes from ${before} to ${after} require approval with grant confirmation`, async ({ page }) => {
    const data = commandRefreshed();
    const prior = data.service.actions[0];
    const next = data.preview!.manifest.tools[0];
    data.service.actions = [{ ...prior, status: "quarantined", definition: { ...prior.definition, download: before } }];
    data.preview!.manifest.tools = [{ ...next, definition: { ...next.definition, download: after } }];
    data.resourceTypeChanges = [];
    data.affectedGrants = ["grant-download"];
    data.affectedGrantsByAction = { "issue.view": ["grant-download"] };
    const accepted = commandAccepted();
    accepted.service.actions = [{ ...prior, definition: { ...prior.definition, download: after } }];
    const api = await mockCommandImportApi(page, data);
    api.acceptances.push({ result: accepted });
    await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
    await page.getByRole("button", { name: "Review preview", exact: true }).click();
    const dialog = review(page);
    const row = actionRow(page, "issue.view");
    await expect(row).toContainText("Changed");
    await expect(row).toContainText(`Output: ${after ? "File download" : "JSON"}`);
    await expect(row.getByRole("checkbox", { name: "Accept issue.view", exact: true })).not.toBeChecked();
    await expect(row.getByLabel("Effects for issue.view", { exact: true })).toHaveValue("write");
    await row.getByText("Schemas and source", { exact: true }).click();
    await expect(row.locator("pre")).toContainText(`"download": ${after}`);
    await row.getByRole("checkbox", { name: "Accept issue.view", exact: true }).check();
    await row.getByLabel("Effects for issue.view", { exact: true }).selectOption("read");
    const accept = dialog.getByRole("button", { name: "Accept selected actions", exact: true });
    await expect(dialog).toContainText("grant-download");
    await expect(accept).toBeDisabled();
    await dialog.getByRole("checkbox", { name: "I reviewed the affected grants and approve these action changes.", exact: true }).check();
    await accept.click();
    await expect(dialog).toHaveCount(0);
    expect(api.accepted[0]).toMatchObject({
      selections: [{ source: { name: "issue.view" }, action: "issue.view", readOnly: true }],
      confirmAffectedGrants: true
    });
    // The server reconstructs the output contract from the persisted preview.
    expect(JSON.stringify(api.accepted[0])).not.toContain("download");
    expect(api.errors).toEqual([]);
  });
}

test("command audit declarations show accepted and proposed selectors without invocation values", async ({ page }) => {
  const data = commandRefreshed();
  const prior = data.service.actions[0];
  const next = data.preview!.manifest.tools[0];
  const rule = { key: "query", label: "Requested query", pointer: "/query", capture: "value", shape: "scalar", kind: "query", maxBytes: 1024, overflow: "prefix", role: "fact", display: "primary" };
  prior.definition.annotations = { command: { auditInputs: [rule] } };
  next.definition.annotations = { command: { auditInputs: [{ ...rule, maxBytes: 4096 }, { key: "body", pointer: "/body", capture: "omit" }, { key: "files", pointer: "/files", capture: "records", kind: "records", label: "Files", role: "fact", display: "detail", fields: [{ ...rule, key: "name", label: "Filename", pointer: "/name", kind: "text" }] }] } };
  const api = await mockCommandImportApi(page, data);
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  const row = actionRow(page, "issue.view");
  await expect(row.getByRole("checkbox", { name: "Accept issue.view", exact: true })).not.toBeChecked();
  await row.getByText("Audit inputs", { exact: true }).click();
  await expect(row).toContainText("Unlisted inputs are omitted");
  await expect(row).toContainText("including service managers");
  await expect(row).toContainText("Audit declaration changed");
  await expect(row.getByRole("list", { name: "Audit declaration changes", exact: true })).toContainText("Changed: Requested query");
  await expect(row.getByRole("table", { name: "Accepted audit inputs", exact: true })).toContainText("1024 bytes / prefix");
  const proposed = row.getByRole("table", { name: "Proposed audit inputs", exact: true });
  await expect(proposed).toContainText("4096 bytes / prefix");
  await expect(proposed).toContainText("scalar / query");
  await expect(proposed).toContainText("/files [each item]");
  await expect(proposed).toContainText("/name");
  await expect(proposed).toContainText("/body");
  await expect(proposed).not.toContainText("inputSchema");
  expect(api.errors).toEqual([]);
});

test("installed command action details retain the accepted audit declaration", async ({ page }) => {
  const data = commandAccepted();
  const action = data.service.actions.find(action => action.definition.action === "issue.search")!;
  action.definition.annotations = { command: { auditInputs: [{ key: "query", label: "Requested query", pointer: "/query", capture: "value", shape: "scalar", kind: "query", maxBytes: 4096, overflow: "prefix", role: "fact", display: "primary" }] } };
  const api = await mockCommandImportApi(page, data);
  await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing`);
  await page.getByRole("table", { name: "Ticketing actions", exact: true }).getByRole("link", { name: "issue.search", exact: true }).click();
  const drawer = page.getByRole("complementary", { name: "Action issue.search", exact: true });
  await drawer.getByText("Audit inputs", { exact: true }).click();
  const table = drawer.getByRole("table", { name: "Accepted audit inputs", exact: true });
  await expect(table).toContainText("/query");
  await expect(table).toContainText("4096 bytes / prefix");
  await expect(drawer.getByRole("table", { name: "Proposed audit inputs", exact: true })).toHaveCount(0);
  expect(api.errors).toEqual([]);
});
