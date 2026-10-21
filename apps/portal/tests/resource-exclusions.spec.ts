// Mocked management contract: exercises inclusion/exclusion eligibility and a
// stale editor after another operator changes a command's type capability.
import { expect, test, type Page } from "@playwright/test";
import type { ResourceRecord } from "../src/types";
import { COMMAND_RESOURCE_TYPES, commandAccepted } from "../unit/command-import.fixture";
import { mockCommandImportApi } from "./support/command-import-api";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

let assets: PortalAssets;
test.beforeAll(async () => { assets = await servePortalAssets(); });
test.afterAll(async () => { await assets.close(); });

const resources: ResourceRecord[] = [
  { id: "triage", resourceType: "ticketing_queue", displayName: "Inclusion-only queue", selector: { kind: "exact", value: "triage" }, allowedExecutionContexts: ["external"], enabled: false, version: 1 },
  { id: "ops", resourceType: "ticketing_project", displayName: "Operations project", selector: { kind: "exact", value: "OPS" }, allowedExecutionContexts: ["external"], enabled: false, version: 1 }
];

async function openEditor(page: Page) {
  const api = await mockCommandImportApi(page, commandAccepted());
  api.resources = structuredClone(resources);
  api.resourceTypes = COMMAND_RESOURCE_TYPES.map((type) => ({ ...type, supportsExclusions: type.id !== "ticketing_queue" }));
  await page.goto(`${assets.baseUrl}/ui/admin/catalog/resource-groups?item=new`);
  const editor = page.getByRole("complementary", { name: "Add resource group", exact: true });
  await editor.getByLabel("Group name", { exact: true }).fill("Mixed group");
  await expect(editor.getByRole("button", { name: "Refresh resource types", exact: true })).toBeEnabled();
  return { api, editor, includes: editor.getByRole("group", { name: "Included resources", exact: true }), excludes: editor.getByRole("group", { name: "Excluded resources", exact: true }) };
}

test("opted-out resources stay available for inclusion while mixed groups can exclude supported types", async ({ page }) => {
  const { api, editor, includes, excludes } = await openEditor(page);
  await expect(includes.getByRole("checkbox", { name: "Inclusion-only queue · triage", exact: true })).toBeEnabled();
  await expect(excludes.getByRole("checkbox", { name: "Inclusion-only queue · triage", exact: true })).toHaveCount(0);
  await expect(excludes).toContainText("Only resources whose types support exclusions are offered here.");
  await includes.getByRole("checkbox", { name: "Inclusion-only queue · triage", exact: true }).check();
  const supported = excludes.getByRole("checkbox", { name: "Operations project · OPS", exact: true });
  await expect(supported).toHaveAccessibleDescription(/regardless of enabled state or execution context/);
  await supported.check();
  await editor.getByRole("button", { name: "Save resource group", exact: true }).click();
  await expect(page.getByRole("complementary", { name: "Resource group Mixed group", exact: true })).toBeVisible();
  expect(api.savedGroups).toEqual([{ name: "Mixed group", includedResourceIds: ["triage"], excludedResourceIds: ["ops"] }]);
  expect(api.errors).toEqual([]);
});

test("a rejected stale editor refreshes capability metadata and keeps invalid exclusions removable", async ({ page }) => {
  const { api, editor, includes, excludes } = await openEditor(page);
  await includes.getByRole("checkbox", { name: "Inclusion-only queue · triage", exact: true }).check();
  await excludes.getByRole("checkbox", { name: "Operations project · OPS", exact: true }).check();
  // This exclusion is only in the open editor. An accepted refresh elsewhere
  // can therefore disable exclusions before this group is saved.
  api.resourceTypes = api.resourceTypes.map((type) => ({ ...type, supportsExclusions: false }));
  api.groupSaveError = "Resource ops of type ticketing_project does not support exclusions in group Mixed group.";
  const save = editor.getByRole("button", { name: "Save resource group", exact: true });
  await save.click();
  await expect(editor.getByRole("alert").filter({ hasText: api.groupSaveError })).toBeVisible();
  await expect(save).toBeDisabled();
  const stale = excludes.getByRole("checkbox", { name: "Operations project · OPS", exact: true });
  await expect(stale).toBeChecked();
  await expect(stale).toBeEnabled();
  await expect(stale).toHaveAccessibleDescription(/does not support new exclusions. Remove this added exclusion/);
  await excludes.getByLabel("Filter excluded resources", { exact: true }).fill("no matching name");
  await expect(stale).toBeVisible();
  // Removing this selection immediately hides the checkbox. Click models the
  // operator action without requiring a detached checkbox to remain queryable.
  await stale.click();
  await expect(stale).toHaveCount(0);
  await expect(save).toBeEnabled();
  await expect(includes.getByRole("checkbox", { name: "Inclusion-only queue · triage", exact: true })).toBeChecked();
  api.groupSaveError = null;
  await save.click();
  await expect(page.getByRole("complementary", { name: "Resource group Mixed group", exact: true })).toBeVisible();
  expect(api.savedGroups.map((body) => body.excludedResourceIds)).toEqual([["ops"], []]);
  expect(api.errors).toEqual([]);
});


test("refreshing a rejected group edit preserves its original conflict version", async ({ page }) => {
  const api = await mockCommandImportApi(page, commandAccepted());
  api.resources = structuredClone(resources);
  api.resourceGroups = [{ id: "engineering", name: "Engineering", includedResourceIds: ["triage"], excludedResourceIds: [], version: 1 }];
  await page.goto(`${assets.baseUrl}/ui/admin/catalog/resource-groups?item=engineering`);
  await page.getByRole("complementary", { name: "Resource group Engineering", exact: true }).getByRole("button", { name: "Edit", exact: true }).click();
  const editor = page.getByRole("complementary", { name: "Edit resource group Engineering", exact: true });
  await editor.getByLabel("Group name", { exact: true }).fill("My draft");
  // Another operator updates this group before the current draft is saved.
  api.resourceGroups = [{ ...api.resourceGroups[0]!, includedResourceIds: ["ops"], version: 2 }];
  api.groupSaveError = "Resource group changed since this editor was opened. Reopen it before saving.";
  const save = editor.getByRole("button", { name: "Save resource group", exact: true });
  await save.click();
  await expect(editor.getByRole("alert")).toContainText(api.groupSaveError);
  await expect(editor.getByLabel("Group name", { exact: true })).toHaveValue("My draft");
  await save.click();
  await expect.poll(() => api.savedGroups.length).toBe(2);
  expect(api.savedGroups.map((body) => body.expectedVersion)).toEqual([1, 1]);
  expect(api.savedGroups.map((body) => body.includedResourceIds)).toEqual([["triage"], ["triage"]]);
  expect(api.errors).toEqual([]);
});


test("stored exclusions stay valid while an editor refreshes stale opt-out metadata", async ({ page }) => {
  const api = await mockCommandImportApi(page, commandAccepted());
  api.resources = structuredClone(resources);
  api.resourceTypes = COMMAND_RESOURCE_TYPES.map((type) => ({ ...type, supportsExclusions: false }));
  let releaseCatalog!: () => void;
  const catalogReady = new Promise<void>((resolve) => { releaseCatalog = resolve; });
  await page.route("**/v1/admin/policy/resource-groups", async (route) => {
    if (route.request().method() === "GET") await catalogReady;
    await route.fallback();
  });
  const cachedTypes = page.waitForResponse((response) => new URL(response.url()).pathname === "/v1/resource-types");
  await page.goto(`${assets.baseUrl}/ui/admin/catalog/resource-groups`);
  await cachedTypes;
  // The tab has cached false. Another operator enables exclusions and saves a
  // group before this tab receives its fresh resource catalog.
  api.resourceTypes = COMMAND_RESOURCE_TYPES;
  api.resourceGroups = [{ id: "engineering", name: "Engineering", includedResourceIds: ["triage"], excludedResourceIds: ["ops"], version: 2 }];
  releaseCatalog();
  await page.getByRole("table", { name: "Resource groups", exact: true }).getByRole("link", { name: "Engineering", exact: true }).click();
  let releaseTypes!: () => void;
  const typesReady = new Promise<void>((resolve) => { releaseTypes = resolve; });
  await page.route("**/v1/resource-types", async (route) => { await typesReady; await route.fallback(); });
  const refetchedTypes = page.waitForResponse((response) => new URL(response.url()).pathname === "/v1/resource-types");
  await page.getByRole("complementary", { name: "Resource group Engineering", exact: true }).getByRole("button", { name: "Edit", exact: true }).click();
  const editor = page.getByRole("complementary", { name: "Edit resource group Engineering", exact: true });
  const saved = editor.getByRole("group", { name: "Excluded resources", exact: true }).getByRole("checkbox", { name: "Operations project · OPS", exact: true });
  try {
    await expect(saved).toBeChecked();
    await expect(saved).toBeEnabled();
    await expect(saved).toHaveAccessibleDescription(/Saved exclusion. The broker validates this membership when saving/);
    await expect(editor).not.toContainText("Remove");
    await expect(editor.getByRole("button", { name: "Save resource group", exact: true })).toBeEnabled();
  } finally {
    releaseTypes();
  }
  await refetchedTypes;
  await expect(saved).toHaveAccessibleDescription(/Exclusion applies regardless of enabled state or execution context/);
  await editor.getByLabel("Group name", { exact: true }).fill("Renamed engineering");
  await editor.getByRole("button", { name: "Save resource group", exact: true }).click();
  await expect(page.getByRole("complementary", { name: "Resource group Renamed engineering", exact: true })).toBeVisible();
  expect(api.savedGroups).toEqual([{ name: "Renamed engineering", includedResourceIds: ["triage"], excludedResourceIds: ["ops"], expectedVersion: 2 }]);
  expect(api.errors).toEqual([]);
});

test("loading and failed metadata never suggest removing saved exclusions or block a rename", async ({ page }) => {
  const api = await mockCommandImportApi(page, commandAccepted());
  api.resources = structuredClone(resources);
  api.resourceGroups = [{ id: "engineering", name: "Engineering", includedResourceIds: ["triage"], excludedResourceIds: ["ops"], version: 1 }];
  let releaseTypes!: () => void;
  const typesReady = new Promise<void>((resolve) => { releaseTypes = resolve; });
  await page.route("**/v1/resource-types", async (route) => {
    await typesReady;
    await route.fulfill({ status: 503, json: { error: "Metadata temporarily unavailable" } });
  });
  await page.goto(`${assets.baseUrl}/ui/admin/catalog/resource-groups?item=engineering`);
  await page.getByRole("complementary", { name: "Resource group Engineering", exact: true }).getByRole("button", { name: "Edit", exact: true }).click();
  const editor = page.getByRole("complementary", { name: "Edit resource group Engineering", exact: true });
  const saved = editor.getByRole("group", { name: "Excluded resources", exact: true }).getByRole("checkbox", { name: "Operations project · OPS", exact: true });
  const save = editor.getByRole("button", { name: "Save resource group", exact: true });
  try {
    await expect(saved).toBeChecked();
    await expect(saved).toBeEnabled();
    await expect(saved).toHaveAccessibleDescription(/Saved exclusion. The broker validates this membership when saving/);
    await expect(editor).not.toContainText("Remove");
    await expect(save).toBeEnabled();
  } finally {
    releaseTypes();
  }
  await expect(editor).toContainText("Couldn’t refresh resource types.");
  await expect(editor).not.toContainText("Remove");
  await expect(save).toBeEnabled();
  await editor.getByLabel("Group name", { exact: true }).fill("Renamed engineering");
  await save.click();
  await expect(page.getByRole("complementary", { name: "Resource group Renamed engineering", exact: true })).toBeVisible();
  expect(api.savedGroups[0]).toMatchObject({ excludedResourceIds: ["ops"], expectedVersion: 1 });
  expect(api.errors).toEqual([]);
});

test("a blocked new exclusion can recover from stale metadata without dropping the selection", async ({ page }) => {
  const { api, editor, excludes } = await openEditor(page);
  const selected = excludes.getByRole("checkbox", { name: "Operations project · OPS", exact: true });
  await selected.check();
  api.resourceTypes = api.resourceTypes.map((type) => ({ ...type, supportsExclusions: false }));
  api.groupSaveError = "Resource ops cannot be excluded.";
  const save = editor.getByRole("button", { name: "Save resource group", exact: true });
  await save.click();
  await expect(save).toBeDisabled();
  await expect(selected).toBeChecked();
  // A later acceptance restores support. Refreshing eligibility retains the
  // user's draft and permits saving it once the metadata is up to date.
  api.resourceTypes = COMMAND_RESOURCE_TYPES;
  api.groupSaveError = null;
  await editor.getByRole("button", { name: "Refresh resource types", exact: true }).click();
  await expect(save).toBeEnabled();
  await expect(selected).toBeChecked();
  await save.click();
  await expect(page.getByRole("complementary", { name: "Resource group Mixed group", exact: true })).toBeVisible();
  expect(api.savedGroups.map((body) => body.excludedResourceIds)).toEqual([["ops"], ["ops"]]);
  expect(api.errors).toEqual([]);
});
