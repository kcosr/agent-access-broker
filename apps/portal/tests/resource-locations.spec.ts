// Portal contract fixtures; provider normalization and management authorization
// are independently exercised by the Rust service tests.
import { expect, test, type Page } from "@playwright/test";
import type { ResourceLocationRequest, ResourceLocationService } from "../src/types";
import { mockCommandImportApi } from "./support/command-import-api";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

let assets: PortalAssets;
test.beforeAll(async () => { assets = await servePortalAssets(); });
test.afterAll(async () => { await assets.close(); });
const service: ResourceLocationService = { service: "confluence", resourceTypes: ["confluence_space", "confluence_content"], siteHost: "example.atlassian.net", locationKinds: ["space", "page", "folder", "blog"], coverageKinds: ["space", "exact", "subtree"], normalizationRoute: "/v1/admin/policy/resource-locations/normalize" };

async function fixture(page: Page, services = [service]) {
  const api = await mockCommandImportApi(page);
  const requests: Array<ResourceLocationRequest & { csrf: string | undefined }> = [];
  const state = { responseWait: Promise.resolve(), services };
  await page.route("**/v1/admin/policy/resource-locations", (route) => route.fulfill({ json: { ok: true, result: { services: state.services } } }));
  await page.route("**/v1/admin/policy/resource-locations/normalize", async (route) => {
    const body = route.request().postDataJSON() as ResourceLocationRequest;
    requests.push({ ...body, csrf: route.request().headers()["x-csrf-token"] });
    await state.responseWait;
    const url = new URL(body.url);
    if (url.host !== service.siteHost) {
      await route.fulfill({ status: 400, json: { ok: false, reasonCode: "input_invalid", error: { message: "url must use the selected service site" } } });
      return;
    }
    const parts = url.pathname.split("/");
    const spaceKey = body.spaceKey || parts[3];
    const kind = parts[4] === "pages" ? "page" : parts[4] === "folder" ? "folder" : parts[4] === "blog" ? "blog" : "space";
    const id = kind === "blog" && /^\d{4}$/.test(parts[5]) && parts.length >= 9 ? parts[8] : parts[5];
    const value = kind === "space" ? spaceKey : `https://${service.siteHost}/wiki/spaces/${spaceKey}/${parts[4]}/${id}`;
    await route.fulfill({ json: { ok: true, result: { resourceType: kind === "space" ? "confluence_space" : "confluence_content", selector: { kind: body.coverage === "space" ? "exact" : body.coverage, value }, locationKind: kind, configuredSpaceKey: spaceKey, verification: "not_checked" } } });
  });
  return { api, requests, state };
}
async function open(page: Page, type = "confluence_content") {
  await page.goto(`${assets.baseUrl}/ui/admin/catalog/resources?item=new`);
  const editor = page.getByRole("complementary", { name: "Add resource", exact: true });
  await editor.getByLabel("Resource type", { exact: true }).selectOption(type);
  return editor;
}

for (const coverage of ["exact", "subtree"] as const) {
  test(`page URL ${coverage} preview saves the canonical server result without an administrator connection`, async ({ page }) => {
    const model = await fixture(page);
    const editor = await open(page);
    await editor.getByRole("button", { name: "Enter location URL", exact: true }).click();
    await expect(editor.getByRole("button", { name: "Preview location", exact: true })).toBeDisabled();
    await editor.getByLabel("Location service", { exact: true }).selectOption("confluence");
    await editor.getByLabel("Location URL", { exact: true }).fill("https://example.atlassian.net/wiki/spaces/browser-alias/pages/12345/Runbooks");
    await expect(editor.getByLabel("Space key", { exact: true })).toHaveValue("browser-alias");
    await expect(editor.getByRole("button", { name: "Preview location", exact: true })).toBeDisabled();
    await editor.getByLabel("Space key", { exact: true }).fill("ENG");
    await editor.getByLabel("Location coverage", { exact: true }).selectOption(coverage);
    await editor.getByRole("button", { name: "Preview location", exact: true }).click();
    await expect(editor).toContainText("Not checked upstream");
    await expect(editor).toContainText("https://example.atlassian.net/wiki/spaces/ENG/pages/12345");
    await editor.getByLabel(/^Display name/).fill("Runbooks");
    await editor.getByRole("checkbox", { name: "internal", exact: true }).check();
    await editor.getByRole("button", { name: "Save resource", exact: true }).click();
    await expect.poll(() => model.api.createdResources.length).toBe(1);
    expect(model.api.createdResources[0]).toMatchObject({ resourceType: "confluence_content", displayName: "Runbooks", selector: { kind: coverage, value: "https://example.atlassian.net/wiki/spaces/ENG/pages/12345" }, allowedExecutionContexts: ["internal"] });
    expect(model.requests).toEqual([{ service: "confluence", url: "https://example.atlassian.net/wiki/spaces/browser-alias/pages/12345/Runbooks", coverage, spaceKey: "ENG", csrf: "fixture" }]);
    expect(model.api.errors).toEqual([]);
  });
}

for (const [path, label, coverage, type, id] of [
  ["spaces/ENG/overview", "Entire ENG space", "space", "confluence_space", null],
  ["spaces/ENG/folder/67890", "This folder and descendants", "subtree", "confluence_content", "67890"],
  ["spaces/ENG/blog/2026/11/20/54321/Release", "This blog post only", "exact", "confluence_content", "54321"]
] as const) {
  test(`${label} has fixed coverage and no page choice`, async ({ page }) => {
    const model = await fixture(page);
    const editor = await open(page, type);
    await editor.getByRole("button", { name: "Enter location URL", exact: true }).click();
    await editor.getByLabel("Location service", { exact: true }).selectOption("confluence");
    await editor.getByLabel("Location URL", { exact: true }).fill(`https://example.atlassian.net/wiki/${path}`);
    await expect(editor.getByLabel("Location coverage", { exact: true })).toHaveCount(0);
    await expect(editor.getByText(label, { exact: true })).toBeVisible();
    if (id) await expect(editor).toContainText(`Root ID: ${id}`);
    await editor.getByRole("button", { name: "Preview location", exact: true }).click();
    await expect(editor).toContainText("Not checked upstream");
    expect(model.requests[0].coverage).toBe(coverage);
    expect(model.api.errors).toEqual([]);
  });
}

test("editing a URL invalidates an in-flight preview and cannot save the old selector", async ({ page }) => {
  const model = await fixture(page);
  let release!: () => void;
  model.state.responseWait = new Promise<void>((resolve) => { release = resolve; });
  const editor = await open(page);
  await editor.getByRole("button", { name: "Enter location URL", exact: true }).click();
  await editor.getByLabel("Location service", { exact: true }).selectOption("confluence");
  await editor.getByLabel("Location URL", { exact: true }).fill("https://example.atlassian.net/wiki/spaces/ENG/pages/12345/First");
  await editor.getByLabel("Location coverage", { exact: true }).selectOption("subtree");
  await editor.getByRole("button", { name: "Preview location", exact: true }).click();
  await expect.poll(() => model.requests.length).toBe(1);
  await editor.getByLabel("Location URL", { exact: true }).fill("https://example.atlassian.net/wiki/spaces/ENG/pages/67890/Second");
  release();
  await expect(editor.getByRole("button", { name: "Preview location", exact: true })).toBeDisabled();
  await editor.getByRole("checkbox", { name: "internal", exact: true }).check();
  await editor.getByRole("button", { name: "Save resource", exact: true }).click();
  await expect(editor).toContainText("Preview the location before saving");
  await expect(editor).not.toContainText("Not checked upstream");
  expect(model.api.createdResources).toEqual([]);
});

test("a type with no location service keeps strict canonical entry and explains dormant coverage", async ({ page }) => {
  const model = await fixture(page, []);
  const editor = await open(page);
  await expect(editor).toContainText("this resource is currently dormant");
  await expect(editor.getByRole("button", { name: "Enter location URL", exact: true })).toHaveCount(0);
  await expect(editor.getByLabel("Coverage", { exact: true }).locator("option")).toHaveText(["Specific resource", "Root and descendants"]);
  await editor.getByLabel("Coverage", { exact: true }).selectOption("subtree");
  await editor.getByLabel("Canonical subtree root", { exact: true }).fill("https://other.atlassian.net/wiki/spaces/ENG/folder/67890");
  await editor.getByRole("checkbox", { name: "internal", exact: true }).check();
  await editor.getByRole("button", { name: "Save resource", exact: true }).click();
  await expect.poll(() => model.api.createdResources.length).toBe(1);
  expect(model.api.createdResources[0].selector).toEqual({ kind: "subtree", value: "https://other.atlassian.net/wiki/spaces/ENG/folder/67890" });
  expect(model.requests).toEqual([]);
});

test("an unsuccessful preview keeps saving blocked and reports the server field error", async ({ page }) => {
  const model = await fixture(page);
  const editor = await open(page);
  await editor.getByRole("button", { name: "Enter location URL", exact: true }).click();
  await editor.getByLabel("Location service", { exact: true }).selectOption("confluence");
  await editor.getByLabel("Location URL", { exact: true }).fill("https://other.atlassian.net/wiki/spaces/ENG/folder/67890");
  await editor.getByRole("button", { name: "Preview location", exact: true }).click();
  await expect(editor).toContainText("url must use the selected service site");
  await editor.getByRole("checkbox", { name: "internal", exact: true }).check();
  await editor.getByRole("button", { name: "Save resource", exact: true }).click();
  await expect(editor).toContainText("Preview the location before saving");
  expect(model.api.createdResources).toEqual([]);
});

test("grant editor explains location applicability and broad unions while preserving an unavailable preview", async ({ page }) => {
  const model = await fixture(page);
  model.api.resources = [
    { id: "space", displayName: "Engineering", resourceType: "confluence_space", selector: { kind: "exact", value: "ENG" }, allowedExecutionContexts: ["internal"], enabled: true, version: 1 },
    { id: "folder", displayName: "Runbooks", resourceType: "confluence_content", selector: { kind: "subtree", value: "https://example.atlassian.net/wiki/spaces/ENG/folder/12" }, allowedExecutionContexts: ["internal"], enabled: true, version: 1 }
  ];
  const previews: Array<Record<string, unknown>> = [];
  await page.route("**/v1/admin/policy/catalog", (route) => route.fulfill({ json: { ok: true, result: {
    resources: model.api.resources, resourceGroups: [], subjects: { users: [], groups: [], anonymous: false }, executionContexts: { allowedValues: ["internal"], defaultContext: "internal", contextRequired: false },
    services: [{ service: "confluence", displayName: "Confluence", surface: "invoke", configuredCredentialModes: ["per_user"], lookupCredentialConfigured: false,
      resourceScopes: { location: { matching: "containment", domain: "page", selectorsByType: { confluence_space: ["exact", "all"], confluence_content: ["exact", "subtree"] }, containerTypes: ["confluence_space"], targetKinds: ["page"], ancestorKinds: ["page", "folder"], effects: ["content"] } },
      actions: [{ action: "page.update", readOnly: false, description: "Update a page", requiredScopeTypes: ["location"], credentialModes: ["per_user"], lookupRequired: true, inputSchema: {} }]
    }]
  } } }));
  await page.route("**/v1/admin/policy/effective-access", (route) => {
    previews.push(route.request().postDataJSON());
    return route.fulfill({ json: { ok: true, result: { policyGeneration: 2, access: [{ service: "confluence", action: "page.update", executionContext: "internal", scope: "location", resourceTypes: ["confluence_space", "confluence_content"], domain: "page", enforcement: "request", containmentVerification: "at_invocation", projectionStatus: "too_complex", reasonCode: "resource_access_too_complex" }] } } });
  });
  await page.goto(`${assets.baseUrl}/ui/admin/policies/new`);
  await page.getByRole("combobox", { name: "Service", exact: true }).selectOption("confluence");
  await page.getByRole("group", { name: "Write-capable", exact: true }).getByRole("checkbox", { name: "page.update", exact: true }).check();
  await page.getByRole("group", { name: "Execution contexts", exact: true }).getByRole("checkbox", { name: "internal", exact: true }).check();
  const resources = page.getByRole("group", { name: "Resources", exact: true });
  await resources.getByRole("checkbox", { name: "Engineering · ENG", exact: true }).check();
  await resources.getByRole("checkbox", { name: /^Runbooks ·/ }).check();
  await expect(page.getByText(/Page and folder selections do not authorize blogs or space metadata/)).toBeVisible();
  await expect(page.getByText(/the space still permits the selected write actions throughout that space/)).toBeVisible();
  await expect(page.getByRole("complementary", { name: "Preview", exact: true })).toContainText("Coverage preview unavailable");
  await expect.poll(() => previews.at(-1)).toMatchObject({ service: "confluence", credentialMode: "per_user", actions: ["page.update"], resources: { resourceIds: ["space", "folder"], resourceGroupIds: [] } });
  await expect(resources.getByRole("checkbox", { name: /^Runbooks ·/ })).toBeChecked();
  expect(model.api.errors).toEqual([]);
});

test("switching from URL entry to another resource type restores that type’s canonical editor", async ({ page }) => {
  const model = await fixture(page);
  const editor = await open(page);
  await editor.getByRole("button", { name: "Enter location URL", exact: true }).click();
  await editor.getByLabel("Resource type", { exact: true }).selectOption("jira_project");
  await expect(editor.getByLabel("Location URL", { exact: true })).toHaveCount(0);
  await editor.getByLabel("Canonical identifier", { exact: true }).fill("ENG");
  await editor.getByRole("checkbox", { name: "internal", exact: true }).check();
  await editor.getByRole("button", { name: "Save resource", exact: true }).click();
  await expect.poll(() => model.api.createdResources.length).toBe(1);
  expect(model.api.createdResources[0]).toMatchObject({ resourceType: "jira_project", selector: { kind: "exact", value: "ENG" } });
  expect(model.requests).toEqual([]);
});
