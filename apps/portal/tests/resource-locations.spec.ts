// Browser-only management fixtures. Real Broker/CLI normalization and authorization
// are covered independently by the Rust management and transport suites.
import { expect, test, type Locator, type Page } from "@playwright/test";
import type { NormalizedResourceLocation, ResourceLocationRequest, ResourceLocationService, ResourceRecord, Session } from "../src/types";
import { ADMIN_SESSION, mockCommandImportApi } from "./support/command-import-api";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

let assets: PortalAssets;
test.beforeAll(async () => { assets = await servePortalAssets(); });
test.afterAll(async () => { await assets.close(); });
const service: ResourceLocationService = { service: "confluence", resourceTypes: ["confluence_space", "confluence_content"], siteHost: "example.atlassian.net", locationKinds: ["space", "page", "folder", "blog"], coverageKinds: ["space", "exact", "subtree"], normalizationRoute: "/v1/admin/policy/resource-locations/normalize" };
const pageUrl = "https://example.atlassian.net/wiki/spaces/browser-alias/pages/12345/Runbooks";
const pageIdentity = "https://example.atlassian.net/wiki/content/page/12345";

async function fixture(page: Page, services = [service]) {
  const api = await mockCommandImportApi(page);
  const requests: Array<ResourceLocationRequest & { csrf: string | undefined }> = [];
  const mutations: Array<Record<string, unknown>> = [];
  const order: string[] = [];
  const state = {
    services, session: structuredClone(ADMIN_SESSION), metadataStatus: 200, metadataReads: 0,
    responseWait: Promise.resolve(), metadataWait: Promise.resolve(), mutationWait: Promise.resolve(),
    normalizeError: null as string | null, resultOverride: null as NormalizedResourceLocation | null,
    mutationError: null as string | null, switchSessionOnNormalize: false, switchSessionOnMutation: false
  };
  await page.route("**/v1/auth/session", (route) => route.fulfill({ json: { ok: true, result: state.session } }));
  await page.route("**/v1/admin/policy/resource-locations", async (route) => {
    state.metadataReads += 1;
    await state.metadataWait;
    await route.fulfill(state.metadataStatus === 200 ? { json: { ok: true, result: { services: state.services } } } : { status: state.metadataStatus, json: { ok: false, reasonCode: "upstream_unavailable", error: { message: "Location metadata unavailable" } } });
  });
  await page.route("**/v1/admin/policy/resource-locations/normalize", async (route) => {
    const body = route.request().postDataJSON() as ResourceLocationRequest;
    requests.push({ ...body, csrf: route.request().headers()["x-csrf-token"] });
    order.push("normalize");
    await state.responseWait;
    if (state.switchSessionOnNormalize) {
      state.session = { ...ADMIN_SESSION, principal: "other-admin" } as Session;
      await route.fulfill({ status: 403, json: { ok: false, reasonCode: "csrf_invalid", error: { message: "Session changed" } } });
      return;
    }
    if (state.normalizeError) {
      await route.fulfill({ status: 400, json: { ok: false, reasonCode: "input_invalid", error: { message: state.normalizeError } } });
      return;
    }
    const url = new URL(body.url);
    const parts = url.pathname.replace(/\/$/, "").split("/");
    const kind = parts[4] === "pages" ? "page" : parts[4] === "folder" ? "folder" : parts[4] === "blog" ? "blog" : "space";
    const id = kind === "blog" && /^\d{4}$/.test(parts[5]) && parts.length >= 9 ? parts[8] : parts[5];
    const value = kind === "space" ? parts[3] : `https://${service.siteHost}/wiki/content/${kind}/${id}`;
    const result = state.resultOverride ?? { resourceType: kind === "space" ? "confluence_space" : "confluence_content", selector: { kind: body.coverage === "space" ? "exact" : body.coverage, value }, locationKind: kind, verification: "not_checked" };
    await route.fulfill({ json: { ok: true, result } });
  });
  await page.route(/\/v1\/admin\/policy\/resources(?:\/[^/?]+)?$/, async (route) => {
    const method = route.request().method();
    if (method !== "POST" && method !== "PATCH") return route.fallback();
    const body = route.request().postDataJSON() as Record<string, unknown> & Pick<ResourceRecord, "resourceType" | "selector" | "displayName" | "allowedExecutionContexts" | "enabled">;
    mutations.push(body);
    order.push("mutation");
    await state.mutationWait;
    if (state.switchSessionOnMutation) {
      state.session = { ...ADMIN_SESSION, principal: "other-admin" } as Session;
      await route.fulfill({ status: 403, json: { ok: false, reasonCode: "csrf_invalid", error: { message: "Session changed" } } });
      return;
    }
    const id = method === "PATCH" ? decodeURIComponent(new URL(route.request().url()).pathname.split("/").at(-1)!) : `resource-${mutations.length}`;
    const previous = api.resources.find((item) => item.id === id);
    if (state.mutationError || method === "PATCH" && body.expectedVersion !== previous?.version) {
      await route.fulfill({ status: 409, json: { ok: false, reasonCode: "resource_conflict", error: { message: state.mutationError ?? "The resource was changed by another administrator" } } });
      return;
    }
    const record: ResourceRecord = { ...body, id, version: (previous?.version ?? 0) + 1 };
    api.resources = [...api.resources.filter((item) => item.id !== id), record];
    if (method === "POST") api.createdResources.push(body);
    await route.fulfill({ json: { ok: true, result: { record, previousRevision: { generation: 1 }, revision: { generation: 2 } } } });
  });
  return { api, requests, mutations, order, state };
}
async function open(page: Page, type = "confluence_content") {
  await page.goto(`${assets.baseUrl}/ui/admin/catalog/resources?item=new`);
  const editor = page.getByRole("complementary", { name: "Add resource", exact: true });
  await editor.getByLabel("Resource type", { exact: true }).selectOption(type);
  return editor;
}
async function prepare(editor: Locator, url = pageUrl, coverage: "exact" | "subtree" = "subtree") {
  await editor.getByLabel("Location URL", { exact: true }).fill(url);
  if (await editor.getByLabel("Location coverage", { exact: true }).count()) await editor.getByLabel("Location coverage", { exact: true }).selectOption(coverage);
  await editor.getByLabel(/^Display name/).fill("Runbooks");
  await editor.getByRole("checkbox", { name: "internal", exact: true }).check();
}
async function save(editor: Locator) { await editor.getByRole("button", { name: "Save resource", exact: true }).click(); }
async function refreshQueries(page: Page) {
  await page.clock.setFixedTime(new Date(await page.evaluate(() => Date.now()) + 120_000));
  await page.evaluate(() => { window.dispatchEvent(new Event("offline")); window.dispatchEvent(new Event("online")); });
}
function existing(selector: ResourceRecord["selector"] = { kind: "exact", value: pageIdentity }, resourceType = "confluence_content"): ResourceRecord {
  return { id: "existing", resourceType, selector, displayName: "Existing", allowedExecutionContexts: ["internal"], enabled: true, version: 7 };
}
async function editExisting(page: Page) {
  await page.goto(`${assets.baseUrl}/ui/admin/catalog/resources?item=existing`);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  return page.getByRole("complementary", { name: "Edit resource Existing", exact: true });
}

for (const coverage of ["exact", "subtree"] as const) {
  test(`page URL ${coverage} needs only Save and stores the authoritative identity`, async ({ page }) => {
    const model = await fixture(page);
    const editor = await open(page);
    await expect(editor.getByLabel("Location service", { exact: true })).toHaveCount(0);
    await expect(editor.getByLabel("Space key", { exact: true })).toHaveCount(0);
    await expect(editor.getByLabel("Canonical identifier", { exact: true })).toHaveCount(0);
    await expect(editor.getByRole("button", { name: "Preview location", exact: true })).toHaveCount(0);
    await prepare(editor, pageUrl, coverage);
    expect(model.requests).toEqual([]);
    await save(editor);
    await expect.poll(() => model.api.createdResources.length).toBe(1);
    expect(model.order).toEqual(["normalize", "mutation"]);
    expect(model.api.createdResources[0]).toMatchObject({ resourceType: "confluence_content", displayName: "Runbooks", browserUrl: pageUrl, selector: { kind: coverage, value: pageIdentity }, allowedExecutionContexts: ["internal"], enabled: true });
    expect(model.requests).toEqual([{ service: "confluence", url: pageUrl, coverage, csrf: "fixture" }]);
    expect(model.api.errors).toEqual([]);
  });
}

for (const [path, label, coverage, type, id] of [
  ["spaces/ENG/overview", "Entire ENG space", "space", "confluence_space", null],
  ["spaces/ENG/folder/67890", "This folder and descendants", "subtree", "confluence_content", "67890"],
  ["spaces/ENG/blog/2026/11/20/54321/Release", "This blog post only", "exact", "confluence_content", "54321"]
] as const) {
  test(`${label} infers its type and fixed coverage immediately`, async ({ page }) => {
    const model = await fixture(page);
    const editor = await open(page);
    await prepare(editor, `https://example.atlassian.net/wiki/${path}`);
    await expect(editor.getByLabel("Location coverage", { exact: true })).toHaveCount(0);
    await expect(editor.getByText(label, { exact: true })).toBeVisible();
    await expect(editor.getByLabel("Resource type", { exact: true })).toHaveValue(type);
    if (id) await expect(editor).toContainText(`ID: ${id}`);
    else {
      await expect(editor).toContainText("Space key to save: ENG");
      await expect(editor).toContainText("Browser URLs may contain aliases");
    }
    expect(model.requests).toEqual([]);
    await save(editor);
    await expect.poll(() => model.api.createdResources.length).toBe(1);
    expect(model.requests[0].coverage).toBe(coverage);
    expect(model.api.createdResources[0].resourceType).toBe(type);
    expect(model.api.errors).toEqual([]);
  });
}

test("folder URL retains its title separately from the immutable folder identity", async ({ page }) => {
  const model = await fixture(page);
  const editor = await open(page);
  const url = "https://example.atlassian.net/wiki/spaces/ENG/folder/67890/Operations+Runbooks";
  await prepare(editor, url);
  await expect(editor.getByText("This folder and descendants", { exact: true })).toBeVisible();
  await expect(editor.getByLabel("Location coverage", { exact: true })).toHaveCount(0);
  await expect(editor).toContainText("Folder ID: 67890");
  expect(model.requests).toEqual([]);
  await save(editor);
  await expect.poll(() => model.api.createdResources.length).toBe(1);
  expect(model.order).toEqual(["normalize", "mutation"]);
  expect(model.requests).toEqual([{ service: "confluence", url, coverage: "subtree", csrf: "fixture" }]);
  expect(model.api.createdResources[0]).toMatchObject({
    resourceType: "confluence_content",
    browserUrl: url,
    selector: { kind: "subtree", value: "https://example.atlassian.net/wiki/content/folder/67890" }
  });
  expect(model.api.errors).toEqual([]);
});

test("page choice is explicit and resets with a changed URL", async ({ page }) => {
  const model = await fixture(page);
  const editor = await open(page);
  await prepare(editor);
  await editor.getByLabel("Location URL", { exact: true }).fill(pageUrl.replace("12345", "67890"));
  await expect(editor.getByLabel("Location coverage", { exact: true })).toHaveValue("");
  await save(editor);
  await expect(editor).toContainText("Choose whether to include this page only or its descendants");
  expect(model.requests).toEqual([]);
  expect(model.mutations).toEqual([]);
  await editor.getByLabel("Location URL", { exact: true }).fill("not a URL");
  await expect(editor.getByLabel("Location coverage", { exact: true })).toHaveCount(0);
});

test("URL kind changes keep ordinary fields and the displayed and saved types agree", async ({ page }) => {
  const model = await fixture(page);
  const editor = await open(page);
  await prepare(editor);
  await editor.getByLabel("Location URL", { exact: true }).fill("https://example.atlassian.net/wiki/spaces/VECTOR/overview");
  await expect(editor.getByLabel("Resource type", { exact: true })).toHaveValue("confluence_space");
  await expect(editor.getByLabel("Location URL", { exact: true })).toHaveValue("https://example.atlassian.net/wiki/spaces/VECTOR/overview");
  await expect(editor.getByLabel(/^Display name/)).toHaveValue("Runbooks");
  await expect(editor.getByRole("checkbox", { name: "internal", exact: true })).toBeChecked();
  await editor.getByLabel("Location URL", { exact: true }).fill("https://example.atlassian.net/wiki/spaces/other/folder/88");
  await expect(editor.getByLabel("Resource type", { exact: true })).toHaveValue("confluence_content");
  await save(editor);
  await expect.poll(() => model.mutations.length).toBe(1);
  expect(model.mutations[0]).toMatchObject({ displayName: "Runbooks", selector: { kind: "subtree", value: "https://example.atlassian.net/wiki/content/folder/88" } });
});

for (const [services, url, message] of [
  [[], pageUrl, "No applicable Confluence service is configured"],
  [[service], pageUrl.replace("example.atlassian.net", "other.atlassian.net"), "does not match a configured Confluence site"],
  [[service, { ...service, service: "duplicate" }], pageUrl, "More than one configured service matches"]
] as const) {
  test(`URL save is blocked: ${message}`, async ({ page }) => {
    const model = await fixture(page, [...services]);
    const editor = await open(page);
    await prepare(editor, url);
    await expect(editor).toContainText(message);
    await save(editor);
    expect(model.requests).toEqual([]);
    expect(model.mutations).toEqual([]);
    await expect(editor.getByLabel("Canonical identifier", { exact: true })).toHaveCount(0);
    await expect(editor.getByLabel("Space key", { exact: true })).toHaveCount(0);
  });
}

test("capability loading and failure retain URL draft and allow an explicit retry", async ({ page }) => {
  const model = await fixture(page);
  let release!: () => void;
  model.state.metadataWait = new Promise<void>((resolve) => { release = resolve; });
  const editor = await open(page);
  await prepare(editor);
  await expect(editor).toContainText("Loading configured location services");
  await save(editor);
  expect(model.requests).toEqual([]);
  model.state.metadataStatus = 503;
  release();
  await expect(editor).toContainText("Location services unavailable");
  await expect(editor.getByLabel("Location URL", { exact: true })).toHaveValue(pageUrl);
  model.state.metadataStatus = 200;
  await editor.getByRole("button", { name: /Retry/ }).click();
  await expect(editor).toContainText("Site: example.atlassian.net");
  await save(editor);
  await expect.poll(() => model.mutations.length).toBe(1);
});

test("Save locks the complete draft and prevents duplicate normalize and mutation requests", async ({ page }) => {
  const model = await fixture(page);
  let release!: () => void;
  model.state.responseWait = new Promise<void>((resolve) => { release = resolve; });
  const editor = await open(page);
  await prepare(editor);
  await editor.locator("form").evaluate((form) => {
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  await expect.poll(() => model.requests.length).toBe(1);
  await expect(editor.getByLabel("Location URL", { exact: true })).toBeDisabled();
  await expect(editor.getByLabel("Resource type", { exact: true })).toBeDisabled();
  await expect(editor.getByLabel(/^Display name/)).toBeDisabled();
  await expect(editor.getByRole("checkbox", { name: "internal", exact: true })).toBeDisabled();
  await expect(editor.getByRole("button", { name: "Cancel", exact: true })).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(editor).toBeVisible();
  expect(model.mutations).toEqual([]);
  release();
  await expect.poll(() => model.mutations.length).toBe(1);
  expect(model.requests).toHaveLength(1);
});

for (const rejected of [false, true]) {
  test(`an unmounted draft ignores stale normalization ${rejected ? "failure" : "success"}`, async ({ page }) => {
    const model = await fixture(page);
    let release!: () => void;
    model.state.responseWait = new Promise<void>((resolve) => { release = resolve; });
    const editor = await open(page);
    await prepare(editor);
    await save(editor);
    await expect.poll(() => model.requests.length).toBe(1);
    await page.getByRole("link", { name: "Principals", exact: true }).click();
    await expect(editor).toHaveCount(0);
    if (rejected) model.state.normalizeError = "Old normalization failure";
    release();
    await expect.poll(() => model.api.errors.length).toBe(0);
    await open(page, "jira_project");
    expect(model.mutations).toEqual([]);
    await expect(page.getByText("Old normalization failure")).toHaveCount(0);
  });
}

test("a changed configured site stops the old normalization before mutation", async ({ page }) => {
  const model = await fixture(page);
  let release!: () => void;
  model.state.responseWait = new Promise<void>((resolve) => { release = resolve; });
  const editor = await open(page);
  await prepare(editor);
  await save(editor);
  await expect.poll(() => model.requests.length).toBe(1);
  const reads = model.state.metadataReads;
  model.state.services = [{ ...service, siteHost: "replacement.atlassian.net" }];
  await refreshQueries(page);
  await expect.poll(() => model.state.metadataReads).toBeGreaterThan(reads);
  await expect(editor).toContainText("does not match a configured Confluence site");
  release();
  await expect(editor).toContainText("The configured location service changed");
  expect(model.mutations).toEqual([]);
});

for (const phase of ["normalize", "mutation"] as const) {
  test(`a CSRF refresh cannot continue ${phase} as a different signed-in account`, async ({ page }) => {
    const model = await fixture(page);
    const editor = await open(page);
    await prepare(editor);
    if (phase === "normalize") model.state.switchSessionOnNormalize = true;
    else model.state.switchSessionOnMutation = true;
    await save(editor);
    await expect.poll(() => model.state.session.principal).toBe("other-admin");
    // The account boundary resets the routed editor; the old draft must not
    // reappear or continue its normalization/mutation under the new account.
    await expect(editor.getByLabel("Resource type", { exact: true })).toHaveValue("git_repository");
    await expect(editor.getByLabel(/^Display name/)).toHaveValue("");
    expect(model.requests).toHaveLength(1);
    expect(model.mutations).toHaveLength(phase === "normalize" ? 0 : 1);
    expect(model.api.createdResources).toEqual([]);
  });
}

for (const field of ["content ID", "site", "kind", "coverage", "space key"] as const) {
  test(`a server response with different ${field} cannot change the displayed saved identity`, async ({ page }) => {
    const model = await fixture(page);
    const editor = await open(page);
    await prepare(editor, field === "space key" ? "https://example.atlassian.net/wiki/spaces/VECTOR/overview" : pageUrl);
    model.state.resultOverride = field === "space key"
      ? { resourceType: "confluence_space", selector: { kind: "exact", value: "ROCKET" }, locationKind: "space", verification: "not_checked" }
      : { resourceType: "confluence_content", selector: { kind: field === "coverage" ? "exact" : "subtree", value: field === "content ID" ? pageIdentity.replace("12345", "999") : field === "site" ? pageIdentity.replace("example", "other") : field === "kind" ? pageIdentity.replace("/page/", "/folder/") : pageIdentity }, locationKind: field === "kind" ? "folder" : "page", verification: "not_checked" };
    await save(editor);
    await expect(editor).toContainText("normalized location differs from the displayed location");
    expect(model.mutations).toEqual([]);
    await expect(editor.getByLabel(/^Display name/)).toHaveValue("Runbooks");
  });
}

test("normalization and mutation failures retain fields and retry from the current URL", async ({ page }) => {
  const model = await fixture(page);
  const editor = await open(page);
  await prepare(editor);
  model.state.normalizeError = "The location is no longer accepted";
  await save(editor);
  await expect(editor).toContainText(model.state.normalizeError);
  expect(model.mutations).toEqual([]);
  await expect(editor.getByLabel(/^Display name/)).toHaveValue("Runbooks");
  model.state.normalizeError = null;
  model.state.mutationError = "A duplicate resource already exists";
  await save(editor);
  await expect(editor).toContainText(model.state.mutationError);
  await expect(editor.getByRole("checkbox", { name: "internal", exact: true })).toBeChecked();
  model.state.mutationError = null;
  await editor.getByLabel("Location URL", { exact: true }).fill(pageUrl.replace("12345", "67890"));
  await editor.getByLabel("Location coverage", { exact: true }).selectOption("exact");
  await save(editor);
  await expect.poll(() => model.api.createdResources.length).toBe(1);
  expect(model.requests).toHaveLength(3);
  expect(model.mutations).toHaveLength(2);
  expect(model.api.createdResources[0].selector).toEqual({ kind: "exact", value: pageIdentity.replace("12345", "67890") });
});

for (const blankUrl of ["", "   "]) {
  test(`switching ${blankUrl ? "whitespace-only" : "empty"} content entry to a space starts by key`, async ({ page }) => {
    const model = await fixture(page, []);
    const editor = await open(page);
    await editor.getByLabel("Location URL", { exact: true }).fill(blankUrl);
    await editor.getByLabel(/^Display name/).fill("Engineering");
    await editor.getByRole("checkbox", { name: "internal", exact: true }).check();
    await editor.getByLabel("Resource type", { exact: true }).selectOption("confluence_space");
    await expect(editor.getByRole("button", { name: "By space key", exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(editor.getByLabel("Space key", { exact: true })).toHaveValue("");
    await expect(editor.getByLabel("Location URL", { exact: true })).toHaveCount(0);
    await editor.getByLabel("Space key", { exact: true }).fill("ENG");
    await save(editor);
    await expect.poll(() => model.mutations.length).toBe(1);
    expect(model.mutations[0]).toMatchObject({ resourceType: "confluence_space", selector: { kind: "exact", value: "ENG" }, displayName: "Engineering", allowedExecutionContexts: ["internal"] });
    expect(model.requests).toEqual([]);
  });
}

test("standalone space-key and all-spaces entry work without any location service", async ({ page }) => {
  const model = await fixture(page, []);
  const editor = await open(page, "confluence_space");
  await expect(editor.getByLabel("Space key", { exact: true })).toBeVisible();
  await expect(editor.getByLabel("Location URL", { exact: true })).toHaveCount(0);
  await editor.getByLabel("Space key", { exact: true }).fill("~person.name@example.com");
  await editor.getByRole("checkbox", { name: "internal", exact: true }).check();
  await save(editor);
  await expect.poll(() => model.mutations.length).toBe(1);
  expect(model.mutations[0].selector).toEqual({ kind: "exact", value: "~person.name@example.com" });
  const second = await open(page, "confluence_space");
  await second.getByRole("button", { name: "All spaces", exact: true }).click();
  await second.getByRole("checkbox", { name: "internal", exact: true }).check();
  await save(second);
  await expect.poll(() => model.mutations.length).toBe(2);
  expect(model.mutations[1].selector).toEqual({ kind: "all" });
  expect(model.requests).toEqual([]);
});

test("space URL explicitly displays the unverified key and by-key mode starts empty", async ({ page }) => {
  const model = await fixture(page);
  const editor = await open(page, "confluence_space");
  await editor.getByRole("button", { name: "From space URL", exact: true }).click();
  await prepare(editor, "https://example.atlassian.net/wiki/spaces/VECTOR/overview");
  await expect(editor).toContainText("Space key to save: VECTOR");
  await expect(editor).toContainText("Browser URLs may contain aliases. Enter the canonical key using By space key.");
  await editor.getByRole("button", { name: "By space key", exact: true }).click();
  await expect(editor.getByLabel("Space key", { exact: true })).toHaveValue("");
  await expect(editor.getByLabel(/^Display name/)).toHaveValue("Runbooks");
  await editor.getByLabel("Space key", { exact: true }).fill("ROCKET");
  await save(editor);
  await expect.poll(() => model.mutations.length).toBe(1);
  expect(model.mutations[0].selector).toEqual({ kind: "exact", value: "ROCKET" });
  expect(model.requests).toEqual([]);
});

test("existing space records preserve version checks and exact/all edits clear hidden identity", async ({ page }) => {
  const model = await fixture(page, []);
  model.api.resources = [existing({ kind: "exact", value: "ENG" }, "confluence_space")];
  const editor = await editExisting(page);
  await expect(editor.getByLabel("Space key", { exact: true })).toHaveValue("ENG");
  await editor.getByRole("button", { name: "All spaces", exact: true }).click();
  await editor.getByRole("button", { name: "By space key", exact: true }).click();
  await expect(editor.getByLabel("Space key", { exact: true })).toHaveValue("");
  await save(editor);
  await expect(editor).toContainText("Enter the canonical space key");
  expect(model.mutations).toEqual([]);
  await editor.getByRole("button", { name: "All spaces", exact: true }).click();
  await save(editor);
  await expect.poll(() => model.mutations.length).toBe(1);
  expect(model.mutations[0]).toMatchObject({ expectedVersion: 7, selector: { kind: "all" } });
  const again = await editExisting(page);
  await expect(again.getByText("All Confluence spaces", { exact: true })).toBeVisible();
  await again.getByRole("button", { name: "By space key", exact: true }).click();
  await expect(again.getByLabel("Space key", { exact: true })).toHaveValue("");
  await again.getByLabel("Space key", { exact: true }).fill("ROCKET");
  await save(again);
  await expect.poll(() => model.mutations.length).toBe(2);
  expect(model.mutations[1]).toMatchObject({ expectedVersion: 8, selector: { kind: "exact", value: "ROCKET" } });
  expect(model.requests).toEqual([]);
});

test("existing content metadata and page coverage edit without URL or configured service", async ({ page }) => {
  const model = await fixture(page, []);
  model.api.resources = [existing()];
  const editor = await editExisting(page);
  await expect(editor.getByLabel("Location URL", { exact: true })).toHaveCount(0);
  await expect(editor).toContainText("Page 12345");
  await expect(editor).toContainText("example.atlassian.net");
  await expect(editor.locator(`a[href='${pageIdentity}']`)).toHaveCount(0);
  await editor.getByLabel(/^Display name/).fill("Renamed");
  await editor.getByLabel("Location coverage", { exact: true }).selectOption("subtree");
  await save(editor);
  await expect.poll(() => model.mutations.length).toBe(1);
  expect(model.mutations[0]).toMatchObject({ expectedVersion: 7, displayName: "Renamed", selector: { kind: "subtree", value: pageIdentity } });
  expect(model.requests).toEqual([]);
});

test("saved browser links can be added, corrected and cleared without changing identity", async ({ page }) => {
  const model = await fixture(page, []);
  model.api.resources = [existing()];
  let editor = await editExisting(page);
  await editor.getByLabel("Browser URL (optional)", { exact: true }).fill(`  ${pageUrl}  `);
  await save(editor);
  await expect.poll(() => model.mutations.length).toBe(1);
  expect(model.mutations[0]).toMatchObject({ expectedVersion: 7, browserUrl: pageUrl, selector: { kind: "exact", value: pageIdentity } });
  const details = page.getByRole("complementary", { name: "Resource Existing", exact: true });
  await expect(details).toContainText(pageUrl);
  await expect(details.getByRole("link", { name: pageUrl, exact: true })).toHaveAttribute("href", pageUrl);
  await expect(details.getByRole("link", { name: pageUrl, exact: true })).toHaveAttribute("rel", "noopener noreferrer");
  editor = await editExisting(page);
  const corrected = pageUrl.replace("browser-alias", "NEWSPACE").replace("Runbooks", "Current+Title");
  await editor.getByLabel("Browser URL (optional)", { exact: true }).fill(corrected);
  await save(editor);
  await expect.poll(() => model.mutations.length).toBe(2);
  expect(model.mutations[1]).toMatchObject({ expectedVersion: 8, browserUrl: corrected, selector: { kind: "exact", value: pageIdentity } });
  editor = await editExisting(page);
  await editor.getByLabel("Browser URL (optional)", { exact: true }).fill("");
  await save(editor);
  await expect.poll(() => model.mutations.length).toBe(3);
  expect(model.mutations[2]).toMatchObject({ expectedVersion: 9, browserUrl: null, selector: { kind: "exact", value: pageIdentity } });
  await expect(details.getByRole("link", { name: corrected, exact: true })).toHaveCount(0);
  expect(model.requests).toEqual([]);
});

for (const invalid of [pageUrl.replace("example", "different"), pageUrl.replace("12345", "999"), pageUrl.replace("pages", "folder"), "javascript:alert(1)"]) {
  test(`a saved browser link cannot point to another target: ${invalid}`, async ({ page }) => {
    const model = await fixture(page, []);
    model.api.resources = [{ ...existing(), browserUrl: pageUrl }];
    const editor = await editExisting(page);
    await editor.getByLabel("Browser URL (optional)", { exact: true }).fill(invalid);
    await expect(editor.getByRole("link", { name: "Open in Confluence", exact: true })).toHaveCount(0);
    await save(editor);
    await expect(editor).toContainText("same site, content type and ID");
    expect(model.mutations).toEqual([]);
  });
}

test("enabling a saved resource preserves its browser link and version", async ({ page }) => {
  const model = await fixture(page);
  model.api.resources = [{ ...existing(), browserUrl: pageUrl, enabled: false }];
  await page.goto(`${assets.baseUrl}/ui/admin/catalog/resources?item=existing`);
  await page.getByRole("complementary", { name: "Resource Existing", exact: true }).getByRole("button", { name: "Enable", exact: true }).click();
  await expect.poll(() => model.mutations.length).toBe(1);
  expect(model.mutations[0]).toMatchObject({ expectedVersion: 7, browserUrl: pageUrl, enabled: true });
});

test("explicit content replacement starts empty and can restore the saved identity", async ({ page }) => {
  const model = await fixture(page);
  model.api.resources = [existing()];
  const editor = await editExisting(page);
  await editor.getByRole("button", { name: "Change location", exact: true }).click();
  await expect(editor.getByLabel("Location URL", { exact: true })).toHaveValue("");
  await editor.getByLabel("Location URL", { exact: true }).fill(pageUrl.replace("12345", "67890"));
  await editor.getByRole("button", { name: "Keep saved location", exact: true }).click();
  await expect(editor).toContainText("Page 12345");
  await editor.getByRole("button", { name: "Change location", exact: true }).click();
  await prepare(editor, "https://example.atlassian.net/wiki/spaces/other/folder/88");
  await save(editor);
  await expect.poll(() => model.mutations.length).toBe(1);
  expect(model.mutations[0]).toMatchObject({ expectedVersion: 7, selector: { kind: "subtree", value: "https://example.atlassian.net/wiki/content/folder/88" } });
});

test("a catalog refetch does not advance an open draft's optimistic version", async ({ page }) => {
  const model = await fixture(page);
  model.api.resources = [existing()];
  const editor = await editExisting(page);
  await editor.getByLabel(/^Display name/).fill("My draft");
  model.api.resources = [{ ...existing(), version: 8, displayName: "Someone else's edit" }];
  const reads = model.state.metadataReads;
  await refreshQueries(page);
  await expect.poll(() => model.state.metadataReads).toBeGreaterThan(reads);
  await save(editor);
  await expect(editor).toContainText("changed by another administrator");
  expect(model.mutations[0].expectedVersion).toBe(7);
  await expect(editor.getByLabel(/^Display name/)).toHaveValue("My draft");
});

test("switching to another resource type restores its canonical editor", async ({ page }) => {
  const model = await fixture(page);
  const editor = await open(page);
  await prepare(editor);
  await editor.getByLabel("Resource type", { exact: true }).selectOption("jira_project");
  await expect(editor.getByLabel("Location URL", { exact: true })).toHaveCount(0);
  await editor.getByLabel("Canonical identifier", { exact: true }).fill("ENG");
  await save(editor);
  await expect.poll(() => model.api.createdResources.length).toBe(1);
  expect(model.api.createdResources[0]).toMatchObject({ resourceType: "jira_project", selector: { kind: "exact", value: "ENG" } });
  expect(model.requests).toEqual([]);
});
for (const projectionStatus of ["complete", "too_complex"] as const) {
  test(`grant editor retains conditional move-root visibility without the generic rules banner with ${projectionStatus} coverage`, async ({ page }) => {
    const model = await fixture(page);
    model.api.resources = [
      { id: "space", displayName: "Engineering", resourceType: "confluence_space", selector: { kind: "exact", value: "ENG" }, allowedExecutionContexts: ["internal"], enabled: true, version: 1 },
      { id: "folder", displayName: "Runbooks", resourceType: "confluence_content", selector: { kind: "subtree", value: "https://example.atlassian.net/wiki/content/folder/12" }, allowedExecutionContexts: ["internal"], enabled: true, version: 1 }
    ];
    const previews: Array<Record<string, unknown>> = [];
    await page.route("**/v1/admin/policy/catalog", (route) => route.fulfill({ json: { ok: true, result: {
      resources: model.api.resources, resourceGroups: [], subjects: { users: [], groups: [], anonymous: false }, executionContexts: { allowedValues: ["internal"], defaultContext: "internal", contextRequired: false },
      services: [{ service: "confluence", displayName: "Confluence", surface: "invoke", configuredCredentialModes: ["per_user"], lookupCredentialConfigured: false,
        resourceScopes: { location: { matching: "containment", domain: "page_move", selectorsByType: { confluence_space: ["exact", "all"], confluence_content: ["exact", "subtree"] }, containerTypes: ["confluence_space"], targetKinds: ["page"], ancestorKinds: ["page", "folder"], effects: ["content"] } },
        actions: [{ action: "page.move", readOnly: false, description: "Move a page", requiredScopeTypes: ["location"], credentialModes: ["per_user"], lookupRequired: true, inputSchema: {} }]
      }]
    } } }));
    await page.route("**/v1/admin/policy/effective-access", (route) => {
      previews.push(route.request().postDataJSON());
      return route.fulfill({ json: { ok: true, result: { policyGeneration: 2, access: [{ service: "confluence", action: "page.move", executionContext: "internal", scope: "location", resourceTypes: ["confluence_space", "confluence_content"], domain: "page_move", enforcement: "request", containmentVerification: "at_invocation", requiresRuntimeRootVisibility: true, ...(projectionStatus === "too_complex" ? { projectionStatus, reasonCode: "resource_access_too_complex" } : { projectionStatus, boundaries: [{ included: [{ resourceType: "confluence_space", selector: { kind: "exact", value: "ENG" } }], excluded: [{ resourceType: "confluence_content", selector: model.api.resources[1].selector }] }], clauses: [{ required: [0], excludedRequests: [], credentialMode: "per_user" }] }) }] } } });
    });
    await page.goto(`${assets.baseUrl}/ui/admin/policies/new`);
    await page.getByRole("combobox", { name: "Service", exact: true }).selectOption("confluence");
    await page.getByRole("group", { name: "Write-capable", exact: true }).getByRole("checkbox", { name: "page.move", exact: true }).check();
    await page.getByRole("group", { name: "Execution contexts", exact: true }).getByRole("checkbox", { name: "internal", exact: true }).check();
    const resources = page.getByRole("group", { name: "Resources", exact: true });
    await resources.getByRole("checkbox", { name: "Engineering · ENG", exact: true }).check();
    await resources.getByRole("checkbox", { name: /^Runbooks ·/ }).check();
    await expect(page.getByText(/Locations grant no actions by themselves/)).toHaveCount(0);
    await expect(page.getByText(/the space still permits the selected write actions throughout that space/)).toHaveCount(0);
    const preview = page.getByRole("complementary", { name: "Preview", exact: true });
    if (projectionStatus === "too_complex") await expect(preview).toContainText("Coverage preview unavailable");
    await expect(preview).toContainText("Moves require runtime visibility of relevant excluded roots");
    await expect(preview).toContainText("This offline preview does not check whether those roots are current or readable");
    await expect(preview).toContainText("can block moves throughout the site");
    await expect(preview).toContainText("selected user legitimately lacks access");
    await expect(preview).toContainText("administrator can inspect protected diagnostics");
    await expect.poll(() => previews.at(-1)).toMatchObject({ service: "confluence", credentialMode: "per_user", actions: ["page.move"], resources: { resourceIds: ["space", "folder"], resourceGroupIds: [] } });
    await expect(resources.getByRole("checkbox", { name: /^Runbooks ·/ })).toBeChecked();
    expect(model.api.errors).toEqual([]);
  });
}
