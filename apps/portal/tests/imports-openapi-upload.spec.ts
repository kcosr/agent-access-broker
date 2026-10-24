import { expect, test, type Page, type Locator } from "@playwright/test";
import { createHash } from "node:crypto";
import type { ImportDefinition, ImportPreviewResult } from "../src/import-types";
import { ADMIN_SESSION } from "./support/command-import-api";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

// Mocked management contracts for source choice and uncertain upload recovery.
// imports-openapi-upload-live.spec.ts exercises real retained-source discovery and grants.
let assets: PortalAssets;
test.beforeAll(async () => { assets = await servePortalAssets(); });
test.afterAll(async () => { await assets.close(); });
const raw = '\n {"swagger":"2.0","info":{"title":"café","version":"1"},"paths":{}}\n';
const file = (name = "inventory.json", text = raw) => ({ name, mimeType: "application/json", buffer: Buffer.from(text) });

function draft(definition: ImportDefinition): ImportPreviewResult {
  return {
    catalogRevision: 4, operatorAllowed: true, importAuthentication: [], affectedGrants: [], affectedGrantsByAction: {}, preview: null,
    scopedMcp: { ready: false, issues: [{ code: "service_unavailable", actions: [] }], truncated: false }, scopedMcpWarnings: [],
    service: { definition, status: "draft", version: 1, actions: [], slotVersions: {}, credentialInputs: {}, createdAt: "", updatedAt: "", createdBy: "admin", updatedBy: "admin" }
  };
}

async function mockApi(page: Page) {
  const api = {
    current: null as ImportPreviewResult | null,
    created: [] as ImportDefinition[],
    uploads: [] as { body: Buffer; query: URLSearchParams; headers: Record<string, string> }[],
    failNext: "" as "" | "reject" | "lost" | "conflict",
    events: [] as string[],
    reads: 0,
    errors: [] as string[]
  };
  page.on("pageerror", (error) => api.errors.push(error.message));
  await page.route("**/v1/**", async (route) => {
    const request = route.request(), url = new URL(request.url()), method = request.method(), pathname = url.pathname;
    let result: unknown = [];
    if (pathname === "/v1/auth/session") result = ADMIN_SESSION;
    else if (pathname === "/v1/resource-types" || pathname === "/v1/me") {
      await route.fulfill({ json: pathname === "/v1/me" ? { principal: "admin", serviceLimits: [] } : { resourceTypes: [] } });
      return;
    } else if (pathname === "/v1/admin/imports") {
      if (method === "POST") {
        const definition = request.postDataJSON() as ImportDefinition;
        api.created.push(definition);
        api.current = draft(definition);
        result = api.current;
      } else result = { catalogRevision: api.current?.catalogRevision ?? 4, operatorEnabled: true, availableKinds: ["openapi_http"], commandImports: [], importAuthentication: [], services: api.current ? [api.current.service] : [] };
    } else if (pathname === "/v1/admin/imports/inventory/document" && method === "PUT") {
      api.events.push("upload");
      const body = request.postDataBuffer()!;
      api.uploads.push({ body, query: url.searchParams, headers: request.headers() });
      const failure = api.failNext;
      api.failNext = "";
      if (failure === "reject") {
        await route.fulfill({ status: 400, json: { ok: false, error: { message: "Document was refused by the Broker" } } });
        return;
      }
      const current = api.current!;
      if (failure === "conflict") {
        current.service.version++;
        current.catalogRevision++;
        current.service.document = { filename: "colleague.json", byteLength: 100, sha256: "c".repeat(64) };
        current.service.definition.connectionSettings.securityScheme = "colleagueAuth";
      }
      if (url.searchParams.get("expectedVersion") !== String(current.service.version) || url.searchParams.get("expectedCatalogRevision") !== String(current.catalogRevision)) {
        await route.fulfill({ status: 409, json: { ok: false, error: { message: "Import changed; reload current state" } } });
        return;
      }
      current.service.version++;
      current.catalogRevision++;
      current.service.document = { filename: url.searchParams.get("filename")!, byteLength: body.length, sha256: createHash("sha256").update(body).digest("hex") };
      current.preview = { service: "inventory", serviceVersion: current.service.version, catalogRevision: current.catalogRevision, configRevision: "config", credentialVersions: {}, manifestHash: "manifest", createdAt: "", expiresAt: "", createdBy: "admin", manifest: { protocolVersion: "2.0", metadata: {}, tools: [] } };
      if (failure === "lost") { await route.abort("connectionreset"); return; }
      result = current;
    } else if (pathname === "/v1/admin/imports/inventory/preview") { api.reads++; api.events.push("read"); result = api.current; }
    else if (pathname === "/v1/admin/imports/inventory/discover") result = api.current;
    else if (pathname === "/v1/admin/policy/catalog") result = { services: [], resources: [], resourceGroups: [], executionContexts: { allowedValues: ["internal"], defaultContext: "internal", contextRequired: false }, subjects: { users: [], groups: [], anonymous: false } };
    else if (pathname === "/v1/admin/policy/status") result = { policyGeneration: 1, writable: true, authority: "managed", counts: { active: 0, disabled: 0, deleted: 0 }, managementScope: { kind: "global" } };
    else if (pathname.endsWith("/audit/options")) result = { services: [] };
    else if (pathname.endsWith("/audit/events")) result = { records: [], nextCursor: null };
    await route.fulfill({ json: { ok: true, result } });
  });
  return api;
}

async function openCreate(page: Page): Promise<Locator> {
  await page.goto(`${assets.baseUrl}/ui/admin/catalog?import=1`);
  const dialog = page.getByRole("dialog", { name: "Import service", exact: true });
  await dialog.getByLabel("Service ID").fill("inventory");
  await dialog.getByLabel("Display name").fill("Inventory");
  await dialog.getByLabel("API base URL").fill("https://api.example.test/v1");
  return dialog;
}

test("source changes preserve local drafts and upload only exact file bytes and upload settings", async ({ page }) => {
  const api = await mockApi(page);
  const dialog = await openCreate(page);
  await dialog.getByLabel("OpenAPI / Swagger definition URL").fill("https://docs.example.test/private.json");
  await dialog.getByLabel("Definition authentication").selectOption("raw_header");
  await dialog.getByLabel("Definition token header").fill("X-Document-Key");
  await dialog.getByRole("button", { name: "Upload file", exact: true }).click();
  await expect(dialog.getByLabel("API base URL")).toHaveValue("https://api.example.test/v1");
  await expect(dialog.getByLabel("Definition authentication")).toHaveCount(0);
  await dialog.getByLabel("Choose specification JSON file").setInputFiles(file("café & notes.json"));
  await expect(dialog).toContainText("Swagger 2.0");
  await dialog.getByRole("button", { name: "From URL", exact: true }).click();
  await expect(dialog.getByLabel("OpenAPI / Swagger definition URL")).toHaveValue("https://docs.example.test/private.json");
  await expect(dialog.getByLabel("Definition authentication")).toHaveValue("raw_header");
  await expect(dialog.getByLabel("Definition token header")).toHaveValue("X-Document-Key");
  await dialog.getByRole("button", { name: "Upload file", exact: true }).click();
  await expect(dialog).toContainText("café & notes.json");
  await dialog.getByRole("button", { name: "Create draft" }).click();
  await expect(page).toHaveURL(/\/services\/inventory\/import$/);
  expect(api.created).toHaveLength(1);
  expect(api.created[0]).toMatchObject({ endpoint: "https://api.example.test/v1", connectionSettings: { definitionSource: "upload" }, discovery: { kind: "anonymous" } });
  expect(api.created[0].connectionSettings).toEqual({ definitionSource: "upload" });
  expect(api.uploads).toHaveLength(1);
  expect(api.uploads[0].body.equals(Buffer.from(raw))).toBe(true);
  expect(api.uploads[0].query.get("filename")).toBe("café & notes.json");
  expect(api.uploads[0].headers["content-type"]).toBe("application/json");
  expect(api.uploads[0].headers["x-csrf-token"]).toBe("fixture");
  await expect(page.getByText("café & notes.json", { exact: false })).toBeVisible();
  await expect(page.getByRole("button", { name: "Load saved definition", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Set discovery token", exact: true })).toHaveCount(0);
  expect(api.errors).toEqual([]);
});

test("browse, drop, replace and remove enforce one bounded JSON source before creation", async ({ page }) => {
  const api = await mockApi(page);
  const dialog = await openCreate(page);
  await dialog.getByRole("button", { name: "Upload file", exact: true }).click();
  const input = dialog.getByLabel("Choose specification JSON file");
  await input.setInputFiles(file("bad.json", "not JSON"));
  await expect(dialog).toContainText("Choose a valid UTF-8 JSON specification.");
  await expect(dialog.getByRole("button", { name: "Create draft" })).toBeDisabled();
  await input.setInputFiles({ name: "large.json", mimeType: "application/json", buffer: Buffer.alloc(4 * 1024 * 1024 + 1) });
  await expect(dialog).toContainText("no larger than 4 MiB");
  const dropped = await page.evaluateHandle((text) => {
    const transfer = new DataTransfer();
    transfer.items.add(new File([text], "dropped.json", { type: "application/json" }));
    return transfer;
  }, raw);
  await dialog.locator(".pt-import-file-area").dispatchEvent("drop", { dataTransfer: dropped });
  await dropped.dispose();
  await expect(dialog).toContainText("dropped.json");
  await expect(dialog.getByRole("button", { name: "Create draft" })).toBeEnabled();
  const chooser = page.waitForEvent("filechooser");
  await dialog.getByRole("button", { name: "Replace file" }).click();
  await (await chooser).setFiles(file("replacement.json", '{"openapi":"3.1.1"}'));
  await expect(dialog).toContainText("OpenAPI 3.1.1");
  await expect(dialog).not.toContainText("dropped.json");
  const multiple = await page.evaluateHandle((text) => {
    const transfer = new DataTransfer();
    for (const name of ["one.json", "two.json"]) transfer.items.add(new File([text], name));
    return transfer;
  }, raw);
  await dialog.locator(".pt-import-file-area").dispatchEvent("drop", { dataTransfer: multiple });
  await multiple.dispose();
  await expect(dialog).toContainText("Choose one specification file.");
  await expect(dialog.getByRole("button", { name: "Create draft" })).toBeDisabled();
  await dialog.getByRole("button", { name: "Remove", exact: true }).click();
  await expect(dialog).not.toContainText("replacement.json");
  await expect(dialog).not.toContainText("Choose one specification file.");
  await dialog.getByRole("button", { name: "Create draft" }).click();
  await expect(dialog).toContainText("Choose a JSON specification file.");
  expect(api.created).toHaveLength(0);
  expect(api.uploads).toHaveLength(0);
  expect(api.errors).toEqual([]);
});

for (const failure of ["reject", "lost"] as const) {
  test(`a ${failure === "lost" ? "lost committed response" : "refused upload"} keeps one draft and requires visible current state before retry`, async ({ page }) => {
    const api = await mockApi(page);
    api.failNext = failure;
    const dialog = await openCreate(page);
    await dialog.getByRole("button", { name: "Upload file", exact: true }).click();
    await dialog.getByLabel("Choose specification JSON file").setInputFiles(file());
    await dialog.getByRole("button", { name: "Create draft" }).click();
    const retry = page.getByRole("dialog", { name: "Upload definition", exact: true });
    await expect(retry).toContainText("The upload was not confirmed");
    await expect(retry.getByRole("button", { name: "Open draft" })).toBeVisible();
    await expect(retry.getByRole("button", { name: "Upload and review" })).toBeDisabled();
    expect(api.created).toHaveLength(1);
    expect(api.uploads).toHaveLength(1);
    const reads = api.reads;
    // A concurrent administrator can advance both fences while the recovery dialog is open.
    api.current!.service.version += 3;
    api.current!.catalogRevision += 2;
    const version = api.current!.service.version, revision = api.current!.catalogRevision;
    await retry.getByRole("button", { name: "Reload current state" }).click();
    await expect(retry).toContainText(`Service revision ${version} · Catalog revision ${revision}`);
    await expect(retry).toContainText("Current state reloaded");
    if (failure === "lost") await expect(retry.getByLabel("Stored definition document")).toContainText("inventory.json");
    expect(api.reads).toBeGreaterThan(reads);
    expect(api.uploads).toHaveLength(1);
    const eventCount = api.events.length;
    await retry.getByRole("button", { name: "Upload and review" }).click();
    await expect(page).toHaveURL(/\/services\/inventory\/import$/);
    expect(api.events[eventCount]).toBe("upload");
    expect(api.uploads).toHaveLength(2);
    expect(api.uploads[1].query.get("expectedVersion")).toBe(String(version));
    expect(api.uploads[1].query.get("expectedCatalogRevision")).toBe(String(revision));
    expect(api.created).toHaveLength(1);
    expect(api.errors).toEqual([]);
  });
}

test("opening a draft after a lost response reveals the stored document without replaying its upload", async ({ page }) => {
  const api = await mockApi(page);
  api.failNext = "lost";
  const dialog = await openCreate(page);
  await dialog.getByRole("button", { name: "Upload file", exact: true }).click();
  await dialog.getByLabel("Choose specification JSON file").setInputFiles(file());
  await dialog.getByRole("button", { name: "Create draft" }).click();
  await page.getByRole("dialog", { name: "Upload definition", exact: true }).getByRole("button", { name: "Open draft" }).click();
  await expect(page).toHaveURL(/\/services\/inventory\/import$/);
  await expect(page.getByText("inventory.json", { exact: false })).toBeVisible();
  await expect(page.getByRole("button", { name: "Review preview", exact: true })).toBeEnabled();
  expect(api.created).toHaveLength(1);
  expect(api.uploads).toHaveLength(1);
  expect(api.errors).toEqual([]);
});

test("a concurrent replacement must be displayed before retry and later changes still conflict with the displayed versions", async ({ page }) => {
  const api = await mockApi(page);
  let dialog = await openCreate(page);
  await dialog.getByRole("button", { name: "Upload file", exact: true }).click();
  await dialog.getByLabel("Choose specification JSON file").setInputFiles(file());
  await dialog.getByRole("button", { name: "Create draft" }).click();
  await expect(page).toHaveURL(/\/services\/inventory\/import$/);
  await page.getByRole("button", { name: "Upload replacement", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Upload replacement definition", exact: true });
  await dialog.getByLabel("Choose specification JSON file").setInputFiles(file("replacement.json"));
  api.failNext = "conflict";
  await dialog.getByRole("button", { name: "Upload and review" }).click();
  await expect(dialog.getByRole("alert")).toContainText("Import changed");
  await expect(dialog.getByRole("button", { name: "Upload and review" })).toBeDisabled();
  await expect(dialog.getByLabel("Stored definition document")).toContainText("inventory.json");
  expect(api.uploads).toHaveLength(2);
  await dialog.getByRole("button", { name: "Reload current state" }).click();
  await expect(dialog.getByLabel("Stored definition document")).toContainText("colleague.json");
  await expect(dialog).toContainText("API security scheme: colleagueAuth");
  await expect(dialog.getByRole("group", { name: "Specification file", exact: true })).toContainText("replacement.json");
  const version = api.current!.service.version, revision = api.current!.catalogRevision;
  await expect(dialog).toContainText(`Service revision ${version} · Catalog revision ${revision}`);
  await expect(dialog.getByRole("button", { name: "Upload and review" })).toBeEnabled();
  // A later change must conflict, rather than being silently overwritten by a hidden pre-PUT read.
  api.current!.service.version++;
  api.current!.catalogRevision++;
  api.current!.service.document!.filename = "later.json";
  const eventCount = api.events.length;
  await dialog.getByRole("button", { name: "Upload and review" }).click();
  await expect(dialog.getByRole("button", { name: "Reload current state" })).toBeVisible();
  expect(api.events[eventCount]).toBe("upload");
  expect(api.uploads).toHaveLength(3);
  expect(api.uploads[2].query.get("expectedVersion")).toBe(String(version));
  expect(api.uploads[2].query.get("expectedCatalogRevision")).toBe(String(revision));
  expect(api.current!.service.document!.filename).toBe("later.json");
  await dialog.getByRole("button", { name: "Reload current state" }).click();
  await expect(dialog.getByLabel("Stored definition document")).toContainText("later.json");
  await dialog.getByRole("button", { name: "Upload and review" }).click();
  await expect(page.getByRole("dialog", { name: "Review discovered operations", exact: true })).toBeVisible();
  expect(api.current!.service.document!.filename).toBe("replacement.json");
  expect(api.created).toHaveLength(1);
  expect(api.errors).toEqual([]);
});

test("reloading a concurrently changed source prevents an upload into a URL import", async ({ page }) => {
  const api = await mockApi(page);
  const dialog = await openCreate(page);
  await dialog.getByRole("button", { name: "Upload file", exact: true }).click();
  await dialog.getByLabel("Choose specification JSON file").setInputFiles(file());
  api.failNext = "reject";
  await dialog.getByRole("button", { name: "Create draft" }).click();
  const retry = page.getByRole("dialog", { name: "Upload definition", exact: true });
  await expect(retry.getByRole("button", { name: "Reload current state" })).toBeVisible();
  api.current!.service.definition.connectionSettings = { definitionUrl: "https://docs.example.test/api.json" };
  api.current!.service.version++;
  await retry.getByRole("button", { name: "Reload current state" }).click();
  await expect(retry).toContainText("Definition source: From URL");
  await expect(retry).toContainText("This service no longer permits document uploads");
  await expect(retry.getByRole("button", { name: "Upload and review" })).toBeDisabled();
  expect(api.created).toHaveLength(1);
  expect(api.uploads).toHaveLength(1);
  expect(api.errors).toEqual([]);
});
