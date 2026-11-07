import { expect, test, type Page } from "@playwright/test";
import type { ImportActionDefinition, ImportPreviewResult } from "../src/import-types";
import { BASIC_INPUT } from "../unit/credential-input.fixture";
import { ADMIN_SESSION } from "./support/command-import-api";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

// Mocked management metadata: these tests cover preview presentation only.
// Real document discovery and HTTP dispatch have separate OpenAPI and Swagger suites.
let assets: PortalAssets;
test.beforeAll(async () => { assets = await servePortalAssets(); });
test.afterAll(async () => { await assets.close(); });

function preview(protocolVersion: string): ImportPreviewResult {
  const operation = (action: string, method: string, path: string, inputSchema: Record<string, unknown>, body: Record<string, unknown>): ImportActionDefinition => ({
    action, source: { operationId: action }, description: action, inputSchema, readOnly: false,
    annotations: { openapi: { method, path, ...body } }
  });
  const form = operation("submit_form", "POST", "/search", { type: "object", properties: { body: { type: "object", properties: { query: { type: "string" }, page: { type: "integer" } }, required: ["query"], additionalProperties: false } }, required: ["body"], additionalProperties: false }, {
    requestBody: true, formBody: { fields: [{ name: "query", valueType: "string", required: true }, { name: "page", valueType: "integer", required: false }] }
  });
  const json = operation("submit_json", "POST", "/items", {
    type: "object", properties: { body: { $ref: "#/$defs/item" } }, required: [],
    $defs: { item: { type: "object", properties: { name: { type: "string" }, note: { type: "string" } }, required: ["name"] } }
  }, { requestBody: true });
  const unsupported = operation("upload", "POST", "/uploads", {}, {});
  const get = operation("list_items", "GET", "/items", { type: "object" }, { requestBody: false });
  return {
    catalogRevision: 1, operatorAllowed: true, importAuthentication: [], affectedGrants: [], affectedGrantsByAction: {},
    scopedMcp: { ready: false, issues: [{ code: "service_unavailable", actions: [] }], truncated: false }, scopedMcpWarnings: [],
    service: {
      definition: { service: "inventory", displayName: "Inventory", adapterKind: "openapi_http", endpoint: "https://api.example.test", connectionSettings: { definitionUrl: "https://docs.example.test/api.json", securityScheme: "basic" }, executionBindings: [{ ownerMode: "service", mechanism: "static_token", delivery: { kind: "basic" }, status: "configured" }], discovery: { kind: "anonymous" }, transportAuth: false },
      status: "draft", version: 1, actions: [], slotVersions: {}, credentialInputs: { execution: BASIC_INPUT }, createdAt: "", updatedAt: "", createdBy: "admin", updatedBy: "admin"
    },
    preview: {
      service: "inventory", serviceVersion: 1, catalogRevision: 1, configRevision: "config", credentialVersions: {}, manifestHash: "manifest", createdAt: "", expiresAt: "", createdBy: "admin",
      manifest: { protocolVersion, metadata: {}, tools: [form, json, unsupported, get].map((definition) => ({ definition, readOnlyHint: null, unsupportedReason: definition === unsupported ? "multipart request bodies are unsupported" : null })) }
    }
  };
}

async function mockPreview(page: Page, data: ImportPreviewResult) {
  await page.route("**/v1/**", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    let result: unknown = [];
    if (pathname === "/v1/auth/session") result = ADMIN_SESSION;
    else if (pathname === "/v1/resource-types" || pathname === "/v1/me") {
      await route.fulfill({ json: pathname === "/v1/me" ? { principal: "admin", serviceLimits: [] } : { resourceTypes: [] } });
      return;
    } else if (pathname === "/v1/admin/imports") result = { catalogRevision: 1, operatorEnabled: true, gatewayBindings: [], availableKinds: ["openapi_http"], commandImports: [], importAuthentication: [], services: [data.service] };
    else if (pathname === "/v1/admin/imports/inventory/preview") result = data;
    else if (pathname === "/v1/admin/policy/catalog") result = { services: [], resources: [], resourceGroups: [], executionContexts: { allowedValues: ["internal"], defaultContext: "internal", contextRequired: false }, subjects: { users: [], groups: [], anonymous: false } };
    else if (pathname === "/v1/admin/policy/status") result = { policyGeneration: 1, writable: true, authority: "managed", counts: { active: 0, disabled: 0, deleted: 0 }, managementScope: { kind: "global" } };
    else if (pathname.endsWith("/audit/options")) result = { services: [] };
    else if (pathname.endsWith("/audit/events")) result = { records: [], nextCursor: null };
    await route.fulfill({ json: { ok: true, result } });
  });
}

for (const protocolVersion of ["2.0", "3.1.0"]) {
  test(`${protocolVersion} previews distinguish required bodies, required fields and unsupported body plans`, async ({ page }) => {
    const data = preview(protocolVersion);
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await mockPreview(page, data);
    await page.goto(`${assets.baseUrl}/ui/admin/catalog/services/inventory/import`);
    await page.getByRole("button", { name: "Review preview", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Review discovered operations", exact: true });
    await expect(dialog).toContainText(protocolVersion === "2.0" ? "Source: Swagger 2.0" : "Source: OpenAPI 3.1.0");
    const form = dialog.locator(".pt-catalog-op").filter({ hasText: "POST /search" });
    await expect(form).toContainText("application/x-www-form-urlencoded");
    await expect(form).toContainText("Body required");
    await expect(form).toContainText("Required body fields: query");
    await expect(form).not.toContainText("page");
    const json = dialog.locator(".pt-catalog-op").filter({ hasText: "POST /items" });
    await expect(json).toContainText("application/json");
    await expect(json).toContainText("Body optional");
    await expect(json).toContainText("Required fields when body is supplied: name");
    await expect(json).not.toContainText("note");
    const unsupported = dialog.locator(".pt-catalog-review-item").filter({ hasText: "POST /uploads" });
    await expect(unsupported).toContainText("multipart request bodies are unsupported");
    await expect(unsupported).not.toContainText("No request body");
    await expect(unsupported).not.toContainText("Body optional");
    await expect(dialog.locator(".pt-catalog-op").filter({ hasText: "GET /items" })).toContainText("No request body");
    expect(errors).toEqual([]);
  });
}


test("long operation names keep concise review labels and responsive fields", async ({ page }) => {
  const source = "list_records_with_extended_metadata_and_configuration_for_archived_workspace_entries";
  const data = preview("2.0");
  const tool = data.preview!.manifest.tools[0];
  tool.definition.action = source;
  tool.definition.source = { operationId: source };
  tool.definition.description = `${"A detailed description of the operation and its returned records. ".repeat(8)}${"extended_record_attribute_".repeat(8)}`;
  tool.readOnlyHint = true;
  data.preview!.manifest.tools = [tool];
  await mockPreview(page, data);
  await page.goto(`${assets.baseUrl}/ui/admin/catalog/services/inventory/import`);
  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Review discovered operations", exact: true });
  const row = dialog.locator(".pt-catalog-review-item");
  await expect(row.getByLabel(`Action name for ${source}`, { exact: true })).toHaveValue(source);
  await expect(row.getByLabel(`Display label for ${source}`, { exact: true })).toBeEditable();
  await expect(row.getByLabel(`Effects for ${source}`, { exact: true })).toHaveValue("write");
  const labels = await row.locator(".pt-catalog-review-fields .wb-field-label").evaluateAll((elements) => elements.map((element) => {
    const copy = element.cloneNode(true) as HTMLElement;
    copy.querySelectorAll(".wb-sr-only").forEach((suffix) => suffix.remove());
    return copy.textContent?.trim();
  }));
  expect(labels).toEqual(["Action name", "Display label", "Effects"]);
  await expect(row.locator(".wb-field-hint")).toHaveText("Upstream suggests read-only.");
  await row.locator(".pt-catalog-more > summary").click();
  await expect(row.locator(".pt-catalog-more")).toHaveAttribute("open", "");

  for (const width of [1280, 700, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    const layout = await row.evaluate((element) => {
      const fields = [...element.querySelectorAll<HTMLElement>(".pt-catalog-review-fields > .wb-field")];
      const bounds = fields.map((field) => field.getBoundingClientRect());
      const within = (inner: DOMRect, outer: DOMRect) => inner.left >= outer.left - 1 && inner.right <= outer.right + 1;
      const modal = element.closest<HTMLElement>(".wb-modal")!;
      const modalBody = modal.querySelector<HTMLElement>(".wb-modal-body")!;
      const modalBounds = modal.getBoundingClientRect();
      return {
        tops: bounds.map((bound) => Math.round(bound.top)),
        fieldWidths: bounds.map((bound) => bound.width),
        overflow: fields.flatMap((field, index) => [...field.querySelectorAll<HTMLElement>(".wb-field-label, .wb-field-hint, input, select")]
          .filter((child) => !within(child.getBoundingClientRect(), bounds[index]))
          .map((child) => child.tagName)),
        textOverflow: fields.flatMap((field) => [...field.querySelectorAll<HTMLElement>(".wb-field-label, .wb-field-hint")]
          .filter((child) => child.scrollWidth > child.clientWidth + 1)
          .map((child) => child.className)),
        hiddenSuffixes: [...element.querySelectorAll<HTMLElement>(".wb-field-label .wb-sr-only")].every((suffix) => suffix.getBoundingClientRect().width <= 1 && suffix.getBoundingClientRect().height <= 1),
        cardFits: element.scrollWidth <= element.clientWidth + 1,
        modalBodyFits: modalBody.scrollWidth <= modalBody.clientWidth + 1,
        modalFits: modalBounds.left >= -1 && modalBounds.right <= window.innerWidth + 1
      };
    });
    expect(layout.overflow, `${width}px fields stay inside their columns`).toEqual([]);
    expect(layout.textOverflow, `${width}px labels and hints stay inside their boxes`).toEqual([]);
    expect(layout.hiddenSuffixes, `${width}px operation suffixes stay visually hidden`).toBe(true);
    expect(layout.cardFits, `${width}px long description stays inside the card`).toBe(true);
    expect(layout.modalBodyFits, `${width}px dialog content does not overflow horizontally`).toBe(true);
    expect(layout.modalFits, `${width}px dialog stays inside the viewport`).toBe(true);
    if (width === 1280) {
      expect(new Set(layout.tops).size).toBeLessThan(3);
      expect(layout.fieldWidths.every((fieldWidth) => fieldWidth >= 220), "desktop fields keep usable widths").toBe(true);
    }
    if (width <= 390) expect(new Set(layout.tops).size).toBe(3);
  }
});
