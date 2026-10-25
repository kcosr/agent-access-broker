import { expect, test } from "@playwright/test";
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

for (const protocolVersion of ["2.0", "3.1.0"]) {
  test(`${protocolVersion} previews distinguish required bodies, required fields and unsupported body plans`, async ({ page }) => {
    const data = preview(protocolVersion);
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route("**/v1/**", async (route) => {
      const pathname = new URL(route.request().url()).pathname;
      let result: unknown = [];
      if (pathname === "/v1/auth/session") result = ADMIN_SESSION;
      else if (pathname === "/v1/resource-types" || pathname === "/v1/me") {
        await route.fulfill({ json: pathname === "/v1/me" ? { principal: "admin", serviceLimits: [] } : { resourceTypes: [] } });
        return;
      } else if (pathname === "/v1/admin/imports") result = { catalogRevision: 1, operatorEnabled: true, availableKinds: ["openapi_http"], commandImports: [], importAuthentication: [], services: [data.service] };
      else if (pathname === "/v1/admin/imports/inventory/preview") result = data;
      else if (pathname === "/v1/admin/policy/catalog") result = { services: [], resources: [], resourceGroups: [], executionContexts: { allowedValues: ["internal"], defaultContext: "internal", contextRequired: false }, subjects: { users: [], groups: [], anonymous: false } };
      else if (pathname === "/v1/admin/policy/status") result = { policyGeneration: 1, writable: true, authority: "managed", counts: { active: 0, disabled: 0, deleted: 0 }, managementScope: { kind: "global" } };
      else if (pathname.endsWith("/audit/options")) result = { services: [] };
      else if (pathname.endsWith("/audit/events")) result = { records: [], nextCursor: null };
      await route.fulfill({ json: { ok: true, result } });
    });
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
