import { expect, test, type Page } from "@playwright/test";
import type { ImportDefinition, ImportPreviewResult } from "../src/import-types";
import { GATEWAY_BINDING, gatewayImportList, gatewayOperation, gatewayPolicyService, gatewayPreview } from "../unit/gateway-import.fixture";
import { ADMIN_SESSION } from "./support/command-import-api";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

// Mocked management API contracts. Real import compilation, publication and
// HTTP execution are covered by the gateway integration fixtures separately.
let assets: PortalAssets;
test.beforeAll(async () => { assets = await servePortalAssets(); });
test.afterAll(async () => { await assets.close(); });

async function fixture(page: Page, initial?: ImportPreviewResult) {
  const api = { current: initial, writes: [] as Array<{ path: string; body: unknown }>, errors: [] as string[] };
  page.on("pageerror", (error) => api.errors.push(error.message));
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    let result: unknown = [];
    if (request.method() !== "GET") api.writes.push({ path, body: request.postDataJSON() });
    if (path === "/v1/auth/session") result = ADMIN_SESSION;
    else if (path === "/v1/resource-types" || path === "/v1/me") {
      await route.fulfill({ json: path === "/v1/me" ? { principal: "admin", serviceLimits: [] } : { resourceTypes: [] } });
      return;
    } else if (path === "/v1/admin/imports" && request.method() === "POST") {
      api.current = gatewayPreview();
      api.current.service.definition = request.postDataJSON() as ImportDefinition;
      api.current.service.document = null;
      api.current.preview = null;
      result = api.current;
    } else if (path === "/v1/admin/imports") result = gatewayImportList(api.current);
    else if (path === "/v1/admin/imports/inventory/accept" && api.current) {
      const body = request.postDataJSON() as { selections: Array<{ source: Record<string, unknown>; action: string; readOnly: boolean }> };
      api.current.service.actions = body.selections.map((selection) => ({
        definition: { ...gatewayOperation(selection.action), source: selection.source, readOnly: selection.readOnly },
        status: "enabled", version: 1, definitionHash: "accepted"
      }));
      api.current.service.version += 1;
      api.current.catalogRevision += 1;
      result = api.current;
    } else if (path === "/v1/admin/imports/inventory" && request.method() === "PUT" && api.current) {
      api.current.service.definition = request.postDataJSON().definition as ImportDefinition;
      result = api.current;
    } else if (path.startsWith("/v1/admin/imports/inventory")) result = api.current;
    else if (path === "/v1/admin/policy/catalog") result = {
      services: api.current ? [gatewayPolicyService(api.current)] : [], resources: [], resourceGroups: [],
      executionContexts: { allowedValues: ["internal"], defaultContext: "internal", contextRequired: false },
      subjects: { users: [], groups: [], anonymous: false }
    };
    else if (path === "/v1/admin/policy/status") result = { policyGeneration: 1, writable: true, authority: "managed", counts: { active: 0, disabled: 0, deleted: 0 }, managementScope: { kind: "global" } };
    else if (path.endsWith("/audit/options")) result = { services: [] };
    else if (path.endsWith("/audit/events")) result = { records: [], nextCursor: null };
    await route.fulfill({ json: { ok: true, result } });
  });
  return api;
}

test("creates an anonymous gateway from an approved binding and retains its exposure", async ({ page }) => {
  const api = await fixture(page);
  await page.goto(`${assets.baseUrl}/ui/admin/catalog?import=1`);
  const editor = page.getByRole("dialog", { name: "Import service", exact: true });
  await editor.getByLabel("Import type", { exact: true }).selectOption("openapi");
  await editor.getByLabel("Exposure", { exact: true }).selectOption("openapi_gateway");
  await expect(editor.getByRole("button", { name: "Create draft", exact: true })).toBeDisabled();
  await editor.getByLabel("Approved gateway binding", { exact: true }).selectOption("inventory");
  await expect(editor.getByLabel("Service ID", { exact: true })).toHaveValue("inventory");
  await expect(editor.getByLabel("Service ID", { exact: true })).toBeDisabled();
  await expect(editor.getByLabel("API base URL", { exact: true })).toHaveValue(GATEWAY_BINDING.endpoint);
  await expect(editor.getByLabel("API base URL", { exact: true })).toBeDisabled();
  await editor.getByLabel("Display name", { exact: true }).fill("Inventory gateway");
  await editor.getByLabel("OpenAPI / Swagger definition URL", { exact: true }).fill("https://docs.example.test/inventory.json");
  await editor.getByLabel("Upstream authentication", { exact: true }).selectOption("anonymous");
  await expect(editor.getByLabel("Shared service credential", { exact: true })).toHaveCount(0);
  await expect(editor.getByLabel("API security scheme", { exact: true })).toHaveCount(0);
  await editor.getByRole("button", { name: "Create draft", exact: true }).click();
  await expect.poll(() => api.writes[0]).toEqual({ path: "/v1/admin/imports", body: {
    service: "inventory", displayName: "Inventory gateway", adapterKind: "openapi_gateway", endpoint: GATEWAY_BINDING.endpoint,
    connectionSettings: { definitionUrl: "https://docs.example.test/inventory.json", definitionAuthKind: "none", executionAuthentication: "anonymous" },
    executionBindings: [], discovery: { kind: "anonymous" }, transportAuth: false
  } });
  await expect(page).toHaveURL(/\/ui\/admin\/catalog\/services\/inventory\/import$/);
  await expect(page.getByText("Gateway address example:", { exact: false })).toContainText("https://inventory.gateway.example.test/<operation-path>");
  await page.getByRole("button", { name: "Edit configuration", exact: true }).click();
  const edit = page.getByRole("dialog", { name: "Edit imported service", exact: true });
  await expect(edit.getByLabel("Import type", { exact: true })).toBeDisabled();
  await expect(edit.getByLabel("Exposure", { exact: true })).toHaveValue("openapi_gateway");
  await expect(edit.getByLabel("Exposure", { exact: true })).toBeDisabled();
  await expect(edit.getByLabel("Approved gateway binding", { exact: true })).toBeDisabled();
  expect(api.errors).toEqual([]);
});

test("chooses static upstream authentication independently of Broker ingress", async ({ page }) => {
  const api = await fixture(page, gatewayPreview());
  await page.goto(`${assets.baseUrl}/ui/admin/catalog/services/inventory/import`);
  await page.getByRole("button", { name: "Edit configuration", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "Edit imported service", exact: true });
  await editor.getByLabel("Upstream authentication", { exact: true }).selectOption("static");
  await editor.getByLabel("Shared service credential", { exact: true }).check();
  await editor.getByLabel("API security scheme", { exact: true }).selectOption("basic");
  await expect(editor).toContainText("Broker ingress: Broker Bearer token");
  await expect(editor).toContainText("Credential delivery: Authorization: Basic");
  await expect(editor).toContainText("no active credential verification probe");
  await editor.getByRole("button", { name: "Save configuration", exact: true }).click();
  await expect.poll(() => api.writes[0]?.body).toMatchObject({ definition: {
    adapterKind: "openapi_gateway", endpoint: GATEWAY_BINDING.endpoint,
    connectionSettings: { definitionSource: "upload", executionAuthentication: "static", securityScheme: "basic" },
    executionBindings: [{ ownerMode: "service", mechanism: "static_token", status: "configured", delivery: { kind: "basic" } }]
  } });
  await expect(editor).toHaveCount(0);
  expect(api.errors).toEqual([]);
});

test("reviews raw HTTP semantics and requires approval for quarantined action changes", async ({ page }) => {
  const data = gatewayPreview();
  data.service.actions = [{ definition: gatewayOperation(), status: "quarantined", version: 2, definitionHash: "old" }];
  data.preview!.manifest.tools[0]!.definition = gatewayOperation("get_item", "GET", "/items/{id}/detail");
  data.affectedGrantsByAction = { get_item: ["readers"] };
  const api = await fixture(page, data);
  await page.goto(`${assets.baseUrl}/ui/admin/catalog/services/inventory/import`);
  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  const review = page.getByRole("dialog", { name: "Review discovered operations", exact: true });
  await expect(review).toContainText("Whole-action access");
  await expect(review).toContainText("Body schema not validated by gateway");
  await expect(review).toContainText("GET /items/{id}/detail");
  await expect(review).toContainText("X-Api-Version");
  await expect(review.getByRole("group", { name: "Current service-specific MCP readiness", exact: true })).toHaveCount(0);
  await expect(review.getByLabel("Accept get_item", { exact: true })).not.toBeChecked();
  await review.getByLabel("Accept get_item", { exact: true }).check();
  await review.getByLabel("Effects for get_item", { exact: true }).selectOption("read");
  const accept = review.getByRole("button", { name: "Accept selected operations", exact: true });
  await expect(accept).toBeDisabled();
  await review.getByLabel("I reviewed the affected grants and approve these action changes.", { exact: true }).check();
  await accept.click();
  await expect.poll(() => api.writes.find((write) => write.path.endsWith("/accept"))?.body).toMatchObject({
    manifestHash: "manifest", confirmAffectedGrants: true,
    selections: [{ action: "get_item", readOnly: true, source: { operationId: "get_item" } }]
  });
  await expect(review).toHaveCount(0);
  expect(api.errors).toEqual([]);
});
