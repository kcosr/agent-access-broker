import { expect, test } from "@playwright/test";
import type { ImportPreviewResult } from "../src/import-types";
import { commandDiscovered } from "../unit/command-import.fixture";
import { mockCommandImportApi } from "./support/command-import-api";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

// Browser contract coverage uses explicit management responses. The Rust host
// receiver suite exercises the real Broker, reference store, and MCP transport.
let assets: PortalAssets;
test.beforeAll(async () => { assets = await servePortalAssets(); });
test.afterAll(async () => { await assets.close(); });
function receiverPreview(): ImportPreviewResult {
  const data = commandDiscovered();
  data.service.definition.adapterKind = "mcp_http";
  data.service.definition.endpoint = "https://tools.example.test/mcp";
  data.service.definition.discovery = { kind: "execution" };
  data.service.definition.executionBindings = [{ ownerMode: "service", mechanism: "static_token", delivery: { kind: "bearer" }, status: "configured" }];
  data.service.status = "enabled";
  delete data.service.acceptedMetadata;
  data.resourceTypeChanges = [];
  const definition = { action: "store_token", source: { toolName: "store_token" }, description: "Store a token", inputSchema: { type: "object", properties: { token: { type: "string", description: "Token value to store" }, label: { type: "string", description: "Display label" } }, required: ["token"] }, annotations: {}, readOnly: false };
  data.service.actions = [{ definition: structuredClone(definition), status: "enabled", version: 1, definitionHash: "source-hash", secretInputs: [] }];
  data.preview!.manifest = { protocolVersion: "2026-07-28", metadata: {}, tools: [{ definition, unsupportedReason: null, readOnlyHint: false }] };
  data.secretInputCandidates = [{ toolIndex: 0, pointers: ["/inputs/label", "/inputs/token"] }];
  data.affectedGrants = ["existing-grant"];
  data.affectedGrantsByAction = { store_token: ["existing-grant"] };
  return data;
}

test("receiver selections show receipt consequences and require affected-grant confirmation", async ({ page }) => {
  const data = receiverPreview();
  const api = await mockCommandImportApi(page, data);
  const accepted = structuredClone(data);
  accepted.service.actions[0].secretInputs = [{ pointer: "/inputs/token" }];
  api.acceptances.push({ result: accepted });
  await page.goto(`${assets.baseUrl}/ui/admin/catalog/services/ticketing/import`);
  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Review discovered tools", exact: true });
  await dialog.getByRole("checkbox", { name: "/inputs/token · string", exact: true }).check();
  await expect(dialog).toContainText("Token value to store");
  await expect(dialog).toContainText("Its upstream response content will be hidden for every call");
  await expect(dialog.getByRole("button", { name: "Accept selected tools", exact: true })).toBeDisabled();
  await dialog.getByRole("checkbox", { name: "I reviewed the affected grants and approve these action changes.", exact: true }).check();
  await dialog.getByRole("button", { name: "Accept selected tools", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(api.accepted[0]).toMatchObject({ selections: [{ source: { toolName: "store_token" }, action: "store_token", readOnly: false, secretInputs: [{ pointer: "/inputs/token" }] }], confirmAffectedGrants: true });
  expect(data.preview!.manifest.tools[0].definition.inputSchema.properties).toEqual({ token: { type: "string", description: "Token value to store" }, label: { type: "string", description: "Display label" } });
  expect(api.errors).toEqual([]);
});

test("ineligible retained receiver remains selected until explicitly corrected", async ({ page }) => {
  const data = receiverPreview();
  data.service.actions[0].secretInputs = [{ pointer: "/inputs/old_value" }];
  const api = await mockCommandImportApi(page, data);
  await page.goto(`${assets.baseUrl}/ui/admin/catalog/services/ticketing/import`);
  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Review discovered tools", exact: true });
  const stale = dialog.getByRole("checkbox", { name: "/inputs/old_value · string · no longer eligible; remove to accept", exact: true });
  await expect(stale).toBeChecked();
  await expect(dialog).toContainText("Remove or correct receiver fields that are no longer eligible");
  await expect(dialog.getByRole("button", { name: "Accept selected tools", exact: true })).toBeDisabled();
  await stale.click();
  await expect(stale).toHaveCount(0);
  await expect(dialog).toContainText("restores upstream response content for every call");
  await dialog.getByRole("checkbox", { name: "/inputs/token · string", exact: true }).check();
  await dialog.getByRole("checkbox", { name: "I reviewed the affected grants and approve these action changes.", exact: true }).check();
  await dialog.getByRole("button", { name: "Accept selected tools", exact: true }).click();
  await expect.poll(() => api.accepted.length).toBe(1);
  expect(api.accepted[0]).toMatchObject({ selections: [{ secretInputs: [{ pointer: "/inputs/token" }] }] });
  expect(api.errors).toEqual([]);
});
