import { vi } from "vitest";
vi.mock("../src/app/session", () => ({ useSession: () => ({ session: { authenticated: true, role: "admin", selfServiceEnabled: true, principal: "admin" } }) }));
import { describe, expect, test } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { ImportActionDefinition, ImportPreviewResult } from "../src/import-types";
import { openApiBindings, openApiDelivery, openApiOperation, openApiSecuritySchemes } from "../src/lib/import-openapi";
import { importReviewRows } from "../src/lib/imports";
import { openApiConnectionSettings } from "../src/lib/import-openapi";
import { ImportEditor } from "../src/features/catalog/import-editor";
import { ImportReview, ScopedMcpStatus } from "../src/features/catalog/import-review";
import { inlineFrame } from "../src/features/catalog/catalog-ui";

function fixture(): ImportPreviewResult {
  const definition: ImportActionDefinition = { action: "read", source: { operationId: "read" }, description: "Read an item", inputSchema: { type: "object" }, annotations: { openapi: { method: "get", path: "/items/{id}", security: { scheme: "apiKey", kind: "raw_header", header: "X-Api-Key" } } }, readOnly: false };
  return { operatorAllowed: true, scopedMcp: { ready: false, issues: [{ code: "service_unavailable", actions: [] }], truncated: false }, scopedMcpWarnings: [], catalogRevision: 1, oauthRegistrations: [], affectedGrants: [], affectedGrantsByAction: {}, service: { definition: { service: "inventory", displayName: "Inventory", adapterKind: "openapi_http", endpoint: "https://api.example.test/v1", connectionSettings: { definitionUrl: "https://docs.example.test/openapi.json", definitionAuthKind: "none" }, executionBindings: [{ ownerMode: "service", mechanism: "static_token", delivery: { kind: "bearer" }, status: "configured" }], discovery: { kind: "anonymous" }, transportAuth: false }, status: "draft", version: 1, actions: [], slotVersions: {}, createdAt: "", updatedAt: "", createdBy: "admin", updatedBy: "admin" }, preview: { service: "inventory", serviceVersion: 1, catalogRevision: 1, configRevision: "config", credentialVersions: {}, manifestHash: "manifest", manifest: { protocolVersion: "3.1.0", metadata: { securitySchemes: [{ name: "apiKey", kind: "raw_header", header: "X-Api-Key" }, { name: "bearer", kind: "bearer" }, { name: "oauth", kind: "oauth" }, { name: "broken", kind: "raw_header" }] }, tools: [{ definition, unsupportedReason: null, readOnlyHint: null }] }, createdAt: "", expiresAt: "", createdBy: "admin" } };
}
function renderEditor(data?: ImportPreviewResult, availableKinds = ["openapi_http"]) {
  return renderToStaticMarkup(createElement(ImportEditor, { principal: "admin", data, availableKinds, registrations: [], onClose: () => {}, onSave: async () => true, frame: inlineFrame }));
}
describe("OpenAPI import configuration", () => {
  test("frozen label and limit edits preserve CLI-created settings with omitted defaults", () => {
    const stored = { definitionUrl: "https://docs.example.test/openapi.json", securityScheme: "apiKey" };
    const settings = openApiConnectionSettings(stored, false, { definitionUrl: stored.definitionUrl, definitionAuthKind: "none", definitionAuthHeader: "", securityScheme: stored.securityScheme });
    expect(settings).toEqual(stored);
    expect(settings).not.toHaveProperty("definitionAuthKind");
    expect(openApiConnectionSettings(stored, true, { definitionUrl: stored.definitionUrl, definitionAuthKind: "none", definitionAuthHeader: "", securityScheme: stored.securityScheme })).toEqual(stored);
    expect(renderEditor(fixture())).toContain("removes stored execution and discovery tokens");
  });
  test("public document onboarding separates API and document destinations and omits OAuth", () => {
    const html = renderEditor();
    expect(html).toContain("API base URL");
    expect(html).toContain("OpenAPI definition URL");
    expect(html).toContain("Public document (no credentials)");
    expect(html).toContain("Loading this document sends no credentials");
    expect(html).not.toContain("OAuth connection");
    expect(html).not.toContain("Separate transport bearer");
    expect(html).not.toContain("HTTP MCP");
  });
  test("private document credentials remain independent of the selected API scheme", () => {
    const data = fixture();
    data.service.definition.connectionSettings.definitionAuthKind = "raw_header";
    data.service.definition.connectionSettings.definitionAuthHeader = "X-Document-Token";
    data.service.definition.connectionSettings.securityScheme = "bearer";
    data.service.definition.discovery = { kind: "slot" };
    const html = renderEditor(data);
    expect(html).toContain("X-Document-Token");
    expect(html).toContain("This token only reads the definition document");
    expect(html).toContain("Token delivery: Authorization: Bearer");
  });
  test("scheme selection permits only supported modes and updates delivery for both owner modes", () => {
    const schemes = openApiSecuritySchemes(fixture().preview!.manifest);
    expect(schemes.map((scheme) => scheme.name)).toEqual(["apiKey", "bearer"]);
    const existing = openApiBindings([], true, true, { kind: "bearer" });
    const updated = openApiBindings(existing, false, false, openApiDelivery(schemes[0]));
    expect(updated.map((binding) => binding.ownerMode)).toEqual(["service", "per_user"]);
    expect(updated.every((binding) => binding.delivery.kind === "raw_header" && binding.delivery.name === "X-Api-Key" && binding.mechanism === "static_token")).toBe(true);
  });
  test("accepting any action fixes document settings and API token delivery", () => {
    const data = fixture();
    const draft = renderEditor(data);
    expect(draft).not.toContain("The definition settings and token delivery are fixed");
    expect(draft.match(/<input[^>]*value="https:\/\/docs.example.test\/openapi.json"[^>]*>/)?.[0]).not.toContain('disabled=""');
    data.service.actions.push({ definition: data.preview!.manifest.tools[0].definition, status: "retired", version: 1, definitionHash: "hash" });
    const accepted = renderEditor(data);
    expect(accepted).toContain("The definition settings and token delivery are fixed");
    expect(accepted.match(/<input[^>]*value="https:\/\/docs.example.test\/openapi.json"[^>]*>/)?.[0]).toContain('disabled=""');
    expect(renderEditor(data, [])).toContain("openapi_http (unavailable)");
  });
  test("route or security changes require review under the existing operation identity", () => {
    const data = fixture();
    data.service.actions.push({ definition: structuredClone(data.preview!.manifest.tools[0].definition), status: "enabled", version: 1, definitionHash: "hash" });
    data.service.actions[0].definition.readOnly = true;
    expect(importReviewRows(data)[0]).toMatchObject({ change: "Unchanged", selected: true, readOnly: true });
    (data.preview!.manifest.tools[0].definition.annotations as { openapi: { path: string } }).openapi.path = "/v2/items/{id}";
    expect(importReviewRows(data)[0]).toMatchObject({ change: "Changed", selected: false, readOnly: false, action: "read" });
    expect(openApiOperation(data.preview!.manifest.tools[0].definition)).toMatchObject({ method: "GET", path: "/v2/items/{id}", security: { name: "apiKey" } });
    const html = renderToStaticMarkup(createElement(ImportReview, { data, onClose: () => {}, onAccept: async () => true, frame: inlineFrame }));
    expect(html).toContain("Review discovered operations");
    expect(html).toContain("GET /v2/items/{id}");
    expect(html).toContain("apiKey · X-Api-Key");
    expect(html).not.toContain("Upstream suggests read-only");
  });
  test("committed readiness and provisional scoped warnings are distinct and do not block selection", () => {
    const data = fixture();
    data.scopedMcp = { ready: true, issues: [], truncated: false };
    data.scopedMcpWarnings = [{ toolIndex: 0, proposedAction: "read", codes: ["reserved_name"] }];
    const html = renderToStaticMarkup(createElement(ImportReview, { data, onClose: () => {}, onAccept: async () => true, frame: inlineFrame }));
    expect(html).toContain("Current service-specific MCP");
    expect(html).toContain("Ready");
    expect(html).toContain("Provisional service-specific MCP warning for read");
    expect(html).toContain("do not prevent acceptance or aggregate MCP use");
    expect(html).toContain('aria-label="Accept read"');
    const diagnostics = renderToStaticMarkup(createElement(ScopedMcpStatus, { value: { ready: false, issues: [{ code: "duplicate_name", actions: ["one", "two"] }], truncated: true } }));
    expect(diagnostics).toContain("Multiple actions use the same tool name.");
    expect(diagnostics).toContain("Actions: one, two.");
    expect(diagnostics).toContain("Additional issue details omitted.");
  });
  test("a changed discovered header does not alter delivery when editing an accepted service", () => {
    const data = fixture();
    data.service.definition.connectionSettings.securityScheme = "apiKey";
    data.service.definition.executionBindings[0].delivery = { kind: "raw_header", name: "X-Original-Key" };
    data.service.actions.push({ definition: data.preview!.manifest.tools[0].definition, status: "quarantined", version: 1, definitionHash: "hash" });
    const html = renderEditor(data);
    expect(html).toContain("Token delivery: X-Original-Key.");
    expect(html).toContain("The discovered scheme now uses different token delivery");
  });
});
