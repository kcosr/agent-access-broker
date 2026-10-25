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
import { ImportReview, OperationDetails, ScopedMcpStatus } from "../src/features/catalog/import-review";
import { inlineFrame } from "../src/features/catalog/catalog-ui";

function fixture(): ImportPreviewResult {
  const definition: ImportActionDefinition = { action: "read", source: { operationId: "read" }, description: "Read an item", inputSchema: { type: "object" }, annotations: { openapi: { method: "get", path: "/items/{id}", security: { scheme: "apiKey", kind: "raw_header", header: "X-Api-Key" } } }, readOnly: false };
  return { operatorAllowed: true, scopedMcp: { ready: false, issues: [{ code: "service_unavailable", actions: [] }], truncated: false }, scopedMcpWarnings: [], catalogRevision: 1, importAuthentication: [], affectedGrants: [], affectedGrantsByAction: {}, service: { definition: { service: "inventory", displayName: "Inventory", adapterKind: "openapi_http", endpoint: "https://api.example.test/v1", connectionSettings: { definitionUrl: "https://docs.example.test/openapi.json", definitionAuthKind: "none" }, executionBindings: [{ ownerMode: "service", mechanism: "static_token", delivery: { kind: "bearer" }, status: "configured" }], discovery: { kind: "anonymous" }, transportAuth: false }, status: "draft", version: 1, actions: [], slotVersions: {}, credentialInputs: {}, createdAt: "", updatedAt: "", createdBy: "admin", updatedBy: "admin" }, preview: { service: "inventory", serviceVersion: 1, catalogRevision: 1, configRevision: "config", credentialVersions: {}, manifestHash: "manifest", manifest: { protocolVersion: "3.1.0", metadata: { securitySchemes: [{ name: "apiKey", kind: "raw_header", header: "X-Api-Key" }, { name: "bearer", kind: "bearer" }, { name: "oauth", kind: "oauth" }, { name: "broken", kind: "raw_header" }] }, tools: [{ definition, unsupportedReason: null, readOnlyHint: null }] }, createdAt: "", expiresAt: "", createdBy: "admin" } };
}
function renderEditor(data?: ImportPreviewResult, availableKinds = ["openapi_http"]) {
  return renderToStaticMarkup(createElement(ImportEditor, { principal: "admin", data, availableKinds, authentication: [], onClose: () => {}, onSave: async () => true, frame: inlineFrame }));
}
describe("OpenAPI import configuration", () => {
  test("upload configuration excludes retained URL authentication drafts and preserves accepted settings", () => {
    const draft = { source: "upload" as const, definitionUrl: "https://docs.example.test/api.json", definitionAuthKind: "raw_header", definitionAuthHeader: "X-Document-Key", securityScheme: "basic" };
    expect(openApiConnectionSettings(undefined, true, draft)).toEqual({ definitionSource: "upload", securityScheme: "basic" });
    const stored = { definitionSource: "upload", securityScheme: "original" };
    expect(openApiConnectionSettings(stored, false, draft)).toBe(stored);
    expect(openApiConnectionSettings(stored, true, { ...draft, securityScheme: "original" })).toBe(stored);
    expect(openApiConnectionSettings(stored, true, { ...draft, source: "url" })).toEqual({ definitionUrl: draft.definitionUrl, definitionAuthKind: "raw_header", definitionAuthHeader: "X-Document-Key", securityScheme: "basic" });
  });
  test("retained uploaded documents expose a summary and no document URL or credential controls", () => {
    const data = fixture();
    data.service.definition.connectionSettings = { definitionSource: "upload" };
    data.service.document = { filename: "café.json", byteLength: 2048, sha256: "a".repeat(64) };
    const html = renderEditor(data);
    expect(html).toContain("café.json");
    expect(html).toContain("Stored by the Broker");
    expect(html).toContain("API base URL");
    expect(html).not.toContain("OpenAPI / Swagger definition URL");
    expect(html).not.toContain("Definition authentication");
    expect(html).not.toContain("Definition token header");
    expect(html).not.toContain("a".repeat(64));
  });
  test("frozen label and limit edits preserve CLI-created settings with omitted defaults", () => {
    const stored = { definitionUrl: "https://docs.example.test/openapi.json", securityScheme: "apiKey" };
    const settings = openApiConnectionSettings(stored, false, { source: "url", definitionUrl: stored.definitionUrl, definitionAuthKind: "none", definitionAuthHeader: "", securityScheme: stored.securityScheme });
    expect(settings).toEqual(stored);
    expect(settings).not.toHaveProperty("definitionAuthKind");
    expect(openApiConnectionSettings(stored, true, { source: "url", definitionUrl: stored.definitionUrl, definitionAuthKind: "none", definitionAuthHeader: "", securityScheme: stored.securityScheme })).toEqual(stored);
    expect(renderEditor(fixture())).toContain("removes stored execution and discovery credentials");
  });
  test("public document onboarding separates API and document destinations and omits OAuth", () => {
    const html = renderEditor();
    expect(html).toContain("API base URL");
    expect(html).toContain("OpenAPI / Swagger definition URL");
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
    expect(html).toContain("It only reads the definition document");
    expect(html).toContain("Credential delivery: Authorization: Bearer");
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
    expect(draft).not.toContain("The definition settings and credential delivery are fixed");
    expect(draft.match(/<input[^>]*value="https:\/\/docs.example.test\/openapi.json"[^>]*>/)?.[0]).not.toContain('disabled=""');
    data.service.actions.push({ definition: data.preview!.manifest.tools[0].definition, status: "retired", version: 1, definitionHash: "hash" });
    const accepted = renderEditor(data);
    expect(accepted).toContain("The definition settings and credential delivery are fixed");
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
    expect(html).toContain("Credential delivery: X-Original-Key.");
    expect(html).toContain("The discovered scheme now uses different credential delivery");
  });
});


describe("Swagger and Basic import presentation", () => {
  test("Basic API and definition settings are separate and neither rewrites a credential kind", () => {
    const data = fixture();
    data.preview!.manifest.metadata = { securitySchemes: [{ name: "basicAuth", kind: "basic" }] };
    data.service.definition.connectionSettings = { definitionUrl: "https://docs.example.test/swagger.json", definitionAuthKind: "basic", securityScheme: "basicAuth" };
    data.service.definition.discovery = { kind: "slot" };
    const schemes = openApiSecuritySchemes(data.preview!.manifest);
    expect(schemes).toEqual([{ name: "basicAuth", kind: "basic" }]);
    expect(openApiBindings([], true, true, openApiDelivery(schemes[0]))).toEqual([
      { ownerMode: "service", mechanism: "static_token", status: "configured", delivery: { kind: "basic" } },
      { ownerMode: "per_user", mechanism: "static_token", status: "configured", delivery: { kind: "basic" } }
    ]);
    const html = renderEditor(data);
    expect(html).toContain("OpenAPI / Swagger");
    expect(html).toContain("Swagger 2.0 JSON");
    expect(html).toContain("Separate discovery Basic credential");
    expect(html).toContain("basicAuth · Authorization: Basic");
    expect(html).toContain("Credential delivery: Authorization: Basic");
    expect(openApiConnectionSettings(undefined, true, { source: "url", definitionUrl: "https://docs.example.test/swagger.json", definitionAuthKind: "basic", definitionAuthHeader: "X-Unused", securityScheme: "basicAuth" })).toEqual({ definitionUrl: "https://docs.example.test/swagger.json", definitionAuthKind: "basic", securityScheme: "basicAuth" });
  });
  test("review shows source version, form encoding and empty response contracts without inferring read authority", () => {
    const data = fixture();
    data.preview!.manifest.protocolVersion = "2.0";
    const definition = data.preview!.manifest.tools[0].definition;
    definition.annotations = { openapi: { method: "DELETE", path: "/items", security: { scheme: "basicAuth", kind: "basic" }, requestBody: true, formBody: { fields: [{ name: "ids", valueType: "string", required: true }] }, responses: { "200": { contentType: null, schema: null }, "400": { contentType: "application/json", schema: { type: "object" } } } } };
    definition.inputSchema = { type: "object", required: ["body"], properties: { body: { type: "object", properties: { ids: { type: "string" } }, required: ["ids"] } } };
    expect(openApiOperation(definition)).toMatchObject({ method: "DELETE", requestMedia: "application/x-www-form-urlencoded", requestBodyRequired: true, requiredBodyFields: ["ids"], noContentStatuses: ["200"] });
    expect(importReviewRows(data)[0].readOnly).toBe(false);
    const html = renderToStaticMarkup(createElement(ImportReview, { data, onClose: () => {}, onAccept: async () => true, frame: inlineFrame }));
    expect(html).toContain("Source: Swagger 2.0");
    expect(html).toContain("application/x-www-form-urlencoded");
    expect(html).toContain("Body required");
    expect(html).toContain("Required body fields: ids");
    expect(html).toContain("Declares no response content (200)");
    expect(html).toContain("DELETE /items");
    const json = { ...definition, annotations: { openapi: { method: "POST", path: "/items", requestBody: true, responses: {} } } };
    expect(openApiOperation(json)?.requestMedia).toBe("application/json");
    expect(renderToStaticMarkup(createElement(OperationDetails, { definition: { ...json, annotations: { openapi: { method: "GET", path: "/items", requestBody: false } } } }))).toContain("No request body");
  });
  test("an unsupported body placeholder reports its reason without claiming there is no body", () => {
    const data = fixture();
    const tool = data.preview!.manifest.tools[0];
    tool.definition.annotations = { openapi: { method: "POST", path: "/uploads" } };
    tool.unsupportedReason = "multipart request bodies are unsupported";
    expect(openApiOperation(tool.definition)).not.toHaveProperty("requestMedia");
    const html = renderToStaticMarkup(createElement(ImportReview, { data, onClose: () => {}, onAccept: async () => true, frame: inlineFrame }));
    expect(html).toContain("POST /uploads");
    expect(html).toContain("multipart request bodies are unsupported");
    expect(html).not.toContain("No request body");
    expect(html).not.toContain("Body optional");
  });
  test("JSON required fields resolve locally and stay distinct from an optional body", () => {
    const definition = fixture().preview!.manifest.tools[0].definition;
    definition.annotations = { openapi: { method: "POST", path: "/items", requestBody: true } };
    definition.inputSchema = {
      type: "object", properties: { body: { $ref: "#/$defs/item~1body" } }, required: [],
      $defs: { "item/body": { type: "object", properties: { name: { type: "string" }, note: { type: "string" } }, required: ["name"] } }
    };
    expect(openApiOperation(definition)).toMatchObject({ requestMedia: "application/json", requestBodyRequired: false, requiredBodyFields: ["name"] });
    const html = renderToStaticMarkup(createElement(OperationDetails, { definition }));
    expect(html).toContain("Body optional");
    expect(html).toContain("Required fields when body is supplied: name");
    expect(html).not.toContain("Body required");
    expect(html).not.toContain("name, note");
  });
  test("form summaries use frozen field requirements even when the optional body schema is complex", () => {
    const definition = fixture().preview!.manifest.tools[0].definition;
    definition.annotations = { openapi: { method: "POST", path: "/items", requestBody: true, formBody: { fields: [{ name: "query", valueType: "string", required: true }, { name: "page", valueType: "integer", required: false }] } } };
    definition.inputSchema = { type: "object", properties: { body: { $ref: "#/$defs/body" } } };
    expect(openApiOperation(definition)).toMatchObject({ requestBodyRequired: false, requiredBodyFields: ["query"] });
  });
  test.each([
    { $ref: "https://example.test/schema" },
    { $ref: "#/$defs/missing" },
    { $ref: "#/$defs/body" },
    { $ref: "#/$defs/simple", required: ["extra"] },
    { type: "object", required: ["name"], allOf: [{ required: ["extra"] }] },
    { type: "object", required: ["name"], if: { required: ["kind"] }, then: { required: ["extra"] } }
  ])("unknown JSON field requirements are omitted without affecting known body presence: %j", (body) => {
    const definition = fixture().preview!.manifest.tools[0].definition;
    definition.annotations = { openapi: { method: "POST", path: "/items", requestBody: true } };
    definition.inputSchema = { type: "object", properties: { body }, required: ["body"], $defs: { body: { $ref: "#/$defs/body" }, simple: { type: "object", required: ["name"] } } };
    expect(openApiOperation(definition)).toMatchObject({ requestBodyRequired: true });
    expect(openApiOperation(definition)).not.toHaveProperty("requiredBodyFields");
    const html = renderToStaticMarkup(createElement(OperationDetails, { definition }));
    expect(html).toContain("Body required");
    expect(html).not.toContain("Required body fields");
  });
});
