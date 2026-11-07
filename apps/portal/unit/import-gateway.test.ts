import { describe, expect, test, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { ImportGatewayBinding, ImportPreviewResult } from "../src/import-types";
import { GATEWAY_BODY_NOTICE, gatewayConnectionSettings, gatewayIngressLabel, openApiOperation } from "../src/lib/import-openapi";
import { affectedImportGrants, importItemNoun, importReviewRows, importSelectionError } from "../src/lib/imports";
import { ImportEditor } from "../src/features/catalog/import-editor";
import { ImportReview, OperationDetails } from "../src/features/catalog/import-review";
import { inlineFrame } from "../src/features/catalog/catalog-ui";
import { GATEWAY_BINDING, gatewayOperation, gatewayPreview } from "./gateway-import.fixture";

vi.mock("../src/app/session", () => ({ useSession: () => ({ session: { authenticated: true, role: "admin", selfServiceEnabled: true, principal: "admin" } }) }));

const renderEditor = (data?: ImportPreviewResult, gatewayBindings: ImportGatewayBinding[] = [GATEWAY_BINDING], availableKinds = ["openapi_gateway"]) => renderToStaticMarkup(createElement(ImportEditor, {
  principal: "admin", data, availableKinds, gatewayBindings, authentication: [], onClose: () => {}, onSave: async () => true, frame: inlineFrame
}));
const renderReview = (data: ImportPreviewResult) => renderToStaticMarkup(createElement(ImportReview, { data, onClose: () => {}, onAccept: async () => true, frame: inlineFrame }));

describe("gateway import configuration", () => {
  test("selects an approved identity instead of accepting an arbitrary destination", () => {
    const html = renderEditor();
    expect(html).toContain("OpenAPI / Swagger");
    expect(html).toContain("HTTP gateway");
    expect(html).toContain("Approved gateway binding");
    expect(html).toContain("inventory.gateway.example.test");
    expect(html).toContain("Reserved by the selected gateway binding");
    expect(html).toContain("Whole-action access");
    expect(html).toContain(GATEWAY_BODY_NOTICE);
    expect(html).toContain("cannot discover an undeclared backend route");
    expect(html).toContain("not advertised in ordinary agent discovery");
  });

  test("missing and reserved bindings cannot create a new import", () => {
    for (const bindings of [[], [{ ...GATEWAY_BINDING, available: false, unavailableReason: "Already used" }]]) {
      const html = renderEditor(undefined, bindings);
      expect(html).toContain("No unused gateway binding is available");
      expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Create draft<\/button>/);
    }
  });

  test("explains unavailable bindings without applying creation-only reasons to the retained import", () => {
    const bindings = [
      { ...GATEWAY_BINDING, available: false, unavailableReason: "Service identity is already retained" },
      { ...GATEWAY_BINDING, service: "packages", available: false, unavailableReason: "Packages binding is already retained" }
    ];
    const html = renderEditor(undefined, bindings);
    expect(html).toContain('title="Service identity is already retained"');
    expect(html).toContain('inventory</span>: Service identity is already retained');
    expect(html).toContain('packages</span>: Packages binding is already retained');
    const edit = renderEditor(gatewayPreview(), bindings);
    expect(edit).not.toContain("Service identity is already retained");
    expect(edit).not.toContain("Packages binding is already retained");
  });

  test("retained imports keep immutable exposure and destination even when the binding is removed", () => {
    const data = gatewayPreview();
    const html = renderEditor(data, []);
    expect(html).toContain("inventory (binding unavailable)");
    expect(html).toContain("The operator binding is unavailable");
    expect(html).toContain(GATEWAY_BINDING.endpoint);
    expect(html).toContain("Fixed after creation. Create a separate service");
    expect(html).toContain("Anonymous upstream");
    expect(html).not.toContain("Shared service credential");
    expect(html).not.toContain("Personal credentials for each user");
    expect(html).not.toContain("API security scheme");
  });

  test("Broker ingress is separate from the upstream scheme", () => {
    expect(gatewayIngressLabel({ ...GATEWAY_BINDING, authModes: ["basic_broker_token", "bearer_broker_token"], allowForwardedIdentity: true })).toBe("Broker Basic token; Broker Bearer token; Approved trusted-ingress identity");
    const data = gatewayPreview();
    data.service.definition.connectionSettings = { definitionSource: "upload", executionAuthentication: "static", securityScheme: "basic" };
    data.service.definition.executionBindings = [{ ownerMode: "service", mechanism: "static_token", delivery: { kind: "basic" }, status: "configured" }];
    const html = renderEditor(data);
    expect(html).toContain("Broker ingress: Broker Bearer token");
    expect(html).toContain("Credential delivery: Authorization: Basic");
    expect(html).toContain("no active credential verification probe");
    expect(html).not.toContain("OAuth registration");
  });

  test("anonymous settings clear a selected static scheme and preserve frozen settings byte for byte", () => {
    const old = { definitionSource: "upload", executionAuthentication: "static", securityScheme: "basic" };
    const draft = { source: "upload" as const, definitionUrl: "https://docs.example.test/spec.json", definitionAuthKind: "basic", definitionAuthHeader: "", securityScheme: "basic" };
    expect(gatewayConnectionSettings(old, true, draft, "anonymous")).toEqual({ definitionSource: "upload", executionAuthentication: "anonymous" });
    expect(gatewayConnectionSettings(old, false, draft, "anonymous")).toBe(old);
    const url = gatewayConnectionSettings(undefined, true, { ...draft, source: "url" }, "anonymous");
    expect(url).toEqual({ definitionUrl: draft.definitionUrl, definitionAuthKind: "basic", executionAuthentication: "anonymous" });
    expect(url).not.toHaveProperty("securityScheme");
  });
});

describe("gateway operation review", () => {
  test("shows raw HTTP, declared headers and unscoped authority without MCP readiness", () => {
    const data = gatewayPreview();
    const html = renderReview(data);
    expect(importItemNoun("openapi_gateway")).toBe("operation");
    expect(html).toContain("Review discovered operations");
    expect(html).toContain("GET /items/{id}");
    expect(html).toContain("Anonymous upstream");
    expect(html).toContain("X-Api-Version");
    expect(html).toContain("path id (required) — simple");
    expect(html).toContain("Native HTTP response (streamed)");
    expect(html).toContain("Whole-action access");
    expect(html).not.toContain("Current service-specific MCP");
    expect(html).not.toContain("Output: JSON");
    expect(html).not.toContain("Body optional");
  });

  test("raw body review describes presence and media types without field-level validation", () => {
    const definition = gatewayOperation("submit", "POST", "/items");
    definition.annotations = { openapiGateway: { version: 1, source: definition.source, method: "POST", path: "/items", security: { kind: "anonymous" }, requestBody: { required: true, mediaTypes: ["application/json", "application/x-www-form-urlencoded"] }, parameters: [], responses: {} } };
    const operation = openApiOperation(definition);
    expect(operation).toMatchObject({ gateway: true, requestBodyRequired: true, requestMediaTypes: ["application/json", "application/x-www-form-urlencoded"] });
    expect(operation).not.toHaveProperty("requiredBodyFields");
    const html = renderToStaticMarkup(createElement(OperationDetails, { definition }));
    expect(html).toContain("Body required");
    expect(html).toContain("Body schema not validated by gateway");
    expect(html).not.toContain("Required body fields");
    expect(html).not.toContain("Required fields when body is supplied");
  });

  test("unsupported and future plans do not invent a body contract", () => {
    const definition = gatewayOperation();
    definition.annotations = { openapiGateway: { version: 1, method: "POST", path: "/uploads" } };
    expect(openApiOperation(definition)).not.toHaveProperty("requestMediaTypes");
    expect(openApiOperation(definition)).not.toHaveProperty("requestBodyRequired");
    definition.annotations = { openapiGateway: { version: 2, method: "GET", path: "/future" } };
    expect(openApiOperation(definition)).toBeNull();
  });

  test("changed HTTP plans require renewed review and affected-grant confirmation", () => {
    const data = gatewayPreview();
    const accepted = structuredClone(data.preview!.manifest.tools[0].definition);
    accepted.readOnly = true;
    data.service.actions = [{ definition: accepted, status: "quarantined", version: 2, definitionHash: "old" }];
    data.affectedGrantsByAction = { get_item: ["readers"] };
    data.preview!.manifest.tools[0].definition = gatewayOperation("get_item", "GET", "/items/{id}/details");
    const rows = importReviewRows(data);
    expect(rows[0]).toMatchObject({ change: "Changed", selected: false, readOnly: false });
    rows[0].selected = true;
    expect(importSelectionError(data, rows)).toBeNull();
    expect(affectedImportGrants(data, rows)).toEqual(["readers"]);
    expect(renderReview(data)).toContain("GET /items/{id}/details");
  });
});
