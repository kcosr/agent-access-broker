import { vi } from "vitest";
vi.mock("../src/app/session", () => ({ useSession: () => ({ session: { authenticated: true, role: "admin", selfServiceEnabled: true, principal: "admin" } }) }));
import { describe, expect, test } from "vitest";
import type { ImportActionDefinition, ImportPreviewResult } from "../src/import-types";
import type { PolicyCatalogResult, PolicyGrantRecord } from "../src/types";
import { affectedImportGrants, importReviewRows, importSelectionError, importSourceKey, selectedImportActions } from "../src/lib/imports";
import { policyGrantBody, policyGrantDraft } from "../src/lib/helpers";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { buildCatalogServices, importBlocker } from "../src/features/catalog/catalog-data";
import { actionTransitions, serviceActionRows } from "../src/features/catalog/service-actions";
import { ImportTokenModal } from "../src/features/catalog/import-token-modal";
import { inlineFrame } from "../src/features/catalog/catalog-ui";

const tool = (action: string, readOnly = false): ImportActionDefinition => ({ action, source: { toolName: action }, description: action, inputSchema: { type: "object" }, annotations: {}, readOnly });
function fixture(): ImportPreviewResult {
  return {
    operatorAllowed: true, scopedMcp: { ready: false, issues: [{ code: "service_unavailable", actions: [] }], truncated: false }, secretInputCandidates: [], scopedMcpWarnings: [], importAuthentication: [], catalogRevision: 4, affectedGrants: ["grant1", "removed-grant"], affectedGrantsByAction: { read: ["grant1"], removed: ["removed-grant"] },
    service: { definition: { service: "metrics", displayName: "Metrics", adapterKind: "mcp_http", endpoint: "https://example.test/mcp", executionBindings: [{ ownerMode: "service", mechanism: "static_token", delivery: { kind: "bearer" }, status: "configured" }], connectionSettings: {}, discovery: { kind: "execution" }, transportAuth: false }, status: "enabled", version: 2, actions: [{ definition: tool("read", true), status: "enabled", version: 1, secretInputs: [], definitionHash: "old" }, { definition: tool("removed", true), status: "quarantined", version: 1, secretInputs: [], definitionHash: "old" }], slotVersions: {}, createdAt: "", updatedAt: "", createdBy: "admin", updatedBy: "admin" },
    preview: { service: "metrics", serviceVersion: 2, catalogRevision: 4, configRevision: "cfg", credentialVersions: {}, manifestHash: "hash", manifest: { protocolVersion: "fixture", metadata: {}, tools: [{ definition: tool("read"), unsupportedReason: null, readOnlyHint: false }, { definition: tool("new"), unsupportedReason: null, readOnlyHint: true }, { definition: tool("unsupported"), unsupportedReason: "Requires streaming", readOnlyHint: true }] }, createdAt: "", expiresAt: "", createdBy: "admin" },
  };
}
describe("import review", () => {
  test("retains reviewed classifications, ignores untrusted hints, and requires explicit additions", () => {
    const rows = importReviewRows(fixture());
    expect(rows.map(({ change, selected, readOnly, selectable }) => ({ change, selected, readOnly, selectable }))).toEqual([
      { change: "Unchanged", selected: true, readOnly: true, selectable: true },
      { change: "New", selected: false, readOnly: false, selectable: true },
      { change: "Unsupported", selected: false, readOnly: false, selectable: false },
      { change: "Removed", selected: false, readOnly: true, selectable: false },
    ]);
    expect(selectedImportActions(rows)).toEqual([{ source: { toolName: "read" }, action: "read", readOnly: true, secretInputs: [] }]);
    rows[1].selected = true;
    rows[1].action = "query.metrics";
    rows[1].label = " Query ";
    expect(selectedImportActions(rows)[1]).toEqual({ source: { toolName: "new" }, action: "query.metrics", label: "Query", readOnly: false, secretInputs: [] });
  });
  test("receiver edits preserve source schemas, require grant review, and retain invalid old selections", () => {
    const data = fixture();
    const original = { type: "object", properties: { token: { type: "string", description: "Value to store" }, label: { type: "string" } } };
    data.preview!.manifest.tools[0].definition.inputSchema = structuredClone(original);
    data.service.actions[0].definition.inputSchema = structuredClone(original);
    data.secretInputCandidates = [{ toolIndex: 0, pointers: ["/inputs/label", "/inputs/token"] }];
    let rows = importReviewRows(data);
    rows[0].secretInputs = [{ pointer: "/inputs/token" }];
    expect(importSelectionError(data, rows)).toBeNull();
    expect(affectedImportGrants(data, rows)).toEqual(["grant1"]);
    expect(selectedImportActions(rows)[0].secretInputs).toEqual([{ pointer: "/inputs/token" }]);
    expect(rows[0].tool.definition.inputSchema).toEqual(original);
    data.service.actions[0].secretInputs = [{ pointer: "/inputs/token" }];
    data.secretInputCandidates = [{ toolIndex: 0, pointers: ["/inputs/label"] }];
    rows = importReviewRows(data);
    expect(rows[0].secretInputs).toEqual([{ pointer: "/inputs/token" }]);
    expect(importSelectionError(data, rows)).toContain("no longer eligible");
    rows[0].secretInputs = [];
    expect(importSelectionError(data, rows)).toBeNull();
    expect(affectedImportGrants(data, rows)).toEqual(["grant1"]);
    expect(selectedImportActions(rows)[0].secretInputs).toEqual([]);
  });
  test("changed schemas reset selection and read-only review; description-only edits preserve both", () => {
    const data = fixture();
    data.preview!.manifest.tools[0].definition.description = "Updated description";
    expect(importReviewRows(data)[0]).toMatchObject({ change: "Metadata changed", selected: true, readOnly: true });
    data.preview!.manifest.tools[0].definition.inputSchema = { type: "object", required: ["new"] };
    expect(importReviewRows(data)[0]).toMatchObject({ change: "Changed", selected: false, readOnly: false });
  });
  test("action mappings cannot collide with retained identities or rename accepted tools", () => {
    const data = fixture();
    const rows = importReviewRows(data);
    rows[1].selected = true;
    rows[1].action = "removed";
    expect(importSelectionError(data, rows)).toContain("already used");
    rows[1].action = "metrics.query";
    expect(importSelectionError(data, rows)).toContain("service prefix");
    rows[1].action = "valid.name";
    rows[0].action = "renamed";
    expect(importSelectionError(data, rows)).toContain("cannot be changed");
    expect(importSourceKey({ b: [1, { c: 2 }], a: "x" })).toBe(importSourceKey({ a: "x", b: [1, { c: 2 }] }));
  });
  test("only annotation titles are presentation metadata, not hints or execution behavior", () => {
    const data = fixture();
    data.service.actions[0].definition.annotations = { toolAnnotations: { title: "Original", readOnlyHint: true }, execution: { taskSupport: "forbidden" } };
    data.preview!.manifest.tools[0].definition.annotations = { toolAnnotations: { title: "Renamed", readOnlyHint: true }, execution: { taskSupport: "forbidden" } };
    let rows = importReviewRows(data);
    expect(rows[0]).toMatchObject({ change: "Metadata changed", selected: true, readOnly: true });
    expect(affectedImportGrants(data, rows)).toEqual([]);
    data.preview!.manifest.tools[0].definition.annotations = { toolAnnotations: { title: "Renamed", readOnlyHint: false }, execution: { taskSupport: "forbidden" } };
    rows = importReviewRows(data);
    expect(rows[0]).toMatchObject({ change: "Changed", selected: false, readOnly: false });
    data.preview!.manifest.tools[0].definition.annotations = { toolAnnotations: { title: "Renamed", readOnlyHint: true }, execution: { taskSupport: "optional" } };
    expect(importReviewRows(data)[0].change).toBe("Changed");
  });
  test("retired source gets a fresh editable identity while all tombstones remain reserved", () => {
    const data = fixture();
    data.service.actions[0].status = "retired";
    data.preview!.manifest.tools[0].definition.action = "read.new";
    let rows = importReviewRows(data);
    expect(rows[0]).toMatchObject({ change: "Retired – new identity required", selectable: true, selected: false, readOnly: false, action: "read.new" });
    expect(rows.find((row) => row.change === "Retired")).toMatchObject({ action: "read", selectable: false });
    rows[0].selected = true;
    expect(importSelectionError(data, rows)).toBeNull();
    expect(affectedImportGrants(data, rows)).toEqual([]);
    rows[0].action = "read";
    expect(importSelectionError(data, rows)).toContain("already used");
    const active = { ...data.service.actions[0], definition: { ...data.service.actions[0].definition, action: "read.new" }, status: "enabled" as const };
    // A live mapping wins over its source's tombstone, regardless of record order.
    data.service.actions.unshift(active);
    rows = importReviewRows(data);
    expect(rows[0]).toMatchObject({ change: "Unchanged", action: "read.new", selected: true });
    expect(new Set(rows.map((row) => row.key)).size).toBe(rows.length);
  });
  test("confirmation lists only grants for selected behavior, classification or restoration changes", () => {
    const data = fixture();
    const rows = importReviewRows(data);
    expect(affectedImportGrants(data, rows)).toEqual([]);
    rows[1].selected = true;
    expect(affectedImportGrants(data, rows)).toEqual([]);
    rows[0].readOnly = false;
    expect(affectedImportGrants(data, rows)).toEqual(["grant1"]);
    rows[0].selected = false;
    expect(affectedImportGrants(data, rows)).toEqual([]);
    data.service.actions[0].status = "disabled";
    const restored = importReviewRows(data);
    restored[0].selected = true;
    expect(affectedImportGrants(data, restored)).toEqual(["grant1"]);
  });
  test("scoped name warnings remain provisional and do not disable aggregate acceptance", () => {
    const data = fixture();
    data.scopedMcpWarnings = [{ toolIndex: 1, proposedAction: "new", codes: ["reserved_name"] }];
    const rows = importReviewRows(data);
    expect(rows[1]).toMatchObject({ selectable: true, selected: false, scopedMcpWarning: data.scopedMcpWarnings[0] });
    rows[1].selected = true;
    expect(importSelectionError(data, rows)).toBeNull();
    expect(selectedImportActions(rows).map((selection) => selection.action)).toEqual(["read", "new"]);
    rows[1].action = "edited.proposal";
    expect(rows[1].scopedMcpWarning?.proposedAction).toBe("new");
    expect(data.preview!.manifest.tools[1].unsupportedReason).toBeNull();
  });
});

const policyCatalog: PolicyCatalogResult = {
  resources: [], resourceGroups: [], subjects: { users: [], groups: [], anonymous: false }, executionContexts: { allowedValues: ["internal"], defaultContext: "internal", contextRequired: false },
  services: [{ service: "metrics", displayName: "Metrics", surface: "api", available: false, actions: [{ action: "read", readOnly: true, available: false, description: "Read", requiredScopes: {}, credentialModes: ["service"], lookupRequired: false, inputSchema: {} }, { action: "new", readOnly: false, available: false, description: "New", requiredScopes: {}, credentialModes: ["service"], lookupRequired: false, inputSchema: {} }], resourceScopes: {}, configuredCredentialModes: [], lookupCredentialConfigured: false }],
};
const grant = { grantRef: "g", version: 1, writable: true, service: "metrics", subjects: ["user:alice"], actions: ["read"], credentialMode: "service", status: "active", executionContexts: ["internal"], resources: { resourceIds: [], resourceGroupIds: [] } } as PolicyGrantRecord;
test("retained unavailable selections can be maintained, but not added or duplicated", () => {
  const draft = policyGrantDraft(policyCatalog, "edit", grant);
  expect(policyGrantBody(draft, policyCatalog).messages).toEqual([]);
  draft.description = "Retained grant";
  expect(policyGrantBody(draft, policyCatalog).body?.credentialMode).toBe("service");
  draft.actions = [...draft.actions, "new"];
  expect(policyGrantBody(draft, policyCatalog).messages.some((message) => message.code === "unavailable")).toBe(true);
  expect(policyGrantBody(policyGrantDraft(policyCatalog, "duplicate", grant), policyCatalog).body).toBeNull();
});

describe("catalog service index", () => {
  const imports = () => {
    const data = fixture();
    return { catalogRevision: 4, operatorEnabled: true, availableKinds: ["mcp_http"], commandImports: [], importAuthentication: [], services: [data.service] };
  };
  test("merges built-in and imported services with status, action and manager counts", () => {
    const list = imports();
    list.services[0].actions.push({ definition: tool("old"), status: "retired", version: 1, secretInputs: [], definitionHash: "old" });
    const catalog: PolicyCatalogResult = { ...policyCatalog, services: [...policyCatalog.services, { ...policyCatalog.services[0], service: "jira", displayName: "Jira", available: true, unavailableReason: undefined }] };
    const managers = [{ assignmentId: "a", service: "jira", principalId: "bob", principalStatus: "active", serviceConfigured: true, createdAt: "", createdBy: "admin" }];
    const services = buildCatalogServices(catalog, list, managers);
    expect(services.map(({ service, origin, actionCount, managerCount }) => ({ service, origin, actionCount, managerCount }))).toEqual([
      { service: "jira", origin: "builtin", actionCount: 2, managerCount: 1 },
      { service: "metrics", origin: "imported", actionCount: 2, managerCount: 0 }
    ]);
    expect(services[0].state).toMatchObject({ key: "available", label: "Available" });
    // An enabled import the broker cannot execute shows the broker's reason.
    expect(services[1].state).toMatchObject({ key: "unavailable", label: "Unavailable" });
    list.services[0].status = "draft";
    expect(buildCatalogServices(catalog, list, [])[1].state).toMatchObject({ key: "draft", label: "Draft" });
  });
  test("new imports are blocked while loading and by operator configuration", () => {
    expect(importBlocker(null)).toContain("Loading");
    expect(importBlocker({ ...imports(), operatorEnabled: false })).toContain("disabled by operator");
    expect(importBlocker({ ...imports(), availableKinds: [] })).toContain("No import types");
    expect(importBlocker(imports())).toBeNull();
  });
  test("imported action rows keep every status; quarantined and retired actions cannot be enabled", () => {
    const data = fixture();
    const [service] = buildCatalogServices(policyCatalog, { ...imports(), services: [data.service] }, []);
    const rows = serviceActionRows(service);
    expect(rows.map(({ action, status, readOnly }) => ({ action, status, readOnly }))).toEqual([
      { action: "read", status: "enabled", readOnly: true },
      { action: "removed", status: "quarantined", readOnly: true }
    ]);
    expect(rows[0].catalog?.credentialModes).toEqual(["service"]);
    expect(actionTransitions(rows[0], data)).toEqual([
      { status: "disabled", disabled: false },
      { status: "retired", disabled: false }
    ]);
    expect(actionTransitions(rows[1], data).find((transition) => transition.status === "enabled")?.disabled).toBe(true);
    expect(actionTransitions(rows[0], { ...data, operatorAllowed: false }).every((transition) => transition.status === "enabled" || !transition.disabled)).toBe(true);
    data.service.status = "retired";
    expect(actionTransitions(rows[0], data).every((transition) => transition.disabled)).toBe(true);
  });
  test("built-in rows come from the policy catalog", () => {
    const [service] = buildCatalogServices(policyCatalog, null, []);
    expect(service.origin).toBe("builtin");
    expect(serviceActionRows(service)).toMatchObject([
      { action: "read", status: null, record: null, readOnly: true },
      { action: "new", status: null, record: null, readOnly: false }
    ]);
  });
  test("token dialogs name the slot and never render a stored value", () => {
    const render = (purpose: "execution" | "personal", rotate: boolean) =>
      renderToStaticMarkup(createElement(ImportTokenModal, { purpose, rotate, noun: "token", onClose: () => {}, onSave: async () => undefined, frame: inlineFrame }));
    const set = render("execution", false);
    expect(set).toContain("Set execution token");
    expect(set).toContain("without a Bearer prefix");
    expect(set).toContain('type="password"');
    expect(set).toContain('value=""');
    expect(render("execution", true)).toContain("Rotate execution token");
    expect(render("personal", false)).toContain("Set personal token");
  });
});
