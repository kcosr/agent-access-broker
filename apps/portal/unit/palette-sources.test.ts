import { describe, expect, test, vi } from "vitest";
import { entityPaletteSources, navigationPaletteItems, paletteQueryFeedback, type PaletteEntities } from "../src/app/palette-sources";
import type { PaletteItem } from "../src/workbench";
import type { ConnectionCredential, CredentialConnection, PolicyServiceCatalog, Session } from "../src/types";
import type { ImportedServiceRecord } from "../src/import-types";
import { indexResourceTypes } from "../src/lib/resource-types";
import { RESOURCE_TYPES } from "./resource-types.fixture";

const admin: Session = { authenticated: true, principal: "alice", role: "admin", selfServiceEnabled: true, auditQueryable: true };
const service: PolicyServiceCatalog = {
  service: "jira", displayName: "Issue Tracker", surface: "api", configuredCredentialModes: [], lookupCredentialConfigured: false, resourceScopes: {},
  actions: [{ action: "issue.view", description: "Read issue details", readOnly: true, requiredScopeTypes: ["jira_project"], credentialModes: [], lookupRequired: false, inputSchema: {} }]
};
const imported = (id: string, status: ImportedServiceRecord["status"]): ImportedServiceRecord => ({
  definition: { service: id, displayName: `Imported ${id}`, adapterKind: "mcp_http", endpoint: "https://example.test/mcp", connectionSettings: {}, executionBindings: [], discovery: { kind: "anonymous" }, transportAuth: false },
  status, version: 1, actions: [], slotVersions: {}, createdAt: "", createdBy: "", updatedAt: "", updatedBy: ""
});
const credential: ConnectionCredential = {
  credentialId: "cred-123", ownerPrincipal: "alice", ownerKind: "user", connection: "tracker", profile: "standard", credentialKind: "token",
  metadata: { confidential: "DO_NOT_INDEX_THIS" }, status: "active", createdAt: "", createdBy: "", updatedAt: "", updatedBy: "", verificationStatus: "upstream_verified", lastVerificationErrorCode: "DO_NOT_INDEX_ERROR"
};
const connection: CredentialConnection = {
  connection: "tracker", displayName: "Issue Tracker", method: "token", consumers: [{ service: "jira", displayName: "Issue Tracker", credentialVerificationInputs: [] }],
  otherConsumers: 0, profile: "standard", credentialKind: "token", registration: null, credential
};
function fixture(session = admin): PaletteEntities {
  return {
    session, types: indexResourceTypes(RESOURCE_TYPES), principals: [],
    groups: [{ groupId: "ops-id", displayName: "Platform Crew", description: "Night shift responders", status: "disabled", memberCount: 2 }],
    catalog: { resources: [], resourceGroups: [], services: [service], executionContexts: { allowedValues: ["default"], contextRequired: false }, subjects: { users: [], groups: [{ groupId: "ops-id", displayName: "Platform Crew", status: "disabled" }], anonymous: false } },
    grants: [{ grantRef: "read-platform", subjects: ["group:ops-id"], service: "jira", actions: ["issue.view"], executionContexts: ["default"], resources: { resourceIds: [], resourceGroupIds: [] }, credentialMode: "per_user", status: "active", writable: true }],
    resources: [
      { id: "main-project", displayName: "Engineering", resourceType: "jira_project", selector: { kind: "exact", value: "ENG" }, allowedExecutionContexts: ["default"], enabled: true, version: 1 },
      { id: "secret-project", displayName: "Excluded Finance", resourceType: "jira_project", selector: { kind: "exact", value: "FIN" }, allowedExecutionContexts: ["default"], enabled: false, version: 1 }
    ],
    resourceGroups: [{ id: "project-group", name: "Delivery projects", includedResourceIds: ["main-project"], excludedResourceIds: ["secret-project", "missing-id"], version: 1 }],
    imports: [imported("jira", "enabled"), imported("metrics", "draft")],
    tokenOptions: { policyGeneration: 1, resources: [], resourceGroups: [], executionContexts: ["default"], services: [{ service: "jira", displayName: "Issue Tracker", brokerHosts: [], executionContexts: ["default"], actions: [{ action: "issue.view", description: "Read issue details", readOnly: true, requiredScopeTypes: ["jira_project"], executionContexts: ["default"], resourceType: "jira_project", effectiveAccessByExecutionContext: {} }] }], mcp: null },
    tokens: [{ tokenId: "token-123", principalId: "alice", name: "My Agent", tokenClass: "agent", scopes: {}, createdAt: "", createdBy: "" }], credentials: { connections: [connection], retained: [] }
  };
}
function model(data = fixture()) {
  const navigate = vi.fn();
  const sources = entityPaletteSources(data, (href) => () => navigate(href));
  const items = (id: string, query = "") => {
    const source = sources.find((item) => item.id === id);
    return typeof source?.items === "function" ? source.items(query) : source?.items ?? [];
  };
  const follow = (item: PaletteItem) => { item.onSelect(); return navigate.mock.lastCall?.[0] as string; };
  return { sources, items, follow };
}

describe("palette metadata coverage", () => {
  test("resource groups include both included and excluded resource names, including missing member IDs", () => {
    const { items, follow } = model();
    const group = items("resource-groups")[0]!;
    expect(group.label).toBe("Delivery projects");
    expect(group.keywords).toEqual(expect.arrayContaining(["project-group", "Engineering · ENG", "Excluded Finance · FIN", "missing-id", "Jira project"]));
    expect(follow(group)).toBe("/ui/admin/catalog/resource-groups?item=project-group");
    expect(items("resources")[0]?.keywords).toEqual(expect.arrayContaining(["jira_project", "Jira project", "Jira projects"]));
  });

  test("identity groups match description and grants match resolved subject names", () => {
    const { items, follow } = model();
    expect(items("groups")[0]?.keywords).toContain("Night shift responders");
    expect(items("groups")[0]?.hint).toContain("disabled");
    expect(items("grants")[0]?.keywords).toContain("Platform Crew");
    expect(follow(items("groups")[0]!)).toBe("/ui/admin/groups/ops-id");
  });

  test("imports appear once per service and uncataloged drafts open their import page", () => {
    const { items, follow } = model();
    expect(items("services").map((item) => item.id)).toEqual(["service-jira", "service-metrics"]);
    expect(items("services")[0]?.hint).toContain("enabled");
    expect(items("services")[1]?.keywords).toContain("draft");
    expect(follow(items("services")[1]!)).toBe("/ui/admin/catalog/services/metrics/import");
    expect(follow(items("service-actions")[0]!)).toBe("/ui/admin/catalog/services/jira?action=issue.view");
  });

  test("hyphenated service/action pairs retain unique result identities and destinations", () => {
    const data = fixture();
    data.catalog!.services = [
      { ...service, service: "reports-east", actions: [{ ...service.actions[0]!, action: "inspect" }] },
      { ...service, service: "reports", actions: [{ ...service.actions[0]!, action: "east-inspect" }] }
    ];
    const { items, follow } = model(data);
    const actions = items("service-actions");
    expect(new Set(actions.map((item) => item.id)).size).toBe(2);
    expect(follow(actions[0]!)).toBe("/ui/admin/catalog/services/reports-east?action=inspect");
    expect(follow(actions[1]!)).toBe("/ui/admin/catalog/services/reports?action=east-inspect");
  });

  test("credentials use safe fields and only link to stored connection tokens", () => {
    const data = fixture();
    data.credentials.connections.push({ ...connection, connection: "unstored", credential: null });
    const { connection: _connection, ...stored } = credential;
    data.credentials.retained.push({ ...stored, credentialId: "retained-row", service: "old", name: "default" });
    const { items, follow } = model(data);
    expect(items("credentials")).toHaveLength(1);
    const result = items("credentials")[0]!;
    expect(result.label).toBe("Issue Tracker");
    expect(result.keywords).toEqual(expect.arrayContaining(["cred-123", "tracker", "jira", "Issue Tracker", "standard", "Upstream verified"]));
    expect(JSON.stringify(result)).not.toContain("DO_NOT_INDEX");
    expect(follow(result)).toBe("/ui/credentials?credential=tracker");
  });

  test("audit search carries the query as URL data without fetching audit results", () => {
    const { items, follow } = model();
    expect(items("audit-search")).toEqual([]);
    const href = follow(items("audit-search", 'ticket & "review"')[0]!);
    expect(new URL(href, "https://example.test").searchParams.get("q")).toBe('ticket & "review"');
    expect(href.startsWith("/ui/admin/audit?")).toBe(true);
    expect(model(fixture({ ...admin, auditQueryable: false })).items("audit-search", "ticket")).toEqual([]);
  });
});

describe("palette authorization and destinations", () => {
  test("scope-less policy managers can still navigate to the Policies empty state", () => {
    const session: Session = { ...admin, role: "service_policy_manager", selfServiceEnabled: false, policyManagementServices: [] };
    const navigate = vi.fn();
    const items = navigationPaletteItems(session, (href) => () => navigate(href));
    expect(items.map((item) => item.id)).toEqual(["go-policies", "go-account"]);
    items.find((item) => item.id === "go-policies")!.onSelect();
    expect(navigate).toHaveBeenCalledWith("/ui/admin/policies");
    expect(model(fixture(session)).sources).toEqual([]);
  });

  test("nested destinations are available to administrators and auditors", () => {
    for (const role of ["admin", "auditor"] as const) {
      const navigate = vi.fn();
      const items = navigationPaletteItems({ ...admin, role }, (href) => () => navigate(href));
      const expected = { "go-users": "/ui/admin/principals", "go-service-accounts": "/ui/admin/principals?kind=service-accounts", "go-groups": "/ui/admin/principals?kind=groups", "go-resources": "/ui/admin/catalog/resources", "go-resource-groups": "/ui/admin/catalog/resource-groups" };
      for (const [id, href] of Object.entries(expected)) {
        items.find((item) => item.id === id)!.onSelect();
        expect(navigate).toHaveBeenLastCalledWith(href);
      }
    }
  });

  test("policy managers receive policy destinations and no admin-only entities even when passed cached data", () => {
    const session: Session = { ...admin, role: "service_policy_manager", policyManagementServices: ["jira"] };
    const { sources, items, follow } = model(fixture(session));
    expect(sources.some((source) => ["principals", "groups", "resources", "resource-groups"].includes(source.id))).toBe(false);
    expect(items("services")).toHaveLength(1);
    expect(follow(items("service-actions")[0]!)).toBe("/ui/admin/policies?service=jira&action=issue.view");
    expect(navigationPaletteItems(session, () => () => {}).some((item) => ["go-groups", "go-catalog", "go-users", "go-resources"].includes(item.id))).toBe(false);
  });

  test("ordinary users search granted service actions and personal metadata only", () => {
    const session: Session = { ...admin, role: "user" };
    const { sources, items, follow } = model(fixture(session));
    expect(sources.map((source) => source.id)).toEqual(["services", "service-actions", "tokens", "credentials"]);
    expect(follow(items("service-actions")[0]!)).toBe("/ui/access?service=jira&q=issue.view");
    expect(follow(items("services")[0]!)).toBe("/ui/access?service=jira");
    expect(navigationPaletteItems(session, () => () => {}).some((item) => item.id === "go-groups")).toBe(false);
  });

  test("self-service disabled accounts never expose personal metadata even when passed cached data", () => {
    const { sources } = model(fixture({ ...admin, role: "auditor", selfServiceEnabled: false }));
    expect(sources.some((source) => ["tokens", "credentials"].includes(source.id))).toBe(false);
    expect(model(fixture({ ...admin, role: "user", selfServiceEnabled: false })).sources).toEqual([]);
    expect(model(fixture({ ...admin, role: "service_policy_manager", selfServiceEnabled: false, policyManagementServices: [] })).sources).toEqual([]);
  });
});

describe("palette query feedback", () => {
  test("only active fetches report loading and errors never expose server details", () => {
    const query = { isFetching: false, isError: false, data: undefined, refetch: vi.fn() };
    expect(paletteQueryFeedback("Groups", query)).toEqual({ loading: false });
    expect(paletteQueryFeedback("Groups", { ...query, isFetching: true })).toEqual({ loading: true });
    const failed = { ...query, isError: true };
    const feedback = paletteQueryFeedback("Groups", failed);
    expect(feedback.error).toBe("Could not load groups. Results may be incomplete.");
    feedback.onRetry?.();
    expect(failed.refetch).toHaveBeenCalledOnce();
  });

  test("cached data survives refresh errors and retry retries failed sources only", () => {
    const success = { isFetching: false, isError: false, data: [], refetch: vi.fn() };
    const failure = { isFetching: false, isError: true, data: ["cached"], refetch: vi.fn() };
    const feedback = paletteQueryFeedback("Services", success, failure);
    expect(feedback.error).toContain("Available results may be out of date");
    feedback.onRetry?.();
    expect(failure.refetch).toHaveBeenCalledOnce();
    expect(success.refetch).not.toHaveBeenCalled();
  });

  test("background refreshes do not add loading rows for cached result sets", () => {
    const query = { isFetching: true, isError: false, data: ["cached"], refetch: vi.fn() };
    expect(paletteQueryFeedback("Services", query)).toEqual({ loading: false });
    expect(paletteQueryFeedback("Services", { ...query, data: [] })).toEqual({ loading: false });
    expect(paletteQueryFeedback("Services", query, { ...query, data: undefined })).toEqual({ loading: true });
  });
});
