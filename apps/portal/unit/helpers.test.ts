import { describe, expect, test } from "vitest";
import type { ModalState } from "../src/app-types";
import type { AgentTokenOptions, BrokerTokenRecord, PolicyCatalogResult } from "../src/types";
import {
  availableAgentTokenActions,
  availableAgentTokenServices,
  buildAgentTokenServiceRestrictions,
  buildPolicySubject,
  canManagePolicies,
  compactListPreview,
  identityDisplayName,
  isActionOnlyGrant,
  isPolicyGrantIdAllowed,
  microsoftLoginControl,
  passwordValidation,
  policyServiceLocked,
  policySubjectDisplayLabel,
  policySubjectShortLabel,
  policyGrantBody,
  policyGrantDraftForSubject,
  policyGrantKey,
  principalIdentityLabel,
  reconcileAgentTokenModalOptions,
  selectsAllPolicyActions,
  tokenAllowedServiceItems,
  tokenAllowedServicesSummary,
  tokenStatus,
  tokenStatusTone,
  tokenExecutionContextItems,
  tokenExecutionContextsSummary,
} from "../src/lib/helpers";

const catalog: PolicyCatalogResult = {
  resources: [], resourceGroups: [],
  executionContexts: {
    allowedValues: ["workstation", "internal", "external"],
    defaultContext: "workstation",
    contextRequired: false,
  },
  services: [
    {
      service: "github",
      displayName: "GitHub",
      surface: "gateway",
      gatewayKind: "git_http",
      actions: [
        {
          action: "issues.list",
          readOnly: true,
          description: "List issues",
          requiredScopeTypes: ["repository"],
          credentialModes: ["user", "service"],
          lookupRequired: false,
          inputSchema: {},
        },
      ],
      resourceScopes: {
        repository: {
          resourceType: "git_repository",
          selectors: ["exact", "namespace", "all"],
        },
      },
      configuredCredentialModes: ["user", "service"],
      lookupCredentialConfigured: true,
    },
  ],
  subjects: {
    users: [{ principalId: "alice", displayName: "Alice Lovelace", status: "active" }],
    groups: [{ groupId: "agents", displayName: "Automation Agents", status: "active" }],
    anonymous: false,
  },
};

function token(overrides: Partial<BrokerTokenRecord>): BrokerTokenRecord {
  return {
    tokenId: "tok_1",
    principalId: "alice",
    name: "agent",
    tokenClass: "agent_invoke",
    scopes: {},
    createdAt: "2026-01-01T00:00:00Z",
    createdBy: "alice",
    ...overrides,
  };
}

const tokenOptions: AgentTokenOptions = {
  policyGeneration: 1, resources: [], resourceGroups: [],
  executionContexts: ["workstation", "internal", "external"],
  services: [
    { service: "github", displayName: "Github", brokerHosts: [], executionContexts: ["workstation", "internal"], actions: [{ action: "issues.list", readOnly: false, description: "List issues", requiredScopeTypes: ["project"], resourceType: "jira_project", executionContexts: ["workstation", "internal"], effectiveAccessByExecutionContext: { internal: [{ included: [{ kind: "all" }], excluded: [] }] } }] },
    { service: "confluence", displayName: "Confluence", brokerHosts: [], executionContexts: ["external"], actions: [{ action: "page.view", readOnly: false, description: "View pages", requiredScopeTypes: ["space"], resourceType: "confluence_space", executionContexts: ["external"], effectiveAccessByExecutionContext: { external: [{ included: [{ kind: "exact", value: "ENG" }], excluded: [] }] } }] },
    { service: "shared", displayName: "Shared", brokerHosts: [], executionContexts: ["internal", "external"], actions: [{ action: "read", readOnly: false, description: "Read shared data", requiredScopeTypes: ["project"], resourceType: "jira_project", executionContexts: ["internal", "external"], effectiveAccessByExecutionContext: { internal: [{ included: [{ kind: "all" }], excluded: [] }] } }] }
  ],
  mcp: null
};

test("keeps restricted references and wizard state when access becomes empty", () => {
  const modal: Extract<ModalState, { type: "token" }> = {
    type: "token", administrative: false, targetPrincipalId: "alice", options: tokenOptions,
    accessMode: "restricted", screen: "review", selectedExecutionContexts: ["external"],
    selectedServices: ["confluence"], selectedActions: { confluence: ["page.view"] },
    resourceSelections: { confluence: { resourceIds: [], resourceGroupIds: ["docs"] } },
    name: "workspace", lifetime: "1h", ttlPolicy: { defaultTtl: "1h", maxTtl: "1h", options: ["1h"] }
  };
  const refreshed = { ...tokenOptions, services: [] };
  const reconciled = reconcileAgentTokenModalOptions(modal, refreshed);
  expect(reconciled.options).toBe(refreshed);
  expect(reconciled.screen).toBe("review");
  expect(reconciled.resourceSelections).toEqual(modal.resourceSelections);
  expect(reconciled.selectedServices).toEqual(["confluence"]);
  expect(reconciled.selectedActions).toEqual({ confluence: ["page.view"] });
});

describe("portal helper policy logic", () => {
  test("recognizes grants whose actions take no resources", () => {
    const action = (name: string, requiredScopeTypes: string[]) => ({ action: name, readOnly: true, description: name, requiredScopeTypes, credentialModes: ["per_user"], lookupRequired: false, inputSchema: {} });
    const service = {
      service: "mail", displayName: "Mail", surface: "invoke", actions: [action("message.view", []), action("record.list", ["collection"])],
      resourceScopes: { collection: { resourceType: "collection", selectors: ["exact"] } }, configuredCredentialModes: ["per_user"], lookupCredentialConfigured: false
    };
    const none = { resourceIds: [], resourceGroupIds: [] };
    expect(isActionOnlyGrant(service, { actions: ["message.view"], resources: none })).toBe(true);
    expect(isActionOnlyGrant(service, { actions: ["message.view", "record.list"], resources: none })).toBe(false);
    expect(isActionOnlyGrant(service, { actions: ["message.view"], resources: { resourceIds: ["inbox"], resourceGroupIds: [] } })).toBe(false);
    // Unknown actions or services are not assumed to be resource-free.
    expect(isActionOnlyGrant(service, { actions: ["message.view", "retired.action"], resources: none })).toBe(false);
    expect(isActionOnlyGrant(null, { actions: ["message.view"], resources: none })).toBe(false);
  });

  test("builds a policy grant body using resource references", () => {
    const draft = policyGrantDraftForSubject(catalog, "user:alice");
    draft.service = "github";
    draft.actions = ["issues.list"];
    draft.credentialMode = "user";
    draft.priority = "10";
    draft.resources = { resourceIds: ["portal"], resourceGroupIds: [] };

    const result = policyGrantBody(draft, catalog);

    expect(result.messages).toEqual([]);
    expect(result.body).toMatchObject({
      subjects: ["user:alice"],
      service: "github",
      actions: ["issues.list"],
      executionContexts: ["workstation"],
      credentialMode: "user",
      priority: 10,
      resources: { resourceIds: ["portal"], resourceGroupIds: [] },
      status: "active",
    });
  });

  test("allows an explicitly empty grant resource selection", () => {
    const draft = policyGrantDraftForSubject(catalog, "group:agents");
    draft.actions = ["issues.list"];
    draft.credentialMode = "user";
    expect(policyGrantBody(draft, catalog).body?.resources).toEqual({ resourceIds: [], resourceGroupIds: [] });
  });

  test("requires a finite set of configured execution contexts", () => {
    const draft = policyGrantDraftForSubject(catalog, "group:agents");
    expect(draft.executionContexts).toEqual(["workstation"]);

    draft.service = "github";
    draft.actions = ["issues.list"];
    draft.credentialMode = "user";
    draft.resources = { resourceIds: ["portal"], resourceGroupIds: [] };
    draft.executionContexts = [];
    expect(policyGrantBody(draft, catalog).messages).toContainEqual(
      expect.objectContaining({ field: "executionContexts", code: "required" })
    );

    draft.executionContexts = ["retired"];
    expect(policyGrantBody(draft, catalog).messages).toContainEqual(
      expect.objectContaining({ field: "executionContexts", code: "invalid" })
    );

    draft.executionContexts = ["internal", "external"];
    expect(policyGrantBody(draft, catalog).body).toMatchObject({
      executionContexts: ["internal", "external"],
    });
  });

  test("validates grant ids and canonical subjects", () => {
    expect(isPolicyGrantIdAllowed("team.release_2026")).toBe(true);
    expect(isPolicyGrantIdAllowed("export")).toBe(false);
    expect(isPolicyGrantIdAllowed("../escape")).toBe(false);
    expect(buildPolicySubject("anonymousUser", "ignored")).toBe("user:anonymous");
    expect(policyGrantKey({ grantRef: "", index: 7 })).toBe("toml:7");
  });

  test("keeps immutable identity visible beside human-readable subject names", () => {
    expect(principalIdentityLabel("usr-123", "Ada Lovelace")).toBe("Ada Lovelace · ID: usr-123");
    expect(principalIdentityLabel("usr-123", null)).toBe("usr-123");
    expect(policySubjectDisplayLabel("user:alice", catalog)).toBe("Alice Lovelace · ID: user:alice");
    expect(policySubjectDisplayLabel("group:agents", catalog)).toBe("Automation Agents · ID: group:agents");
    expect(policySubjectDisplayLabel("user:missing", catalog)).toBe("user:missing");
    expect(policySubjectDisplayLabel("user:anonymous", catalog)).toBe("user:anonymous");
  });

  test("shortens subjects to display names only when the catalog knows one", () => {
    expect(policySubjectShortLabel("user:alice", catalog)).toBe("Alice Lovelace");
    expect(policySubjectShortLabel("group:agents", catalog)).toBe("Automation Agents");
    expect(policySubjectShortLabel("user:missing", catalog)).toBe("user:missing");
    expect(policySubjectShortLabel("group:anonymous", catalog)).toBe("group:anonymous");
    expect(policySubjectShortLabel("user:alice", null)).toBe("user:alice");
  });

  test("neutralizes identity-like separators and bidi controls in display names", () => {
    expect(identityDisplayName(" Alice Admin — user:usr-privileged\u202e ")).toBe("Alice Admin user usr-privileged");
    expect(principalIdentityLabel("usr-attacker", "Alice Admin — user:usr-privileged\u202e")).toBe(
      "Alice Admin user usr-privileged · ID: usr-attacker"
    );
  });

  test("recognizes exactly the complete action catalog", () => {
    const service = catalog.services[0];
    expect(selectsAllPolicyActions(service, ["issues.list"])).toBe(true);
    expect(selectsAllPolicyActions(service, ["issues.list", "unknown"])).toBe(false);
    expect(selectsAllPolicyActions(service, [])).toBe(false);
    expect(selectsAllPolicyActions(null, ["issues.list"])).toBe(false);
  });

  test("keeps semantic list values in bounded text previews", () => {
    expect(compactListPreview(["page.view", "page.create", "page.update", "page.move"])).toBe(
      "page.view, page.create +2"
    );
    expect(compactListPreview(["default"])).toBe("default");
  });


});

describe("portal helper status and shell logic", () => {
  test("allows policy navigation for global and scoped policy managers", () => {
    expect(canManagePolicies({ role: "admin", selfServiceEnabled: true, authenticated: true,  })).toBe(true);
    expect(canManagePolicies({ role: "service_policy_manager", selfServiceEnabled: true, authenticated: true, policyManagementServices: ["confluence"] })).toBe(true);
    expect(canManagePolicies({ role: "service_policy_manager", selfServiceEnabled: true, authenticated: true, policyManagementServices: [] })).toBe(true);
    expect(canManagePolicies({ role: "user", selfServiceEnabled: true, authenticated: true })).toBe(false);
  });

  test("locks only scoped policy manager edits to their stored service", () => {
    const manager = { role: "service_policy_manager" as const, selfServiceEnabled: true, authenticated: true, policyManagementServices: ["confluence"] };
    expect(policyServiceLocked(manager, "edit")).toBe(true);
    expect(policyServiceLocked(manager, "create")).toBe(false);
    expect(policyServiceLocked(manager, "duplicate")).toBe(false);
    expect(policyServiceLocked({ ...manager, role: "admin" }, "edit")).toBe(false);
  });

  test("hides Microsoft linking while OIDC is disabled but preserves unlink for an active method", () => {
    expect(microsoftLoginControl(undefined, false)).toBe("disabled");
    expect(microsoftLoginControl("disabled", false)).toBe("disabled");
    expect(microsoftLoginControl(undefined, true)).toBe("link");
    expect(microsoftLoginControl("active", false)).toBe("unlink");
  });

  test("reports token status in precedence order", () => {
    expect(tokenStatus(token({ revokedAt: "2026-01-02T00:00:00Z", expiresAt: "2999-01-01T00:00:00Z", pausedAt: "2026-01-01T00:00:00Z" }))).toBe("Revoked");
    expect(tokenStatus(token({ expiresAt: "2000-01-01T00:00:00Z", pausedAt: "1999-01-01T00:00:00Z" }))).toBe("Expired");
    expect(tokenStatus(token({ expiresAt: "2999-01-01T00:00:00Z", pausedAt: "2026-01-01T00:00:00Z" }))).toBe("Paused");
    expect(tokenStatus(token({ expiresAt: "2999-01-01T00:00:00Z" }))).toBe("Active");
    expect(tokenStatusTone("Active")).toBe("success");
    expect(tokenStatusTone("Paused")).toBe("warning");
    expect(tokenStatusTone("Expired")).toBe("warning");
    expect(tokenStatusTone("Revoked")).toBe("neutral");
  });

  test("derives token service choices from the selected execution contexts", () => {
    expect(availableAgentTokenServices(tokenOptions, [])).toEqual([]);
    expect(availableAgentTokenServices(tokenOptions, ["internal"])).toEqual(["github", "shared"]);
    expect(availableAgentTokenServices(tokenOptions, ["external"])).toEqual(["confluence", "shared"]);
    expect(availableAgentTokenServices(tokenOptions, ["workstation", "external"])).toEqual(["github", "confluence", "shared"]);
  });

  test("filters action choices to selected contexts", () => {
    expect(availableAgentTokenActions(tokenOptions, "github", ["external"])).toEqual([]);
    expect(availableAgentTokenActions(tokenOptions, "github", ["internal"]).map((action) => action.action)).toEqual(["issues.list"]);
  });

  test("preserves restricted-empty versus follow-grants token semantics", () => {
    const restrictions = buildAgentTokenServiceRestrictions(
      ["github", "confluence", "shared"],
      { github: ["issues.list"], confluence: ["page.view"], shared: ["read"] },
      { github: { resourceIds: [], resourceGroupIds: [] }, confluence: { resourceIds: ["ops", "eng"], resourceGroupIds: ["docs"] } },
      tokenOptions
    );
    expect(restrictions.github.resources).toEqual({ resourceIds: [], resourceGroupIds: [] });
    expect(restrictions.shared).not.toHaveProperty("resources");
    expect(restrictions.confluence.resources).toEqual({ resourceIds: ["eng", "ops"], resourceGroupIds: ["docs"] });
  });

  test("drops meaningless resource restrictions for mailbox-wide actions", () => {
    const options: AgentTokenOptions = { ...tokenOptions, services: [{ service: "gmail", displayName: "Gmail", brokerHosts: [], executionContexts: ["internal"], actions: [{ action: "message.trash", readOnly: false, description: "Trash", resourceType: null, executionContexts: ["internal"], requiredScopeTypes: [], effectiveAccessByExecutionContext: {} }] }] };
    const restrictions = buildAgentTokenServiceRestrictions(["gmail"], { gmail: ["message.trash"] }, { gmail: { resourceIds: [], resourceGroupIds: ["empty"] } }, options);
    expect(restrictions.gmail).toEqual({ actions: ["message.trash"] });
  });

  test("labels bounded, legacy, stale, and non-agent token contexts", () => {
    expect(tokenExecutionContextsSummary(token({}), tokenOptions.executionContexts)).toBe("Legacy unbound");
    expect(tokenExecutionContextsSummary(token({ scopes: { allowedExecutionContexts: ["internal"] } }), tokenOptions.executionContexts)).toBe("internal");
    expect(tokenExecutionContextsSummary(token({ scopes: { allowedExecutionContexts: ["retired"] } }), tokenOptions.executionContexts)).toBe("retired (stale)");
    expect(tokenExecutionContextsSummary(token({ scopes: { allowedExecutionContexts: [] } }), tokenOptions.executionContexts)).toBe("Invalid binding");
    expect(tokenExecutionContextsSummary(token({ tokenClass: "admin" }), tokenOptions.executionContexts)).toBe("Not applicable");
    expect(tokenExecutionContextItems(token({ scopes: { allowedExecutionContexts: ["internal", "retired"] } }), tokenOptions.executionContexts)).toEqual([
      "internal",
      "retired (stale)",
    ]);
    expect(tokenExecutionContextItems(token({}), tokenOptions.executionContexts)).toBeNull();
  });

  test("renders token service caveats defensively", () => {
    expect(tokenAllowedServicesSummary(token({}))).toBe("All configured");
    expect(tokenAllowedServicesSummary(token({ scopes: { allowedServices: ["github", "confluence"] } }))).toBe("github, confluence");
    expect(tokenAllowedServicesSummary(token({ scopes: { allowedServices: [] } }))).toBe("Invalid allowlist");
    expect(tokenAllowedServicesSummary(token({ scopes: { allowedServices: { corrupt: true } as unknown as string[] } }))).toBe("Invalid allowlist");
    expect(tokenAllowedServicesSummary(token({ tokenClass: "user_manage", scopes: { allowedServices: { corrupt: true } as unknown as string[] } }))).toBe("Not applicable");
    expect(tokenAllowedServiceItems(token({ scopes: { allowedServices: ["github", "confluence"] } }))).toEqual(["github", "confluence"]);
    expect(tokenAllowedServiceItems(token({}))).toBeNull();
  });


});

describe("small portal helpers", () => {
  test("reports password validation outcomes", () => {
    expect(passwordValidation("abc", "def")).toBe("New passwords do not match.");
    expect(passwordValidation("abc", "abc")).toBeNull();
    expect(passwordValidation("", "")).toBeNull();
  });
});
