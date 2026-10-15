import { describe, expect, test } from "vitest";
import type { AgentTokenOptions, TokenTtlPolicy } from "../src/types";
import { actionSelectionCounts, grantActionGroups } from "../src/lib/grant-actions";
import { agentTokenResourceSelection, agentTokenSelectedActions } from "../src/lib/helpers";
import { buildAgentTokenBoundary, buildAgentTokenIssuance, createAgentTokenDraft, lifetimeLabel, tokenActionChoices } from "../src/lib/token-draft";

const ttlPolicy: TokenTtlPolicy = { defaultTtl: "8h", maxTtl: "30d", options: ["1h", "8h", "30d", "never"] };
const options: AgentTokenOptions = {
  policyGeneration: 1,
  executionContexts: ["internal", "external"],
  resources: [], resourceGroups: [], mcp: null,
  services: [
    {
      service: "jira", displayName: "Jira", brokerHosts: [], executionContexts: ["internal", "external"],
      actions: [
        { action: "issue.view", description: "View an issue", readOnly: true, executionContexts: ["internal"], requiredScopeTypes: ["project"], resourceType: "jira_project", effectiveAccessByExecutionContext: {} },
        { action: "issue.search", description: "Search issues", readOnly: true, executionContexts: ["internal"], requiredScopeTypes: ["project"], resourceType: "jira_project", effectiveAccessByExecutionContext: {} },
        { action: "issue.update", description: "Update an issue", readOnly: false, executionContexts: ["external"], requiredScopeTypes: ["project"], resourceType: "jira_project", effectiveAccessByExecutionContext: {} },
      ],
    },
    {
      service: "mail", displayName: "Mail", brokerHosts: [], executionContexts: ["internal"],
      actions: [{ action: "message.view", description: "View a message", readOnly: true, executionContexts: ["internal"], requiredScopeTypes: [], resourceType: null, effectiveAccessByExecutionContext: {} }],
    },
  ],
};

describe("token boundary construction", () => {
  test("a manually selected constructor service has no inherited actions or resource restriction", () => {
    const namedOptions = { ...options, services: [{ ...options.services[0], service: "constructor" }] };
    const draft = { ...createAgentTokenDraft(namedOptions, ttlPolicy), name: "agent", accessMode: "restricted" as const, selectedServices: ["constructor"] };
    expect(agentTokenSelectedActions(draft.selectedActions, "constructor")).toEqual([]);
    expect(agentTokenResourceSelection(draft.resourceSelections, "constructor")).toBeUndefined();
    expect(buildAgentTokenBoundary(draft, namedOptions)).toEqual({ valid: false, issues: [{ field: "service:constructor", message: "Select at least one action for Jira." }] });
    expect(buildAgentTokenIssuance(draft, namedOptions, ttlPolicy).valid).toBe(false);
    const selected = { ...draft, selectedActions: { ...draft.selectedActions, constructor: ["issue.view"] } };
    expect(buildAgentTokenIssuance(selected, namedOptions, ttlPolicy)).toEqual({ valid: true, body: {
      name: "agent", ttl: "8h", allowedExecutionContexts: ["internal", "external"], allowedServices: ["constructor"], serviceRestrictions: { constructor: { actions: ["issue.view"] } },
    } });
  });

  test("service prefills and explicit empty resources work for constructor", () => {
    const namedOptions = { ...options, services: [{ ...options.services[0], service: "constructor" }] };
    const draft = createAgentTokenDraft(namedOptions, ttlPolicy, ["constructor"]);
    expect(agentTokenSelectedActions(draft.selectedActions, "constructor")).toEqual(["issue.view", "issue.search", "issue.update"]);
    const boundary = buildAgentTokenBoundary({ ...draft, resourceSelections: { constructor: { resourceIds: [], resourceGroupIds: [] } } }, namedOptions);
    expect(boundary).toEqual({ valid: true, boundary: {
      allowedExecutionContexts: ["internal", "external"], allowedServices: ["constructor"], serviceRestrictions: { constructor: { actions: ["issue.search", "issue.update", "issue.view"], resources: { resourceIds: [], resourceGroupIds: [] } } },
    } });
  });

  test("prefills every action of requested services and copies the initial options", () => {
    const draft = createAgentTokenDraft(options, ttlPolicy, ["jira"]);
    expect(draft).toMatchObject({ name: "", lifetime: "8h", accessMode: "restricted", selectedServices: ["jira"], selectedActions: { jira: ["issue.view", "issue.search", "issue.update"] } });
    expect(draft.selectedExecutionContexts).toEqual(options.executionContexts);
    expect(draft.selectedExecutionContexts).not.toBe(options.executionContexts);
    expect(draft).not.toHaveProperty("options");
    expect(draft).not.toHaveProperty("ttlPolicy");
    expect(draft).not.toHaveProperty("targetPrincipalId");
  });

  test("incomplete restricted drafts never fall back to following grants", () => {
    const draft = { ...createAgentTokenDraft(options, ttlPolicy), name: "agent", accessMode: "restricted" as const };
    expect(buildAgentTokenBoundary(draft, options)).toEqual({ valid: false, issues: [{ field: "services", message: "Select at least one service." }] });
    expect(buildAgentTokenIssuance(draft, options, ttlPolicy)).toEqual({ valid: false, issues: [{ field: "services", message: "Select at least one service." }] });
    const stalePrefill = createAgentTokenDraft(options, ttlPolicy, ["retired-service"]);
    expect(stalePrefill.accessMode).toBe("restricted");
    expect(buildAgentTokenBoundary(stalePrefill, options).valid).toBe(false);
  });

  test("requires contexts and an action in every selected service", () => {
    const draft = { ...createAgentTokenDraft(options, ttlPolicy, ["jira", "mail"]), name: "agent", selectedExecutionContexts: [], selectedActions: { jira: ["issue.view"] } };
    const expected = { valid: false, issues: [{ field: "contexts", message: "Select at least one execution context." }, { field: "service:mail", message: "Select at least one action for Mail." }] };
    expect(buildAgentTokenBoundary(draft, options)).toEqual(expected);
    expect(buildAgentTokenIssuance(draft, options, ttlPolicy)).toEqual(expected);
  });

  test("name and lifetime affect issuance but never the access preview", () => {
    const draft = createAgentTokenDraft(options, ttlPolicy);
    const boundary = { valid: true, boundary: { allowedExecutionContexts: ["internal", "external"] } };
    expect(buildAgentTokenBoundary(draft, options)).toEqual(boundary);
    expect(buildAgentTokenBoundary({ ...draft, name: "agent", lifetime: "removed-choice" }, options)).toEqual(boundary);
    expect(buildAgentTokenIssuance(draft, options, ttlPolicy)).toEqual({ valid: false, issues: [{ field: "name", message: "Enter a token name." }] });
    expect(buildAgentTokenIssuance({ ...draft, name: "agent", lifetime: "removed-choice" }, options, ttlPolicy)).toEqual({ valid: false, issues: [{ field: "lifetime", message: "Choose an available token lifetime." }] });
    expect(buildAgentTokenIssuance({ ...draft, name: "  agent  " }, options, ttlPolicy)).toEqual({ valid: true, body: { name: "agent", ttl: "8h", allowedExecutionContexts: ["internal", "external"] } });
  });

  test("uses exactly the same explicit boundary for preview and issuance", () => {
    const draft = { ...createAgentTokenDraft(options, ttlPolicy, ["jira", "mail"]), name: "agent", lifetime: "never", resourceSelections: { jira: { resourceIds: ["ops", "eng"], resourceGroupIds: ["docs"] } } };
    const preview = buildAgentTokenBoundary(draft, options);
    expect(preview.valid).toBe(true);
    if (!preview.valid) throw new Error("Expected a complete boundary");
    expect(buildAgentTokenIssuance(draft, options, ttlPolicy)).toEqual({ valid: true, body: { ...preview.boundary, name: "agent", never: true } });
    expect(preview.boundary.serviceRestrictions).toEqual({
      jira: { actions: ["issue.search", "issue.update", "issue.view"], resources: { resourceIds: ["eng", "ops"], resourceGroupIds: ["docs"] } },
      mail: { actions: ["message.view"] },
    });
  });

  test("empty resources are a valid restriction distinct from following grants", () => {
    const draft = { ...createAgentTokenDraft(options, ttlPolicy, ["jira"]), name: "agent", resourceSelections: { jira: { resourceIds: [], resourceGroupIds: [] } } };
    const preview = buildAgentTokenBoundary(draft, options);
    expect(preview).toMatchObject({ valid: true, boundary: { allowedServices: ["jira"], serviceRestrictions: { jira: { resources: { resourceIds: [], resourceGroupIds: [] } } } } });
    expect(buildAgentTokenIssuance(draft, options, ttlPolicy).valid).toBe(true);
    expect(buildAgentTokenBoundary({ ...draft, resourceSelections: {} }, options)).toMatchObject({ valid: true, boundary: { serviceRestrictions: { jira: { actions: ["issue.search", "issue.update", "issue.view"] } } } });
    const follow = buildAgentTokenBoundary({ ...draft, accessMode: "policy" }, options);
    expect(follow).toEqual({ valid: true, boundary: { allowedExecutionContexts: ["internal", "external"] } });
  });

  test("live option refreshes retain selected references without broadening their boundary", () => {
    const draft = { ...createAgentTokenDraft(options, ttlPolicy, ["jira"]), name: "agent", resourceSelections: { jira: { resourceIds: [], resourceGroupIds: ["docs"] } } };
    const initial = structuredClone(draft);
    const refreshed: AgentTokenOptions = { ...options, policyGeneration: 2, executionContexts: [], services: [] };
    expect(buildAgentTokenBoundary(draft, refreshed)).toEqual(buildAgentTokenBoundary(draft, options));
    expect(buildAgentTokenIssuance(draft, refreshed, ttlPolicy).valid).toBe(true);
    expect(draft).toEqual(initial);
    const newPolicy = { ...ttlPolicy, options: ["1h"] };
    expect(buildAgentTokenIssuance(draft, refreshed, newPolicy)).toEqual({ valid: false, issues: [{ field: "lifetime", message: "Choose an available token lifetime." }] });
  });

  test("retains resource restrictions for stale actions even when remaining granted actions need no resources", () => {
    const draft = { ...createAgentTokenDraft(options, ttlPolicy, ["mail"]), name: "agent", selectedActions: { mail: ["message.view", "retired.resource.read"] }, resourceSelections: { mail: { resourceIds: [], resourceGroupIds: ["mailboxes"] } } };
    const preview = buildAgentTokenBoundary(draft, options);
    expect(preview).toMatchObject({ valid: true, boundary: { serviceRestrictions: { mail: { actions: ["message.view", "retired.resource.read"], resources: { resourceIds: [], resourceGroupIds: ["mailboxes"] } } } } });
    const currentOnly = buildAgentTokenBoundary({ ...draft, selectedActions: { mail: ["message.view"] } }, options);
    expect(currentOnly).toEqual({ valid: true, boundary: { allowedExecutionContexts: ["internal", "external"], allowedServices: ["mail"], serviceRestrictions: { mail: { actions: ["message.view"] } } } });
  });
});

describe("token action choices", () => {
  test("retains selected context-ineligible metadata without showing unselected ineligible actions", () => {
    const choices = tokenActionChoices(options, "jira", ["external"], ["issue.view"]);
    expect(choices.map((choice) => choice.action)).toEqual(["issue.view", "issue.update"]);
    expect(choices[0]).toEqual({ action: "issue.view", description: "View an issue", readOnly: true, available: false, unavailableReason: "Not available in the selected execution contexts" });
    expect(actionSelectionCounts(choices, ["issue.view"])).toEqual({ readOnly: 1, writeCapable: 0 });
    expect(grantActionGroups(choices, ["issue.view"], "")[0]).toMatchObject({ selected: 1, total: 1 });
  });

  test("missing granted actions remain removable and conservatively write-capable", () => {
    const choices = tokenActionChoices(options, "jira", ["internal"], ["retired.action"]);
    expect(choices.at(-1)).toEqual({ action: "retired.action", available: false, unavailableReason: "Not currently granted" });
    expect(actionSelectionCounts(choices, ["retired.action"])).toEqual({ readOnly: 0, writeCapable: 1 });
    expect(tokenActionChoices(options, "removed-service", ["internal"], ["old.read"])).toEqual([{ action: "old.read", available: false, unavailableReason: "Not currently granted" }]);
  });
});

describe("token lifetime labels", () => {
  test("spell out broker durations and keep other spellings", () => {
    expect(["1h", "8h", "30d", "1d", "15m", "90s", "never", "P1D"].map(lifetimeLabel)).toEqual([
      "1 hour", "8 hours", "30 days", "1 day", "15 minutes", "90 seconds", "Never expires", "P1D",
    ]);
  });
});
