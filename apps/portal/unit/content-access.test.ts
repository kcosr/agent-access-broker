import { describe, expect, test } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { AgentTokenOptions, LocationAccess, NormalizedResourceLocation, PolicyServiceCatalog } from "../src/types";
import { AccessCoverage, EffectiveAccessSummary } from "../src/components/effective-access";
import { buildAccessSummary, mergeEffectiveAccess } from "../src/lib/access";
import { buildAgentTokenServiceRestrictions } from "../src/lib/helpers";
import { coverageLabels, selectorLabel } from "../src/lib/resource-labels";
import { locationCoverage, locationInputHints, locationPreviewLabel } from "../src/lib/resource-locations";
import { grantResourceChoices } from "../src/lib/grant-resources";
import { indexResourceTypes } from "../src/lib/resource-types";
import { RESOURCE_TYPES } from "./resource-types.fixture";

const types = indexResourceTypes(RESOURCE_TYPES);
const root = "https://example.atlassian.net/wiki/spaces/ENG/folder/20";
const point = "https://example.atlassian.net/wiki/spaces/ENG/pages/30";
const complete: LocationAccess = {
  scope: "location", resourceTypes: ["confluence_space", "confluence_content"], domain: "page", enforcement: "request", containmentVerification: "at_invocation", projectionStatus: "complete",
  boundaries: [
    { included: [{ resourceType: "confluence_space", selector: { kind: "exact", value: "ENG" } }], excluded: [{ resourceType: "confluence_content", selector: { kind: "subtree", value: root } }] },
    { included: [{ resourceType: "confluence_content", selector: { kind: "exact", value: point } }], excluded: [] }
  ],
  clauses: [{ required: [0, 1], excludedRequests: [1], credentialMode: "per_user" }]
};
const unavailable: LocationAccess = { scope: "location", resourceTypes: ["confluence_space", "confluence_content"], domain: "page", enforcement: "request", containmentVerification: "at_invocation", projectionStatus: "too_complex", reasonCode: "resource_access_too_complex" };
const { scope: _scope, ...unavailableDetails } = unavailable;
const options: AgentTokenOptions = {
  policyGeneration: 1, agentTokenIssuancePolicy: { source: "user", contexts: [{ executionContext: "default", mode: "write_capable", groupIds: [] }] }, executionContexts: ["default"], resources: [], resourceGroups: [], mcp: null,
  services: [{ service: "confluence", displayName: "Confluence", brokerHosts: [], executionContexts: ["default"], actions: [{ scope: "location", resourceTypes: complete.resourceTypes, domain: "page", action: "page.update", description: "Update", readOnly: false, requiredScopeTypes: ["location"], executionContexts: ["default"], effectiveAccessByExecutionContext: { default: unavailableDetails } }] }]
};

describe("content location presentation", () => {
  test("retains typed conjunctions, local exclusions and competing whole-request conditions", () => {
    const rows = mergeEffectiveAccess([{ ...complete, service: "confluence", action: "page.view", executionContext: "default" }]);
    expect(rows[0].coverage).toEqual(complete);
    const label = coverageLabels(types, complete)[0];
    expect(label).toContain(`ENG except (${root} · root and descendants)`);
    expect(label).toContain(`AND (${point} · this page only)`);
    expect(label).toContain("does not apply when one of these boundaries covers the whole request");
    expect(label).toContain("per_user");
  });

  test("unavailable coverage remains visible without becoming no access or action-only access", () => {
    const action = buildAccessSummary(options)[0].actions[0];
    expect(action.coverage).toEqual(unavailable);
    expect(coverageLabels(types, action.coverage)).toEqual(["Coverage preview unavailable"]);
    const markup = renderToStaticMarkup(createElement(AccessCoverage, { coverage: action.coverage }));
    expect(markup).toContain("Coverage preview unavailable");
    expect(markup).not.toContain("No access");
    expect(markup).not.toContain("Action grant");
    expect(buildAgentTokenServiceRestrictions(["confluence"], { confluence: ["page.update"] }, { confluence: { resourceIds: ["selected"], resourceGroupIds: [] } }, options)).toEqual({ confluence: { actions: ["page.update"], resources: { resourceIds: ["selected"], resourceGroupIds: [] } } });
  });

  test("keeps unavailable and complete entries separate across contexts", () => {
    const rows = mergeEffectiveAccess([
      { ...unavailable, service: "confluence", action: "page.view", executionContext: "default" },
      { ...complete, service: "confluence", action: "page.view", executionContext: "internal" }
    ]);
    expect(rows).toHaveLength(2);
    expect(rows.map((row) => row.contexts)).toEqual([["default"], ["internal"]]);
  });

  test("empty complete location coverage is no access while unavailable coverage remains visible", () => {
    const empty: LocationAccess = { ...complete, projectionStatus: "complete", boundaries: [], clauses: [] };
    const { scope: _emptyScope, ...emptyDetails } = empty;
    const emptyOptions = structuredClone(options);
    const action = emptyOptions.services[0].actions[0];
    if (action.scope !== "location") throw new Error("location fixture required");
    action.effectiveAccessByExecutionContext.default = emptyDetails;
    expect(buildAccessSummary(emptyOptions)).toEqual([]);
    expect(buildAccessSummary(options)[0].actions[0].coverage).toEqual(unavailable);

    const entry = { ...empty, service: "confluence", action: "page.view", executionContext: "default" };
    expect(mergeEffectiveAccess([entry])).toEqual([]);
    const markup = renderToStaticMarkup(createElement(EffectiveAccessSummary, { result: { policyGeneration: 1, access: [entry] } }));
    expect(markup).toContain("No access currently");
    expect(markup).not.toContain("pt-access-table");
    expect(renderToStaticMarkup(createElement(AccessCoverage, { coverage: empty }))).toBe("<span>No access currently</span>");
    expect(mergeEffectiveAccess([entry, { ...unavailable, service: "confluence", action: "page.view", executionContext: "internal" }])).toEqual([
      { service: "confluence", actions: ["page.view"], contexts: ["internal"], coverage: unavailable }
    ]);
  });

  test.each([complete, unavailable])("preserves offline move warnings with $projectionStatus coverage", (coverage) => {
    const conditional = { ...coverage, domain: "page_move", requiresRuntimeRootVisibility: true };
    const rows = mergeEffectiveAccess([
      { ...conditional, service: "confluence", action: "page.move", executionContext: "default" },
      { ...coverage, domain: "page_move", service: "confluence", action: "page.move", executionContext: "internal" }
    ]);
    expect(rows).toHaveLength(2);
    const markup = renderToStaticMarkup(createElement(AccessCoverage, { coverage: rows[0].coverage }));
    expect(markup).toContain("Moves require runtime visibility of relevant excluded roots");
    expect(markup).toContain("This offline preview does not check whether those roots are current or readable");
    expect(markup).toContain("can block moves throughout its space");
    expect(markup).toContain("administrator can inspect the configured exclusion and correct or remove it");
    expect(renderToStaticMarkup(createElement(AccessCoverage, { coverage: rows[1].coverage }))).not.toContain("This offline preview");
  });

  test("distinguishes exact content from subtree coverage in selector and audit labels", () => {
    expect(selectorLabel(types, "confluence_content", { kind: "exact", value: point })).toContain("this page only");
    expect(selectorLabel(types, "confluence_content", { kind: "subtree", value: point })).toContain("root and descendants");
    expect(selectorLabel(types, "confluence_content", { kind: "exact", value: point.replace("/pages/", "/blog/") })).toContain("this blog post only");
    expect(selectorLabel(types, "confluence_content", { kind: "exact", value: "https://example.atlassian.net/wiki/spaces/blog/pages/1" })).toBe("https://example.atlassian.net/wiki/spaces/blog/pages/1 · this page only");
    expect(selectorLabel(types, "confluence_content", { kind: "exact", value: "https://example.atlassian.net/wiki/spaces/blog/blog/1" })).toBe("https://example.atlassian.net/wiki/spaces/blog/blog/1 · this blog post only");
  });

  test("offers both space and content resources for containment services", () => {
    const service = { resourceScopes: { location: { matching: "containment", domain: "page", selectorsByType: { confluence_space: ["exact", "all"], confluence_content: ["exact", "subtree"] }, containerTypes: ["confluence_space"], targetKinds: ["page"], ancestorKinds: ["page", "folder"], effects: ["content"] } } } as unknown as PolicyServiceCatalog;
    const resources = [
      { id: "space", resourceType: "confluence_space", selector: { kind: "exact" as const, value: "ENG" }, enabled: true, allowedExecutionContexts: ["default"] },
      { id: "content", resourceType: "confluence_content", selector: { kind: "subtree" as const, value: root }, enabled: true, allowedExecutionContexts: ["default"] },
      { id: "jira", resourceType: "jira_project", selector: { kind: "exact" as const, value: "ENG" }, enabled: true, allowedExecutionContexts: ["default"] }
    ];
    expect(grantResourceChoices({ resources, resourceGroups: [] }, service, { resourceIds: [], resourceGroupIds: [] }, ["default"]).resources.map((resource) => resource.id)).toEqual(["space", "content"]);
  });
});

describe("offline location editor", () => {
  test.each([
    ["https://example.atlassian.net/wiki/spaces/ENG", "space", null],
    ["https://example.atlassian.net/wiki/spaces/ENG/overview", "space", null],
    ["https://example.atlassian.net/wiki/spaces/ENG/pages/123/Runbooks", "page", "123"],
    ["https://example.atlassian.net/wiki/spaces/ENG/folder/321", "folder", "321"],
    ["https://example.atlassian.net/wiki/spaces/ENG/blog/54321/Release", "blog", "54321"],
    ["https://example.atlassian.net/wiki/spaces/ENG/blog/2026/11/20/54321/Release", "blog", "54321"]
  ])("prefills presentation for %s without claiming validation", (url, kind, rootId) => {
    expect(locationInputHints(url)).toEqual({ kind, rootId, spaceKey: "ENG" });
  });

  test("requires an explicit page coverage choice and fixes the other location kinds", () => {
    expect(locationCoverage("page", "")).toBeNull();
    expect(locationCoverage("page", "exact")).toBe("exact");
    expect(locationCoverage("page", "subtree")).toBe("subtree");
    expect(locationCoverage("space", "subtree")).toBe("space");
    expect(locationCoverage("folder", "exact")).toBe("subtree");
    expect(locationCoverage("blog", "subtree")).toBe("exact");
  });

  test("states the normalized space key and selected exact/subtree semantics", () => {
    const preview: NormalizedResourceLocation = { resourceType: "confluence_content", selector: { kind: "exact", value: point }, locationKind: "page", configuredSpaceKey: "ENG", verification: "not_checked" };
    expect(locationPreviewLabel(preview)).toBe("This page only");
    expect(locationPreviewLabel({ ...preview, selector: { kind: "subtree", value: point } })).toBe("This page and descendants");
    expect(locationPreviewLabel({ ...preview, locationKind: "space" })).toBe("Entire ENG space");
  });
});
