import { describe, expect, test } from "vitest";
import { buildAccessSummary } from "../src/lib/access";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AccessClause } from "../src/components/effective-access";
import { clauseLabel, resourceLabel, resourceSelectionLabels, selectorLabel } from "../src/lib/resource-labels";
import { indexResourceTypes, namespaceCoverage, NO_RESOURCE_TYPES, ResourceTypesProvider, resourceTypeLabel, selectorPlaceholder } from "../src/lib/resource-types";
import type { AgentTokenOptions, ResourceRecord } from "../src/types";
import { RESOURCE_TYPES } from "./resource-types.fixture";

const types = indexResourceTypes(RESOURCE_TYPES);

const options: AgentTokenOptions = {
  policyGeneration: 4, resources: [], resourceGroups: [], executionContexts: ["internal", "external"],
  services: [{ service: "gitlab", displayName: "Gitlab", brokerHosts: [], executionContexts: ["internal", "external"], actions: [{
    action: "repository.tree", description: "Read files", readOnly: true, resourceType: "git_repository", requiredScopeTypes: ["repository"], executionContexts: ["internal", "external"],
    effectiveAccessByExecutionContext: {
      internal: [{ included: [{ kind: "all" }], excluded: [] }],
      external: [
        { included: [{ kind: "all" }], excluded: [{ kind: "namespace", value: "private" }] },
        { included: [{ kind: "exact", value: "private/approved" }], excluded: [] }
      ]
    }
  }] }],
  mcp: null
};

describe("effective access presentation", () => {
  test("preserves separate grant clauses instead of applying exclusions globally", () => {
    const external = buildAccessSummary(options, "external")[0].actions[0];
    expect(external.clauses).toEqual(options.services[0].actions[0].effectiveAccessByExecutionContext.external);
    expect(external.clauses.map((clause) => clauseLabel(types, external.resourceType!, clause))).toEqual([
      "All Git repositories except Repositories under private", "private/approved"
    ]);
  });

  test("combines contexts only when their compiled boundaries match", () => {
    expect(buildAccessSummary(options)[0].actions).toHaveLength(2);
    const identical = structuredClone(options);
    identical.services[0].actions[0].effectiveAccessByExecutionContext.external = identical.services[0].actions[0].effectiveAccessByExecutionContext.internal;
    expect(buildAccessSummary(identical)[0].actions[0].contexts).toEqual(["internal", "external"]);
  });

  test("retains whole-request conditions separately from resource exclusions", () => {
    const conditional = structuredClone(options);
    const clause = conditional.services[0].actions[0].effectiveAccessByExecutionContext.external[0];
    clause.excludedRequests = [{ included: [{ kind: "namespace", value: "engineering" }], excluded: [] }];
    const displayed = buildAccessSummary(conditional, "external")[0].actions[0].clauses[0];
    expect(displayed.excludedRequests).toEqual(clause.excludedRequests);
    expect(displayed.excluded).toEqual([{ kind: "namespace", value: "private" }]);
    const markup = renderToStaticMarkup(createElement(ResourceTypesProvider, { value: types }, createElement(AccessClause, { type: "git_repository", clause: displayed })));
    expect(markup).toContain("Does not apply when every requested resource is within:");
    expect(markup).toContain("Repositories under engineering");
  });

  test("keeps empty effective access empty", () => {
    const empty = structuredClone(options);
    empty.services[0].actions[0].effectiveAccessByExecutionContext = {};
    expect(buildAccessSummary(empty)).toEqual([]);
    expect(buildAccessSummary(options, "missing")).toEqual([]);
  });

  test("labels wildcard coverage without enumerating catalog resources", () => {
    const resource: ResourceRecord = { id: "spaces", resourceType: "confluence_space", selector: { kind: "all" }, allowedExecutionContexts: ["internal"], enabled: true, version: 1 };
    expect(resourceLabel(types, resource)).toBe("All Confluence spaces");
    expect(resourceLabel(types, { ...resource, displayName: "Documentation" })).toBe("Documentation · All Confluence spaces");
    expect(resourceSelectionLabels(types, { resourceIds: ["spaces"], resourceGroupIds: ["docs"] }, { resources: [resource], resourceGroups: [{ id: "docs", name: "Engineering docs" }] })).toEqual(["All Confluence spaces", "Engineering docs"]);
  });

  test("labels CloudBees CI job and controller coverage", () => {
    expect(selectorLabel(types, "cloudbees_ci_job", { kind: "exact", value: "team-ci/payments/build-api" })).toBe("team-ci/payments/build-api");
    expect(selectorLabel(types, "cloudbees_ci_job", { kind: "namespace", value: "team-ci" })).toBe("Jobs under team-ci");
    expect(selectorLabel(types, "cloudbees_ci_job", { kind: "namespace", value: "team-ci/payments" })).toBe("Jobs under team-ci/payments");
    expect(selectorLabel(types, "cloudbees_ci_job", { kind: "all" })).toBe("All CloudBees CI jobs");
  });

  test("labels types the broker does not describe by their raw id", () => {
    expect(resourceTypeLabel(types, "retired_type")).toBe("retired_type");
    expect(selectorLabel(types, "retired_type", { kind: "all" })).toBe("All retired_type");
    expect(selectorLabel(types, "retired_type", { kind: "namespace", value: "team" })).toBe("retired_type under team");
    expect(selectorLabel(NO_RESOURCE_TYPES, "git_repository", { kind: "exact", value: "engineering/payments" })).toBe("engineering/payments");
  });
});

describe("resource type metadata", () => {
  test("offers namespace coverage only for types with namespace selectors", () => {
    expect(namespaceCoverage(types, "git_repository")?.label).toBe("Repositories under a namespace");
    expect(namespaceCoverage(types, "cloudbees_ci_job")?.label).toBe("Jobs under a controller or folder");
    expect(namespaceCoverage(types, "jira_project")).toBeUndefined();
    expect(namespaceCoverage(types, "retired_type")).toBeUndefined();
  });

  test("uses broker examples as identifier placeholders", () => {
    expect(selectorPlaceholder(types, "git_repository", "exact")).toBe("engineering/payments");
    expect(selectorPlaceholder(types, "git_repository", "namespace")).toBe("engineering/platform");
    expect(selectorPlaceholder(types, "oauth_collection", "exact")).toBe("alpha");
    expect(selectorPlaceholder(types, "retired_type", "exact")).toBeUndefined();
  });
});

test("scope-free actions remain visible with explicit action grants", () => {
  const gmail: AgentTokenOptions = {policyGeneration:1,resources:[],resourceGroups:[],executionContexts:["default"],services:[{service:"gmail",displayName:"Gmail",brokerHosts:[],executionContexts:["default"],actions:[{action:"thread.trash",readOnly:false,description:"Trash",requiredScopeTypes:[],resourceType:null,executionContexts:["default"],effectiveAccessByExecutionContext:{default:[]}}]}],mcp:null};
  expect(buildAccessSummary(gmail)[0].actions[0]).toMatchObject({action:"thread.trash",resourceType:null,contexts:["default"]});
});
