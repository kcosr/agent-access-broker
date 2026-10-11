import { describe, expect, test } from "vitest";
import { grantResourceChoices, type GrantResourceCatalog } from "../src/lib/grant-resources";
import type { PolicyServiceCatalog, ResourceDefinition, ResourceGroupRecord, ResourceSelection } from "../src/types";

const gitlab: PolicyServiceCatalog = {
  service: "gitlab", displayName: "GitLab", surface: "rest", actions: [],
  resourceScopes: { repository: { resourceType: "git_repository", selectors: ["all", "exact", "namespace"] } },
  configuredCredentialModes: ["service"], lookupCredentialConfigured: false
};
const jira: PolicyServiceCatalog = {
  ...gitlab, service: "jira", resourceScopes: { project: { resourceType: "jira_project", selectors: ["all", "exact"] } }
};
const resource = (id: string, resourceType: ResourceDefinition["resourceType"], overrides: Partial<ResourceDefinition> = {}): ResourceDefinition => ({
  id, resourceType, displayName: id, selector: { kind: "exact", value: id }, enabled: true, allowedExecutionContexts: ["internal"], ...overrides
});
const group = (id: string, includedResourceIds: string[], excludedResourceIds: string[] = []): ResourceGroupRecord => ({
  id, name: id, includedResourceIds, excludedResourceIds, version: 1
});
const catalog: GrantResourceCatalog = {
  resources: [
    resource("repo", "git_repository"), resource("project", "jira_project"),
    resource("disabled", "git_repository", { enabled: false }),
    resource("external", "git_repository", { allowedExecutionContexts: ["external"] })
  ],
  resourceGroups: [
    group("mixed", ["repo", "project"]), group("jira-only", ["project"]),
    group("exclude-only", [], ["disabled", "external"]),
    group("jira-includes-git-excludes", ["project"], ["repo"]),
    group("empty", []), group("inactive", ["disabled", "external"])
  ]
};
const empty: ResourceSelection = { resourceIds: [], resourceGroupIds: [] };

describe("grant resource choices", () => {
  test("uses capability resource types, including multiple types and shared Git surfaces", () => {
    expect(grantResourceChoices(catalog, gitlab, empty, ["internal"]).resources.map(({ id }) => id)).toEqual(["repo", "disabled", "external"]);
    expect(grantResourceChoices(catalog, { ...gitlab, service: "git-http", surface: "gateway" }, empty, []).resources.map(({ id }) => id)).toEqual(["repo", "disabled", "external"]);
    const multi = { ...gitlab, resourceScopes: { ...gitlab.resourceScopes, ...jira.resourceScopes } };
    expect(grantResourceChoices(catalog, multi, empty, []).resources).toEqual(catalog.resources);
  });

  test("retains mixed, exclusion-only, empty and inactive groups; filters unrelated new choices", () => {
    const choices = grantResourceChoices(catalog, gitlab, empty, ["internal"]);
    expect(choices.groups.map(({ group }) => group.id)).toEqual(["mixed", "exclude-only", "jira-includes-git-excludes", "empty", "inactive"]);
    expect(choices.groups.find(({ group }) => group.id === "exclude-only")?.excluded).toEqual(["disabled", "external"]);
    expect(choices.groups.find(({ group }) => group.id === "jira-includes-git-excludes")?.included).toEqual([]);
    expect(choices.groups.find(({ group }) => group.id === "jira-includes-git-excludes")?.excluded).toEqual(["repo"]);
  });

  test("service changes preserve selected entries, their names and original memberships without changing selection", () => {
    const selection = { resourceIds: ["repo", "project"], resourceGroupIds: ["jira-only", "mixed"] };
    const snapshot = structuredClone({ catalog, selection });
    for (const service of [gitlab, jira]) {
      const choices = grantResourceChoices(catalog, service, selection, ["internal"]);
      expect(choices.resources).toContain(catalog.resources[0]);
      expect(choices.resources).toContain(catalog.resources[1]);
      expect(choices.groups.find(({ group }) => group.id === "mixed")?.group).toEqual(catalog.resourceGroups[0]);
      expect(choices.groups.find(({ group }) => group.id === "jira-only")?.group.name).toBe("jira-only");
      expect(choices.hasMismatch).toBe(true);
    }
    expect({ catalog, selection }).toEqual(snapshot);
    expect(grantResourceChoices(catalog, gitlab, empty, []).resources.some(({ id }) => id === "project")).toBe(false);
  });

  test("missing/unconfigured service leaves choices unfiltered and adds no mismatch", () => {
    const choices = grantResourceChoices(catalog, null, { resourceIds: ["project"], resourceGroupIds: ["mixed"] }, ["internal"]);
    expect(choices.resources).toEqual(catalog.resources);
    expect(choices.groups.map(({ group }) => group)).toEqual(catalog.resourceGroups);
    expect(choices.hasMismatch).toBe(false);
  });

  test("does not flag relevant mixed groups for unrelated included or excluded members", () => {
    const selection = { ...empty, resourceGroupIds: ["mixed"] };
    expect(grantResourceChoices(catalog, gitlab, selection, ["internal"]).hasMismatch).toBe(false);
    const withExclusion = { ...catalog, resourceGroups: [group("mixed-exclusions", ["repo"], ["project"])] };
    expect(grantResourceChoices(withExclusion, gitlab, { ...empty, resourceGroupIds: ["mixed-exclusions"] }, ["internal"]).hasMismatch).toBe(false);
    expect(grantResourceChoices(catalog, gitlab, { ...empty, resourceGroupIds: ["jira-includes-git-excludes"] }, ["internal"]).hasMismatch).toBe(false);
  });

  test("flags wrong-type direct selections and wholly unrelated selected groups", () => {
    expect(grantResourceChoices(catalog, gitlab, { ...empty, resourceIds: ["project"] }, ["internal"]).hasMismatch).toBe(true);
    expect(grantResourceChoices(catalog, gitlab, { ...empty, resourceGroupIds: ["jira-only"] }, ["internal"]).hasMismatch).toBe(true);
    expect(grantResourceChoices(catalog, gitlab, { ...empty, resourceGroupIds: ["empty"] }, ["internal"]).hasMismatch).toBe(false);
  });

  test("retains groups with no members visible in a delegated catalog without implying a mismatch", () => {
    // An administrator sees Jira membership; a Git-only manager receives the
    // same group with those out-of-scope members removed by catalog projection.
    const projected = { resources: [catalog.resources[0]], resourceGroups: [group("jira-only", [])] };
    const choices = grantResourceChoices(projected, gitlab, { ...empty, resourceGroupIds: ["jira-only"] }, ["internal"]);
    expect(choices.groups).toHaveLength(1);
    expect(choices.groups[0].group.name).toBe("jira-only");
    expect(choices.groups[0].empty).toBe(true);
    expect(choices.hasMismatch).toBe(false);
    expect(choices.hasEligibleInclusions).toBe(false);
    expect(grantResourceChoices(projected, gitlab, empty, ["internal"]).groups).toHaveLength(1);
  });

  test("catalog eligibility counts positive enabled compatible entries in any selected context", () => {
    const selection = { ...empty, resourceGroupIds: ["inactive", "exclude-only", "empty"] };
    expect(grantResourceChoices(catalog, gitlab, selection, ["internal"]).hasEligibleInclusions).toBe(false);
    expect(grantResourceChoices(catalog, gitlab, selection, ["internal", "external"]).hasEligibleInclusions).toBe(true);
    expect(grantResourceChoices(catalog, gitlab, { ...empty, resourceIds: ["project"] }, ["internal"]).hasEligibleInclusions).toBe(false);
    expect(grantResourceChoices(catalog, gitlab, { ...empty, resourceIds: ["repo"] }, []).hasEligibleInclusions).toBe(false);
    expect(grantResourceChoices(catalog, gitlab, { ...empty, resourceIds: ["repo"] }, ["internal"]).hasEligibleInclusions).toBe(true);
  });

  test("eligibility does not pretend to resolve exclusions or authorize access", () => {
    const allExcluded = { ...catalog, resourceGroups: [group("blocked", ["repo"], ["repo"])] };
    const choices = grantResourceChoices(allExcluded, gitlab, { ...empty, resourceGroupIds: ["blocked"] }, ["internal"]);
    expect(choices.hasEligibleInclusions).toBe(true);
    expect(choices.groups[0].excluded).toEqual(["repo"]);
  });

  test("unknown references remain in the selection and do not get mislabeled as a type mismatch", () => {
    const selection = { resourceIds: ["missing"], resourceGroupIds: ["missing-group"] };
    const choices = grantResourceChoices(catalog, gitlab, selection, ["internal"]);
    expect(choices.hasMismatch).toBe(false);
    expect(choices.hasEligibleInclusions).toBe(false);
    expect(selection).toEqual({ resourceIds: ["missing"], resourceGroupIds: ["missing-group"] });
  });
});
