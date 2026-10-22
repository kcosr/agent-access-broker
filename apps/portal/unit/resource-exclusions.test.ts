import { describe, expect, test } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { ResourceChoices } from "../src/components/resource-picker";
import { indexResourceTypes, ResourceTypesProvider, resourceExclusionIssue, supportsResourceExclusions } from "../src/lib/resource-types";
import type { ResourceDefinition } from "../src/types";
import { RESOURCE_TYPES } from "./resource-types.fixture";

const types = indexResourceTypes(RESOURCE_TYPES.map((type) => ({ ...type, supportsExclusions: type.id !== "jira_project" })));
const resources: ResourceDefinition[] = [
  { id: "project", resourceType: "jira_project", displayName: "Inclusion-only project", selector: { kind: "exact", value: "OPS" }, enabled: true, allowedExecutionContexts: ["internal"] },
  { id: "repository", resourceType: "git_repository", displayName: "Private repository", selector: { kind: "namespace", value: "private" }, enabled: false, allowedExecutionContexts: ["external"] }
];
function render(purpose: "include" | "exclude", selected: string[] = [], entries = resources, savedSelection: string[] = []) {
  return renderToStaticMarkup(createElement(ResourceTypesProvider, { value: types }, createElement(ResourceChoices, { resources: entries, selected, purpose, savedSelection, onChange: () => {} })));
}

describe("resource group exclusion choices", () => {
  test("hides opted-out resources only from exclusions and preserves supported disabled/context-ineligible choices", () => {
    const included = render("include");
    expect(included).toContain("Inclusion-only project");
    expect(included).toContain("Private repository");
    const excluded = render("exclude");
    expect(excluded).not.toContain("Inclusion-only project");
    expect(excluded).toContain("Private repository");
    expect(excluded).toContain("Exclusion applies regardless of enabled state or execution context");
    expect(excluded).toContain("Other resources can still be included.");
    expect(excluded).not.toContain('disabled=""');
  });

  test("keeps invalid selected exclusions visible, checked, explained and removable", () => {
    const html = render("exclude", ["project"]);
    expect(html).toContain("Inclusion-only project");
    expect(html).toContain("The loaded resource type does not support new exclusions. Remove this added exclusion or refresh resource types.");
    expect(html).toContain('checked=""');
    expect(html).not.toContain('disabled=""');
  });

  test("unknown type metadata cannot enable exclusions and unknown selections remain removable", () => {
    expect(supportsResourceExclusions(types, "unknown")).toBe(false);
    expect(resourceExclusionIssue(types, "unknown")).toContain("metadata is unavailable");
    expect(resourceExclusionIssue(types, "git_repository")).toBeNull();
    const entries = [{ ...resources[0]!, resourceType: "unknown" }];
    expect(render("exclude", [], entries)).not.toContain("Inclusion-only project");
    const html = render("exclude", ["project", "missing"], entries);
    expect(html).toContain("metadata is unavailable");
    expect(html).toContain("Not in the current catalog");
    expect(html).not.toContain("Remove");
    expect(html).not.toContain('disabled=""');
  });

  test("cached opt-outs cannot invalidate server-stored exclusions", () => {
    const html = render("exclude", ["project"], resources, ["project"]);
    expect(html).toContain("Saved exclusion. The broker validates this membership when saving.");
    expect(html).toContain("Inclusion-only project");
    expect(html).toContain('checked=""');
    expect(html).not.toContain("Remove");
    expect(html).not.toContain('disabled=""');
  });

  test("missing metadata and missing resource details never suggest removing stored exclusions", () => {
    const entries = [{ ...resources[0]!, resourceType: "unknown" }];
    const html = render("exclude", ["project", "missing"], entries, ["project", "missing"]);
    expect(html).toContain("Saved exclusion. The broker validates this membership when saving.");
    expect(html).toContain("Saved exclusion. Resource details are unavailable");
    expect(html).not.toContain("Remove");
    expect(html).not.toContain('disabled=""');
  });

});
