// The effective-access listing merges contexts and actions only when their
// clauses are identical, so every (action, context) pair keeps its exact access.
import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { mergeEffectiveAccess } from "../src/lib/access";
import { EffectiveAccessSummary } from "../src/components/effective-access";
import { indexResourceTypes, ResourceTypesProvider } from "../src/lib/resource-types";
import type { EffectiveAccessClause, EffectiveAccessItem } from "../src/types";
import { RESOURCE_TYPES } from "./resource-types.fixture";

const sbc: EffectiveAccessClause[] = [{ included: [{ kind: "exact", value: "SBC" }], excluded: [] }];
const eng: EffectiveAccessClause[] = [{ included: [{ kind: "exact", value: "ENG" }], excluded: [] }];
const item = (action: string, executionContext: string, clauses: EffectiveAccessClause[], service = "jira"): EffectiveAccessItem => ({
  service,
  action,
  executionContext,
  resourceType: "jira_project",
  clauses
});

/** Every (service, action, context) pair a set of rows states, with its clauses. */
function expand(rows: ReturnType<typeof mergeEffectiveAccess>) {
  return rows
    .flatMap((row) => row.actions.flatMap((action) => row.contexts.map((context) => `${row.service}:${action}:${context}=${JSON.stringify(row.clauses)}`)))
    .sort();
}

describe("merged effective access", () => {
  it("merges an action's contexts with identical clauses", () => {
    const rows = mergeEffectiveAccess([item("attachment.add", "internal", sbc), item("attachment.add", "external", sbc)]);
    expect(rows).toEqual([{ service: "jira", actions: ["attachment.add"], contexts: ["internal", "external"], resourceType: "jira_project", clauses: sbc }]);
  });

  it("keeps contexts apart when their clauses differ", () => {
    const rows = mergeEffectiveAccess([item("issue.view", "default", sbc), item("issue.view", "internal", eng)]);
    expect(rows.map((row) => [row.actions, row.contexts])).toEqual([
      [["issue.view"], ["default"]],
      [["issue.view"], ["internal"]]
    ]);
  });

  it("merges actions only when their contexts and clauses are identical", () => {
    const items = [
      item("issue.view", "default", sbc),
      item("issue.view", "internal", sbc),
      item("issue.create", "default", sbc),
      item("issue.create", "internal", eng),
      item("search", "default", sbc),
      item("search", "internal", sbc),
      item("comment.add", "default", sbc)
    ];
    const rows = mergeEffectiveAccess(items);
    expect(rows.map((row) => [row.actions, row.contexts, row.clauses])).toEqual([
      [["issue.view", "search"], ["default", "internal"], sbc],
      [["issue.create", "comment.add"], ["default"], sbc],
      [["issue.create"], ["internal"], eng]
    ]);
    // Nothing is lost or added: the rows state exactly the input pairs.
    expect(expand(rows)).toEqual(items.map((entry) => `jira:${entry.action}:${entry.executionContext}=${JSON.stringify(entry.clauses)}`).sort());
  });

  it("treats a different resource type or exclusion as different access", () => {
    const withExclusion: EffectiveAccessClause[] = [{ included: [{ kind: "all" }], excluded: [{ kind: "exact", value: "SECRET" }] }];
    const withRequestExclusion: EffectiveAccessClause[] = [{ included: [{ kind: "all" }], excluded: [], excludedRequests: [{ included: [{ kind: "exact", value: "SECRET" }], excluded: [] }] }];
    const plain: EffectiveAccessClause[] = [{ included: [{ kind: "all" }], excluded: [] }];
    const rows = mergeEffectiveAccess([
      item("a", "default", plain),
      item("a", "internal", withExclusion),
      item("a", "external", withRequestExclusion),
      { ...item("b", "default", plain), resourceType: null }
    ]);
    expect(rows).toHaveLength(4);
  });

  it("keeps services apart and in order", () => {
    const rows = mergeEffectiveAccess([item("page.view", "default", sbc, "confluence"), item("issue.view", "default", sbc), item("search", "default", sbc, "confluence")]);
    expect(rows.map((row) => [row.service, row.actions])).toEqual([
      ["confluence", ["page.view", "search"]],
      ["jira", ["issue.view"]]
    ]);
  });

  it("renders one table row per merged row, with service headers only for several services", () => {
    const render = (access: EffectiveAccessItem[]) =>
      renderToStaticMarkup(
        createElement(
          ResourceTypesProvider,
          { value: indexResourceTypes(RESOURCE_TYPES) },
          createElement(EffectiveAccessSummary, { result: { policyGeneration: 3, access }, serviceNames: new Map([["jira", "Jira"]]) })
        )
      );
    const single = render([item("attachment.add", "internal", sbc), item("attachment.add", "external", sbc)]);
    expect(single.match(/<tr>/g)).toHaveLength(2);
    expect(single).toContain("<span>internal</span>, <span>external</span>");
    expect(single).not.toContain("rowgroup");
    const several = render([item("issue.view", "default", sbc), item("page.view", "default", sbc, "confluence")]);
    expect(several.match(/scope="rowgroup"/g)).toHaveLength(2);
    expect(several).toContain("Jira");
  });

  it("names a row that covers every granted action of its service, and lists the rest", () => {
    const render = (access: EffectiveAccessItem[], granted: string[]) =>
      renderToStaticMarkup(
        createElement(
          ResourceTypesProvider,
          { value: indexResourceTypes(RESOURCE_TYPES) },
          createElement(EffectiveAccessSummary, { result: { policyGeneration: 3, access }, grantedActions: new Map([["jira", granted]]) })
        )
      );
    const all = render([item("issue.view", "default", sbc), item("search", "default", sbc)], ["issue.view", "search"]);
    // A disclosure: the names are one keyboard-operable click away.
    expect(all).toMatch(/<details class="pt-access-all"><summary>All 2 granted actions<\/summary>.*issue\.<wbr\/>view.*search.*<\/details>/);
    // A row missing one granted action (different access in that context) lists its actions.
    const split = render([item("issue.view", "default", sbc), item("search", "default", eng)], ["issue.view", "search"]);
    expect(split).not.toContain("granted actions");
    expect(split).toContain("issue.<wbr/>view");
  });
});
