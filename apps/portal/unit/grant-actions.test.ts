import { describe, expect, test } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { actionSelectionCounts, grantActionGroups, selectMatchingActions } from "../src/lib/grant-actions";
import { GrantActionSelector, WriteCapability } from "../src/components/grant-actions";

const actions = [
  { action: "issue.view", description: "Read one issue", readOnly: true },
  { action: "issue.search", description: "Find issues", readOnly: true },
  { action: "issue.update", description: "Update issue", readOnly: false },
  { action: "workflow.trigger", description: "Run a workflow", readOnly: false },
  { action: "unreviewed.read", description: "Unclassified tool" },
];

describe("grant action classification and selection", () => {
  test("only explicit read-only metadata qualifies, even when names suggest a read", () => {
    expect(actionSelectionCounts(actions, ["issue.view", "issue.update", "unreviewed.read", "removed.action"])).toEqual({ readOnly: 1, writeCapable: 3 });
    expect(actionSelectionCounts([], ["issue.view"])).toEqual({ readOnly: 0, writeCapable: 1 });
    expect(actionSelectionCounts(actions, ["issue.view", "issue.view"])).toEqual({ readOnly: 1, writeCapable: 0 });
  });

  test("search preserves group counts and classifies unavailable selected actions conservatively", () => {
    const selected = ["issue.view", "workflow.trigger", "removed.action"];
    const groups = grantActionGroups(actions, selected, "ISSUE");
    expect(groups.map(({ selected, total }) => ({ selected, total }))).toEqual([{ selected: 1, total: 2 }, { selected: 2, total: 4 }]);
    expect(groups[0].matching.map(({ action }) => action)).toEqual(["issue.view", "issue.search"]);
    expect(groups[1].matching.map(({ action }) => action)).toEqual(["issue.update"]);
    expect(grantActionGroups(actions, selected, "removed")[1].matching.map(({ action }) => action)).toEqual(["removed.action"]);
    expect(grantActionGroups(actions, selected, "find")[0].matching.map(({ action }) => action)).toEqual(["issue.search"]);
    expect(selected).toEqual(["issue.view", "workflow.trigger", "removed.action"]);
  });

  test("All and None preserve hidden and opposite-column selections and only save explicit identities", () => {
    const selected = ["issue.view", "workflow.trigger"];
    const added = selectMatchingActions(selected, ["issue.view", "issue.search"], true);
    expect(added).toEqual(["issue.view", "workflow.trigger", "issue.search"]);
    expect(selectMatchingActions(added, ["issue.view"], false)).toEqual(["workflow.trigger", "issue.search"]);
    expect(selectMatchingActions(selected, [], false)).toEqual(selected);
    expect(selectMatchingActions(selected, [], true)).toEqual(selected);
    expect(selected).toEqual(["issue.view", "workflow.trigger"]);
    const future = [...actions, { action: "issue.future", readOnly: true }];
    expect(grantActionGroups(future, added, "")[0].selected).toBe(2);
  });

  test("renders two accessible columns and a noninteractive write-capability badge", () => {
    const selector = renderToStaticMarkup(createElement(GrantActionSelector, { available: actions, selected: ["issue.view"], disabled: false, onChange: () => undefined }));
    expect(selector).toContain(">Read-only</legend>");
    expect(selector).toContain(">Write-capable</legend>");
    expect(selector.match(/>All<\/button>/g)).toHaveLength(2);
    expect(selector.match(/>None<\/button>/g)).toHaveLength(2);
    for (const category of ["read-only", "write-capable"]) {
      expect(selector).toContain(`aria-label="Select all matching ${category} actions"`);
      expect(selector).toContain(`aria-label="Select none of the matching ${category} actions"`);
    }
    const readonly = renderToStaticMarkup(createElement(GrantActionSelector, { available: actions, selected: ["issue.view"], disabled: true, onChange: () => undefined }));
    expect(readonly).not.toContain("<button");
    const badge = (selected: string[]) => renderToStaticMarkup(createElement(WriteCapability, { available: actions, selected }));
    expect(badge(["issue.view"])).toContain(">Read-only<");
    expect(badge(["issue.view"])).not.toContain("Writes");
    expect(badge(["issue.view", "issue.update"])).toContain("Writes");
    expect(badge(["issue.view", "issue.update"])).toContain("1 read-only action, 1 write-capable action");
    expect(badge(["unreviewed.read"])).toContain("Writes");
    expect(badge(["unreviewed.read"])).not.toContain('type="checkbox"');
  });
});

test("unavailable actions remain removable but cannot be newly selected", () => {
  const available = [{ action: "retained", readOnly: true, available: false }, { action: "disabled", readOnly: true, available: false }];
  const html = renderToStaticMarkup(createElement(GrantActionSelector, { available, selected: ["retained"], disabled: false, onChange: () => undefined }));
  expect(html.match(/<input[^>]*aria-label="retained"[^>]*>/)?.[0]).not.toContain('disabled=""');
  expect(html.match(/<input[^>]*aria-label="disabled"[^>]*>/)?.[0]).toContain('disabled=""');
  expect(html.match(/<button[^>]*aria-label="Select all matching read-only actions"[^>]*>/)?.[0]).toContain('disabled=""');
  expect(html.match(/<button[^>]*aria-label="Select none of the matching read-only actions"[^>]*>/)?.[0]).not.toContain('disabled=""');
});
