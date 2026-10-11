import { expect, test } from "vitest";
import type { PolicyCatalogResult } from "../src/types";
import { grantIsReadOnly } from "../src/features/policies/grant-effects";

const catalog = {
  services: [
    { service: "jira", actions: [{ action: "issue.view", readOnly: true }, { action: "issue.update", readOnly: false }, { action: "unreviewed.read" }] },
    { service: "other", actions: [{ action: "issue.view", readOnly: false }] }
  ]
} as PolicyCatalogResult;

test("read-only grants require a nonempty selection of explicitly reviewed read actions from their service", () => {
  expect(grantIsReadOnly({ service: "jira", actions: ["issue.view"] }, catalog)).toBe(true);
  expect(grantIsReadOnly({ service: "jira", actions: ["issue.view", "issue.view"] }, catalog)).toBe(true);
  for (const actions of [["issue.update"], ["issue.view", "issue.update"], ["unreviewed.read"], ["removed.read"], []]) {
    expect(grantIsReadOnly({ service: "jira", actions }, catalog), actions.join(",")).toBe(false);
  }
  expect(grantIsReadOnly({ service: "other", actions: ["issue.view"] }, catalog)).toBe(false);
  expect(grantIsReadOnly({ service: "missing", actions: ["issue.view"] }, catalog)).toBe(false);
  expect(grantIsReadOnly({ service: "jira", actions: ["issue.view"] }, null)).toBe(false);
});
