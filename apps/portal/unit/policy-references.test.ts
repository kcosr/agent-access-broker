import { describe, expect, it } from "vitest";
import { referenceRows } from "../src/features/principals/policy-references";
import type { GroupPolicyReference, PolicyReferenceSection } from "../src/types";

const reference = (grantRef: string, derivedViaGroups?: string[]) => ({ grantRef, derivedViaGroups }) as unknown as GroupPolicyReference;
const section = (kind: string, references: GroupPolicyReference[]) =>
  ({ kind, title: kind, subject: "user:alice", subjectRuntimeEligible: true, references }) as PolicyReferenceSection;

describe("grant reference rows", () => {
  it("lists each grant once under its first section and merges the groups it comes through", () => {
    const rows = referenceRows([
      section("direct_user", [reference("both"), reference("direct-only")]),
      section("group_derived", [reference("both", ["ops", "sre"]), reference("derived-only", ["sre"])])
    ]);
    expect(rows.map((row) => [row.key, row.section.kind, row.through])).toEqual([
      ["both", "direct_user", ["ops", "sre"]],
      ["direct-only", "direct_user", []],
      ["derived-only", "group_derived", ["sre"]]
    ]);
  });

  it("keeps a group named twice once", () => {
    const rows = referenceRows([section("group_derived", [reference("g", ["ops"])]), section("group_derived", [reference("g", ["ops", "sre"])])]);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.through).toEqual(["ops", "sre"]);
  });
});
