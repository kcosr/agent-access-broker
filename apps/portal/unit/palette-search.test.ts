import { describe, expect, it } from "vitest";
import { filterPaletteItems, paletteHighlight, paletteMatchScore } from "../src/workbench/lib/paletteSearch";

describe("palette search", () => {
  it("finds words across explicit fields regardless of case, spacing, or order", () => {
    const item = { label: "Engineering", keywords: ["resource group", "engineering-resources", "Jira"] };
    expect(paletteMatchScore(item, "  GROUP\tengineering  jira \n")).toBeGreaterThan(0);
    expect(paletteMatchScore(item, "engineering-res")).toBeGreaterThan(0);
    expect(paletteMatchScore(item, "group engineering missing")).toBe(0);
  });

  it("searches only labels and explicit keywords, not hints or section metadata", () => {
    const item = { label: "Engineering", hint: "resource group", title: "Resources" };
    expect(paletteMatchScore(item, "resource")).toBe(0);
    expect(paletteMatchScore(item, "enginering")).toBe(0);
  });

  it("ranks exact, prefix, phrase, label words, then keyword matches with stable ties", () => {
    const items = [
      { label: "Engineering", keywords: ["resource group"] },
      { label: "Engineering groups", keywords: ["resource"] },
      { label: "Group of resource readers" },
      { label: "My resource group" },
      { label: "Resource groups" },
      { label: "Resource group" }
    ];
    const before = [...items];
    expect(filterPaletteItems(items, "resource group").map(({ label }) => label)).toEqual([
      "Resource group", "Resource groups", "My resource group", "Group of resource readers", "Engineering", "Engineering groups"
    ]);
    expect(items).toEqual(before);
    expect(filterPaletteItems(items, " \t")).toEqual(items);
  });

  it("treats punctuation literally and highlights each matching word", () => {
    const text = "Engineering · Jira [DEV] + Cloud";
    const parts = paletteHighlight(text, "jira Engineering [DEV] +");
    expect(parts.map((part) => part.text).join("")).toBe(text);
    expect(parts.filter((part) => part.match).map((part) => part.text)).toEqual(["Engineering", "Jira", "[DEV]", "+"]);
    expect(paletteHighlight("Access access", "access cess")).toEqual([
      { text: "Access", match: true }, { text: " ", match: false }, { text: "access", match: true }
    ]);
    expect(paletteHighlight("Engineering", "group")).toEqual([{ text: "Engineering", match: false }]);
  });
});
