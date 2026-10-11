import { describe, expect, it } from "vitest";
import { preview, previewParts } from "../src/features/policies/grant-format";

describe("grant list previews", () => {
  it("splits the first items from the count of the rest", () => {
    expect(previewParts(["a", "b", "c", "d"])).toEqual({ text: "a, b", more: 2 });
    expect(previewParts(["a", "b"])).toEqual({ text: "a, b", more: 0 });
    expect(previewParts(["a", "b", "c"], 1)).toEqual({ text: "a", more: 2 });
    expect(previewParts([])).toEqual({ text: "", more: 0 });
  });

  it("joins the count for one-line text", () => {
    expect(preview(["a", "b", "c"])).toBe("a, b +1");
    expect(preview(["a"])).toBe("a");
  });
});
