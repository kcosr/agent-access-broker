import { describe, expect, test } from "vitest";
import { readUrlState, urlParam, urlStateSearch, writeUrlState } from "../src/lib/url-state";

const schema = {
  q: urlParam.text(),
  status: urlParam.oneOf(["all", "active", "disabled"] as const, "all"),
  mine: urlParam.flag(),
  service: urlParam.list(),
  item: urlParam.text()
};

describe("URL state", () => {
  test("reads typed values with defaults for absent or invalid parameters", () => {
    expect(readUrlState(schema, "")).toEqual({ q: "", status: "all", mine: false, service: [], item: "" });
    expect(readUrlState(schema, "?q=jira%20issue&status=disabled&mine=1&service=jira&service=gitlab&service=jira&item=g-1")).toEqual({
      q: "jira issue",
      status: "disabled",
      mine: true,
      service: ["jira", "gitlab"],
      item: "g-1"
    });
    expect(readUrlState(schema, "?status=bogus&mine=0").status).toBe("all");
    expect(readUrlState(schema, "?status=bogus&mine=0").mine).toBe(false);
  });

  test("writes a patch, omits defaults, and keeps parameters outside the patch", () => {
    const next = writeUrlState(schema, "?q=old&keep=1&service=a", { q: "new", status: "active", service: ["b", "c"] });
    expect(next.getAll("service")).toEqual(["b", "c"]);
    expect(next.get("keep")).toBe("1");
    expect(next.get("q")).toBe("new");
    expect(next.get("status")).toBe("active");
    expect(urlStateSearch(schema, next, { q: "", status: "all", service: [] })).toBe("?keep=1");
    expect(urlStateSearch(schema, "", { mine: false, item: "" })).toBe("");
  });

  test("ignores patch keys outside the schema", () => {
    const patch = { q: "x", other: "y" } as Parameters<typeof writeUrlState<typeof schema>>[2];
    expect(urlStateSearch(schema, "", patch)).toBe("?q=x");
  });

  test("round-trips values through the URL", () => {
    const values = { q: "a&b=c", status: "disabled" as const, mine: true, service: ["x y", "z"], item: "user:alice" };
    expect(readUrlState(schema, urlStateSearch(schema, "", values))).toEqual(values);
  });
});

describe("table sort state", () => {
  const schema = { sort: urlParam.sort(["grant", "updated"]), grant: urlParam.text() };

  test("reads key:dir and ignores unknown keys or directions", () => {
    expect(readUrlState(schema, "?sort=grant:asc").sort).toEqual({ key: "grant", dir: "asc" });
    expect(readUrlState(schema, "?sort=updated%3Adesc").sort).toEqual({ key: "updated", dir: "desc" });
    expect(readUrlState(schema, "?sort=secret:asc").sort).toBeNull();
    expect(readUrlState(schema, "?sort=grant:sideways").sort).toBeNull();
    expect(readUrlState(schema, "").sort).toBeNull();
  });

  test("writes the sort and removes it when unsorted, keeping other parameters", () => {
    expect(urlStateSearch(schema, "?grant=g1", { sort: { key: "updated", dir: "desc" } })).toBe("?grant=g1&sort=updated%3Adesc");
    expect(urlStateSearch(schema, "?grant=g1&sort=grant%3Aasc", { sort: null })).toBe("?grant=g1");
  });

  test("clears other open-item parameters in the same update", () => {
    expect(urlStateSearch(schema, "?mtoken=m1&q=x", { grant: "g1" }, ["mtoken"])).toBe("?q=x&grant=g1");
  });
});
