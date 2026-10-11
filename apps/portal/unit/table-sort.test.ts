import { describe, expect, it } from "vitest";
import { groupRows, sortRows } from "../src/lib/table-sort";

type Row = { id: string; name: string; used?: string | null; service: string };

const rows: Row[] = [
  { id: "a", name: "token 10", used: "2026-09-02T00:00:00Z", service: "jira" },
  { id: "b", name: "Token 2", used: null, service: "confluence" },
  { id: "c", name: "token 1", used: "2026-09-03T00:00:00Z", service: "jira" },
  { id: "d", name: "alpha", used: "2026-09-01T00:00:00Z", service: "confluence" }
];
const value = (row: Row, key: string) => (key === "name" ? row.name : row.used);
const byId = (a: Row, b: Row) => a.id.localeCompare(b.id);

describe("sortRows", () => {
  it("keeps the fallback order when unsorted", () => {
    expect(sortRows(rows, null, value, byId).map((row) => row.id)).toEqual(["a", "b", "c", "d"]);
  });

  it("sorts text case-insensitively with numeric runs", () => {
    expect(sortRows(rows, { key: "name", dir: "asc" }, value, byId).map((row) => row.name)).toEqual(["alpha", "token 1", "Token 2", "token 10"]);
    expect(sortRows(rows, { key: "name", dir: "desc" }, value, byId).map((row) => row.name)).toEqual(["token 10", "Token 2", "token 1", "alpha"]);
  });

  it("puts missing values last in either direction", () => {
    expect(sortRows(rows, { key: "used", dir: "desc" }, value, byId).map((row) => row.id)).toEqual(["c", "a", "d", "b"]);
    expect(sortRows(rows, { key: "used", dir: "asc" }, value, byId).map((row) => row.id)).toEqual(["d", "a", "c", "b"]);
  });

  it("does not modify the input", () => {
    const copy = [...rows];
    sortRows(rows, { key: "name", dir: "asc" }, value, byId);
    expect(rows).toEqual(copy);
  });
});

describe("groupRows", () => {
  it("makes each group consecutive in group order, keeping the order within groups", () => {
    const sorted = sortRows(rows, { key: "name", dir: "asc" }, value, byId);
    expect(groupRows(sorted, (row) => row.service, (a, b) => a.localeCompare(b)).map((row) => `${row.service}:${row.name}`)).toEqual([
      "confluence:alpha",
      "confluence:Token 2",
      "jira:token 1",
      "jira:token 10"
    ]);
  });
});
