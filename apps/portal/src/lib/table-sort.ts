// Sorting for DataTable views. The table is controlled: views sort their own
// rows from the URL's sort state with these helpers.
import type { SortState } from "../workbench";

export type SortValue = string | number | null | undefined;

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

/** Orders two values; missing values (null, undefined, "") come last in either direction. */
function compareValues(a: SortValue, b: SortValue, dir: 1 | -1) {
  const aMissing = a === null || a === undefined || a === "";
  const bMissing = b === null || b === undefined || b === "";
  if (aMissing || bMissing) return aMissing === bMissing ? 0 : aMissing ? 1 : -1;
  if (typeof a === "number" && typeof b === "number") return dir * (a - b);
  return dir * collator.compare(String(a), String(b));
}

/**
 * Rows sorted by `sort` (stable), falling back to `fallback` for ties and when
 * unsorted. `value` returns the sortable value of a row for a column key.
 */
export function sortRows<T>(
  rows: readonly T[],
  sort: SortState | null,
  value: (row: T, key: string) => SortValue,
  fallback: (a: T, b: T) => number
): T[] {
  const dir = sort?.dir === "desc" ? -1 : 1;
  return [...rows].sort((a, b) => (sort ? compareValues(value(a, sort.key), value(b, sort.key), dir) : 0) || fallback(a, b));
}

/** Rows regrouped so each group is consecutive, in `groupOrder`, keeping the order within groups. */
export function groupRows<T>(rows: readonly T[], group: (row: T) => string, groupOrder: (a: string, b: string) => number): T[] {
  const indexed = rows.map((row, index) => ({ row, index, key: group(row) }));
  indexed.sort((a, b) => groupOrder(a.key, b.key) || a.index - b.index);
  return indexed.map((entry) => entry.row);
}
