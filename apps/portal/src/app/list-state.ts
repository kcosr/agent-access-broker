// Shared plumbing for URL-driven lists and tables with an open item in a drawer.
import { useCallback } from "react";
import { useLocation } from "react-router";
import { findRowTarget, useListCursor } from "../workbench";
import { urlStateSearch, useUrlState, type UrlStateSchema, type UrlStateValues } from "../lib/url-state";

const NONE: readonly string[] = [];

/**
 * URL state for a table view plus its open item (`itemKey`): row links that
 * toggle the drawer, open/close, and focus return. DataTable owns the j/k
 * cursor (pass `activeId`, `rowHref`, and `onRowFollow` from here).
 * `exclusive` names other open-item parameters on the same page (another
 * list's drawer): opening an item here clears them, so one drawer shows at a
 * time.
 */
export function useTableUrlState<S extends UrlStateSchema>(schema: S, itemKey: keyof S & string, exclusive: readonly string[] = NONE) {
  const [state, setState] = useUrlState(schema);
  const location = useLocation();
  const openId = (state[itemKey] as string) || null;
  const open = useCallback(
    (id: string | null, history: "push" | "replace" = "push") =>
      setState({ [itemKey]: id ?? "" } as Partial<UrlStateValues<S>>, { history, clear: id ? exclusive : NONE }),
    [itemKey, setState, exclusive]
  );
  /** Row link: opens the item, or closes it when it is already open. */
  const itemHref = useCallback(
    (id: string) =>
      `${location.pathname}${urlStateSearch(schema, location.search, { [itemKey]: openId === id ? "" : id } as Partial<UrlStateValues<S>>, openId === id ? NONE : exclusive)}`,
    [location.pathname, location.search, schema, itemKey, openId, exclusive]
  );
  const returnFocus = useCallback(() => (openId ? findRowTarget(openId) : null), [openId]);
  const close = useCallback(() => open(null), [open]);
  return { state, setState, openId, open, close, itemHref, returnFocus };
}

/**
 * The same URL state for a ListRow list, plus the j/k cursor the open drawer
 * follows. `rows` derives the visible row ids (in order) and the key that
 * resets the cursor (usually the filters) from the current state.
 */
export function useListUrlState<S extends UrlStateSchema>(
  schema: S,
  itemKey: keyof S & string,
  rows: (state: UrlStateValues<S>) => { ids: readonly string[]; resetKey: unknown },
  exclusive: readonly string[] = NONE
) {
  const table = useTableUrlState(schema, itemKey, exclusive);
  const { ids, resetKey } = rows(table.state);
  const cursor = useListCursor({
    ids,
    activeId: table.openId,
    onOpen: (id) => table.open(id),
    onFollow: (id) => table.open(id, "replace"),
    resetKey
  });
  return { ...table, cursor };
}
