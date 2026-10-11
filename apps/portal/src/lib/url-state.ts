// Typed URL query-parameter state for view filters, sort, and the open item.
// A schema maps each parameter to a codec; values equal to a codec's default
// are omitted from the URL, and parameters outside the schema are preserved.
// Never put secrets, tokens, or sample content into URL state.
import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router";
import type { SortState } from "../workbench";

export type UrlParamCodec<T> = {
  /** Every value of the parameter, in URL order (empty when absent). */
  parse: (values: string[]) => T;
  /** The values to write; an empty list removes the parameter (the default). */
  format: (value: T) => string[];
};

export const urlParam = {
  /** Free text; the fallback (by default empty) is omitted. */
  text(fallback = ""): UrlParamCodec<string> {
    return {
      parse: (values) => values[0] ?? fallback,
      format: (value) => (value === fallback || value === "" ? [] : [value])
    };
  },
  /** One of a fixed set; unknown values read as the fallback. */
  oneOf<T extends string>(allowed: readonly T[], fallback: T): UrlParamCodec<T> {
    return {
      parse: (values) => (allowed as readonly string[]).includes(values[0] ?? "") ? (values[0] as T) : fallback,
      format: (value) => (value === fallback ? [] : [value])
    };
  },
  /** A boolean written as `1` when set. */
  flag(): UrlParamCodec<boolean> {
    return {
      parse: (values) => values[0] === "1" || values[0] === "true",
      format: (value) => (value ? ["1"] : [])
    };
  },
  /** A set of values written as repeated parameters, in selection order. */
  list(): UrlParamCodec<string[]> {
    return {
      parse: (values) => [...new Set(values.filter(Boolean))],
      format: (value) => [...new Set(value.filter(Boolean))]
    };
  },
  /** A table sort written as `key:asc` or `key:desc`; unknown keys read as unsorted. */
  sort(keys: readonly string[]): UrlParamCodec<SortState | null> {
    return {
      parse: (values) => {
        const [key = "", dir] = (values[0] ?? "").split(":");
        return keys.includes(key) && (dir === "asc" || dir === "desc") ? { key, dir } : null;
      },
      format: (value) => (value ? [`${value.key}:${value.dir}`] : [])
    };
  }
};

export type UrlStateSchema = Record<string, UrlParamCodec<any>>;
export type UrlStateValues<S extends UrlStateSchema> = { [K in keyof S]: ReturnType<S[K]["parse"]> };
export type UrlStateUpdate<S extends UrlStateSchema> = (
  patch: Partial<UrlStateValues<S>>,
  options?: { history?: "push" | "replace"; /** Other parameters to remove in the same update. */ clear?: readonly string[] }
) => void;

function toParams(search: URLSearchParams | string) {
  return new URLSearchParams(typeof search === "string" ? search : search.toString());
}

export function readUrlState<S extends UrlStateSchema>(schema: S, search: URLSearchParams | string): UrlStateValues<S> {
  const params = toParams(search);
  const values = {} as UrlStateValues<S>;
  for (const key of Object.keys(schema) as (keyof S & string)[]) {
    values[key] = schema[key].parse(params.getAll(key));
  }
  return values;
}

/** Applies a patch to the search parameters, keeping parameters outside the patch. */
export function writeUrlState<S extends UrlStateSchema>(schema: S, search: URLSearchParams | string, patch: Partial<UrlStateValues<S>>) {
  const params = toParams(search);
  for (const key of Object.keys(patch) as (keyof S & string)[]) {
    const codec = schema[key];
    if (!codec) continue;
    params.delete(key);
    for (const value of codec.format(patch[key])) params.append(key, value);
  }
  return params;
}

/** Search-string form of `writeUrlState` (removing `clear` parameters too), with a leading `?` when non-empty. */
export function urlStateSearch<S extends UrlStateSchema>(schema: S, search: URLSearchParams | string, patch: Partial<UrlStateValues<S>>, clear: readonly string[] = []) {
  const params = writeUrlState(schema, search, patch);
  for (const key of clear) params.delete(key);
  const next = params.toString();
  return next ? `?${next}` : "";
}

/**
 * Reads and updates URL state for a schema (define the schema at module
 * level). Updates replace the history entry by default; pass
 * `{ history: "push" }` for changes the Back button should undo, such as
 * opening an item.
 */
export function useUrlState<S extends UrlStateSchema>(schema: S): [UrlStateValues<S>, UrlStateUpdate<S>] {
  const [searchParams, setSearchParams] = useSearchParams();
  const values = useMemo(() => readUrlState(schema, searchParams), [schema, searchParams]);
  const update = useCallback<UrlStateUpdate<S>>(
    (patch, options) =>
      // Synchronous, so a controlled filter (checkbox, segment) never shows its old value for a frame.
      setSearchParams(
        (current) => {
          const next = writeUrlState(schema, current, patch);
          for (const key of options?.clear ?? []) next.delete(key);
          return next;
        },
        { replace: options?.history !== "push", preventScrollReset: true, flushSync: true }
      ),
    [schema, setSearchParams]
  );
  return [values, update];
}
