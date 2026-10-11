import { urlParam, type UrlParamCodec } from "./url-state";

export type ActionEffect = "read" | "write";

const effects: readonly ActionEffect[] = ["read", "write"];
const listParam = urlParam.list();
const validEffects = (values: string[]): ActionEffect[] => effects.filter((effect) => values.includes(effect));

/** A set of action effects; unknown URL values never hide every result. */
export const actionEffectsParam: UrlParamCodec<ActionEffect[]> = {
  parse: (values) => validEffects(listParam.parse(values)),
  format: (values) => listParam.format(validEffects(values))
};

/** No selection or both selections leaves the list unrestricted. */
export function matchesActionEffects(readOnly: boolean, selected: readonly ActionEffect[]) {
  return selected.length === 0 || selected.includes(readOnly ? "read" : "write");
}
