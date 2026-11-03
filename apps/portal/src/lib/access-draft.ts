import { issuanceSettingEqual } from "./token-issuance-policy";
import type { PrincipalAgentTokenIssuanceSetting, PrincipalRole } from "../types";

export type AccessFields = { agentTokenIssuance: PrincipalAgentTokenIssuanceSetting; role?: PrincipalRole; selfServiceEnabled?: boolean };
export type AccessDraft<T extends AccessFields> = { base: T; value: T; conflicts: (keyof T)[] };
const equal = <T extends AccessFields>(key: keyof T, a: T, b: T): boolean => key === "agentTokenIssuance"
  ? issuanceSettingEqual(a.agentTokenIssuance, b.agentTokenIssuance) : a[key] === b[key];
export const accessDraft = <T extends AccessFields>(value: T): AccessDraft<T> => ({ base: value, value, conflicts: [] });

/** Each field owns its base; unrelated saved changes always flow into the draft. */
export function refreshAccessDraft<T extends AccessFields>(draft: AccessDraft<T>, latest: T): AccessDraft<T> {
  const base = { ...draft.base };
  const value = { ...draft.value };
  const conflicts: (keyof T)[] = [];
  for (const key of Object.keys(latest) as (keyof T)[]) {
    if (equal(key, value, base) || equal(key, value, latest)) {
      base[key] = latest[key];
      value[key] = latest[key];
    } else if (!equal(key, base, latest)) conflicts.push(key);
  }
  return { base, value, conflicts };
}

/** Acknowledge new bases, retaining only still-edited fields. Never submits. */
export function keepAccessDraft<T extends AccessFields>(draft: AccessDraft<T>, latest: T): AccessDraft<T> {
  return { base: latest, value: refreshAccessDraft(draft, latest).value, conflicts: [] };
}

export function accessDraftPatch<T extends AccessFields>(draft: AccessDraft<T>): Partial<T> {
  const patch: Partial<T> = {};
  for (const key of Object.keys(draft.base) as (keyof T)[]) if (!equal(key, draft.value, draft.base)) patch[key] = draft.value[key];
  return patch;
}
