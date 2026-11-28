import { issuanceSettingEqual } from "./token-issuance-policy";
import { accessKeyTypesSettingEqual } from "./access-keys";
import type { GroupAccessKeyTypes, PrincipalAccessKeyTypes, PrincipalAgentTokenIssuanceSetting, PrincipalRole } from "../types";

export type AccessFields = { agentTokenIssuance: PrincipalAgentTokenIssuanceSetting; role?: PrincipalRole; selfServiceEnabled?: boolean; accessKeyTypes?: PrincipalAccessKeyTypes | GroupAccessKeyTypes };
export type AccessDraft<T extends AccessFields> = { base: T; value: T; conflicts: (keyof T)[] };
const equal = <T extends AccessFields>(key: keyof T, a: T, b: T): boolean => key === "agentTokenIssuance"
  ? issuanceSettingEqual(a.agentTokenIssuance, b.agentTokenIssuance)
  : key === "accessKeyTypes" ? accessKeyTypesSettingEqual(a.accessKeyTypes, b.accessKeyTypes) : a[key] === b[key];
export const accessDraft = <T extends AccessFields>(value: T): AccessDraft<T> => ({ base: value, value, conflicts: [] });

/** Each field owns its base; unrelated saved changes always flow into the draft. */
export function refreshAccessDraft<T extends AccessFields>(draft: AccessDraft<T>, latest: T): AccessDraft<T> {
  const base = { ...draft.base };
  const value = { ...draft.value };
  const conflicts: (keyof T)[] = [];
  // A field the form no longer shows (its source is gone or cannot be read)
  // leaves the draft, edited or not: it is never sent unseen.
  for (const key of Object.keys(base) as (keyof T)[]) {
    if (!Object.hasOwn(latest, key)) {
      delete base[key];
      delete value[key];
    }
  }
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
