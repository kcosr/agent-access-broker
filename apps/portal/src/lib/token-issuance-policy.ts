import type { AgentTokenIssuancePolicy, AgentTokenOptions, GroupRecord, PrincipalAgentTokenIssuanceSetting, Session, TokenTtlPolicy } from "../types";

export const AGENT_TOKEN_ISSUANCE_LABELS = { inherit: "Inherit from groups", disabled: "Disabled", read_only: "Read-only", write_capable: "Write-capable" } as const;
export const GROUP_TOKEN_ISSUANCE_OPTIONS = (["disabled", "read_only", "write_capable"] as const).map((value) => ({ value, label: AGENT_TOKEN_ISSUANCE_LABELS[value] }));
export const PRINCIPAL_TOKEN_ISSUANCE_OPTIONS = [{ value: "inherit", label: AGENT_TOKEN_ISSUANCE_LABELS.inherit }, ...GROUP_TOKEN_ISSUANCE_OPTIONS];
const contextName = /^[a-z][a-z0-9_-]{0,63}$/;
const object = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const exactKeys = (value: Record<string, unknown>, keys: string[]) => Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));

/** Accept only the current wire contract. Missing rows never grant permission. */
export function isAgentTokenIssuancePolicy(value: unknown): value is AgentTokenIssuancePolicy {
  if (!object(value) || !exactKeys(value, ["source", "contexts"]) || !["user", "groups", "default"].includes(value.source as string)
    || !Array.isArray(value.contexts) || value.contexts.length > 64) return false;
  if ((value.source === "default" && value.contexts.length !== 0) || (value.source === "groups" && value.contexts.length === 0)) return false;
  const names = new Set<string>();
  return value.contexts.every((row: unknown) => {
    if (!object(row) || !exactKeys(row, ["executionContext", "mode", "groupIds"]) || typeof row.executionContext !== "string"
      || !contextName.test(row.executionContext) || names.has(row.executionContext) || !["read_only", "write_capable"].includes(row.mode as string)
      || !Array.isArray(row.groupIds) || !row.groupIds.every((id: unknown) => typeof id === "string" && id.length > 0)
      || new Set(row.groupIds).size !== row.groupIds.length || (value.source === "groups" ? !row.groupIds.length : row.groupIds.length !== 0)) return false;
    names.add(row.executionContext);
    return true;
  });
}

export function agentTokenIssuanceDescription(policy: unknown, groups: readonly Pick<GroupRecord, "groupId" | "displayName">[] = []): string {
  if (!isAgentTokenIssuancePolicy(policy)) return "Issuance policy unavailable";
  if (!policy.contexts.length) return policy.source === "user" ? "Disabled, explicit account override" : "Disabled, no contributing groups";
  return policy.contexts.map((row) => `${row.executionContext}: ${AGENT_TOKEN_ISSUANCE_LABELS[row.mode]}, ${policy.source === "user" ? "explicit account override" : `inherited from ${row.groupIds.map((id) => groups.find((group) => group.groupId === id)?.displayName || id).join(", ")}`}`).join("; ");
}

export function validTokenTtlPolicy(value: TokenTtlPolicy | undefined | null): value is TokenTtlPolicy {
  return Boolean(value && Array.isArray(value.options) && value.options.length && value.options.every((option) => typeof option === "string" && option.length)
    && (value.defaultTtl === null || value.options.includes(value.defaultTtl)) && (value.maxTtl === null || typeof value.maxTtl === "string"));
}

/** Intersect by name, not strongest mode: independent refreshes may only narrow. */
export function selfTokenIssuanceContexts(session: Session, options: AgentTokenOptions | null): Map<string, "read_only" | "write_capable"> | null {
  const access = session.tokenIssuancePolicy?.selfAgentInvoke?.access;
  const owner = options?.agentTokenIssuancePolicy;
  if (!isAgentTokenIssuancePolicy(access) || !isAgentTokenIssuancePolicy(owner)) return null;
  const ownerRows = new Map(owner.contexts.map((row) => [row.executionContext, row.mode]));
  return new Map(access.contexts.flatMap((row) => {
    const mode = ownerRows.get(row.executionContext);
    return mode ? [[row.executionContext, row.mode === "read_only" || mode === "read_only" ? "read_only" as const : "write_capable" as const]] : [];
  }));
}

export function eligibleTokenContexts(session: Session, administered: boolean, options: AgentTokenOptions | null): string[] {
  const allowed = administered ? null : selfTokenIssuanceContexts(session, options);
  return options?.executionContexts.filter((context) => administered || allowed?.has(context)) ?? [];
}

export function tokenIssuanceBlocker(session: Session, administered: boolean, options: AgentTokenOptions | null): string | null {
  const ttl = administered ? session.tokenIssuancePolicy?.administered?.agentInvoke : session.tokenIssuancePolicy?.selfAgentInvoke;
  if (!validTokenTtlPolicy(ttl) || !options || (!administered && !selfTokenIssuanceContexts(session, options))) return "Token issuance policy is unavailable.";
  if (!options.executionContexts.length) return "An active policy grant is required before a token can be issued.";
  if (!eligibleTokenContexts(session, administered, options).length) return "No granted execution contexts permit personal agent token issuance.";
  return null;
}

export function issuanceSettingEqual(a: PrincipalAgentTokenIssuanceSetting, b: PrincipalAgentTokenIssuanceSetting): boolean {
  return a.mode === b.mode && a.allowedExecutionContexts.length === b.allowedExecutionContexts.length
    && a.allowedExecutionContexts.every((context) => b.allowedExecutionContexts.includes(context));
}

export function issuanceSettingBlocker(setting: PrincipalAgentTokenIssuanceSetting, contexts: readonly string[] | undefined): string | null {
  if (setting.mode === "disabled" || setting.mode === "inherit") return setting.allowedExecutionContexts.length ? "Clear the context selections for this mode." : null;
  if (!contexts) return "Execution context registry is unavailable.";
  if (!setting.allowedExecutionContexts.length) return "Select at least one execution context.";
  if (setting.allowedExecutionContexts.some((context) => !contexts.includes(context))) return "Deselect contexts that are no longer configured.";
  return null;
}
