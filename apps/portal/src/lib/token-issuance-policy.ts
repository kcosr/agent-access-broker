import type { AgentTokenIssuanceMode, AgentTokenIssuancePolicy, AgentTokenOptions, GroupRecord, Session } from "../types";

export const AGENT_TOKEN_ISSUANCE_LABELS = { inherit: "Inherit from groups", disabled: "Disabled", read_only: "Read-only", write_capable: "Write-capable" } as const;
export const GROUP_TOKEN_ISSUANCE_OPTIONS = (["disabled", "read_only", "write_capable"] as const).map((value) => ({ value, label: AGENT_TOKEN_ISSUANCE_LABELS[value] }));
export const PRINCIPAL_TOKEN_ISSUANCE_OPTIONS = [{ value: "inherit", label: AGENT_TOKEN_ISSUANCE_LABELS.inherit }, ...GROUP_TOKEN_ISSUANCE_OPTIONS];

/** Missing or malformed metadata must never make creation available. */
export function isAgentTokenIssuancePolicy(value: unknown): value is AgentTokenIssuancePolicy {
  if (!value || typeof value !== "object") return false;
  const policy = value as Partial<AgentTokenIssuancePolicy>;
  return ["disabled", "read_only", "write_capable"].includes(policy.mode ?? "")
    && ["user", "groups", "default"].includes(policy.source ?? "")
    && Array.isArray(policy.groupIds) && policy.groupIds.every((id) => typeof id === "string" && id.length > 0)
    && new Set(policy.groupIds).size === policy.groupIds.length
    && (policy.source === "groups" ? policy.groupIds.length > 0 && policy.mode !== "disabled" : policy.groupIds.length === 0)
    && (policy.source !== "default" || policy.mode === "disabled");
}

export function agentTokenIssuanceDescription(policy: unknown, groups: readonly Pick<GroupRecord, "groupId" | "displayName">[] = []): string {
  if (!isAgentTokenIssuancePolicy(policy)) return "Issuance policy unavailable";
  const mode = AGENT_TOKEN_ISSUANCE_LABELS[policy.mode];
  if (policy.source === "user") return `${mode}, explicit account override`;
  if (policy.source === "groups") return `${mode}, inherited from ${policy.groupIds.map((id) => groups.find((group) => group.groupId === id)?.displayName || id).join(", ")}`;
  return `${mode}, no contributing groups`;
}

export function tokenIssuanceBlocker(session: Session, administered: boolean, options: AgentTokenOptions | null): string | null {
  const ttl = administered ? session.tokenIssuancePolicy?.administered?.agentInvoke : session.tokenIssuancePolicy?.selfAgentInvoke;
  if (!ttl?.options.length || !isAgentTokenIssuancePolicy(options?.agentTokenIssuancePolicy)
    || (!administered && !isAgentTokenIssuancePolicy(session.tokenIssuancePolicy?.selfAgentInvoke?.access))) return "Token issuance policy is unavailable.";
  if (!administered && selfTokenIssuanceMode(session, options) === "disabled") return "Agent token issuance is disabled for this account.";
  return null;
}

/** During independent refreshes, neither projection can relax the other's ceiling. */
export function selfTokenIssuanceMode(session: Session, options: AgentTokenOptions | null): AgentTokenIssuanceMode | null {
  const access = session.tokenIssuancePolicy?.selfAgentInvoke?.access;
  const owner = options?.agentTokenIssuancePolicy;
  if (!isAgentTokenIssuancePolicy(access) || !isAgentTokenIssuancePolicy(owner)) return null;
  if (access.mode === "disabled" || owner.mode === "disabled") return "disabled";
  if (access.mode === "read_only" || owner.mode === "read_only") return "read_only";
  return "write_capable";
}
