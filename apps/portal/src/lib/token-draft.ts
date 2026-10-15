import type { AgentTokenIssueBody, AgentTokenOptions, ResourceSelection, TokenEffectiveAccessBody, TokenTtlPolicy } from "../types";
import type { ClassifiedAction } from "./grant-actions";
import { agentTokenSelectedActions, buildAgentTokenServiceRestrictions } from "./helpers";

/** Owner-scoped editor state. Live grant options and the owner are kept separately. */
export type AgentTokenDraft = {
  name: string;
  lifetime: string;
  accessMode: "policy" | "restricted";
  selectedExecutionContexts: string[];
  selectedServices: string[];
  selectedActions: Record<string, string[]>;
  resourceSelections: Record<string, ResourceSelection | undefined>;
};

export function createAgentTokenDraft(options: AgentTokenOptions, ttlPolicy: TokenTtlPolicy, services: string[] = []): AgentTokenDraft {
  const selectedServices = [...new Set(services)].filter((service) => options.services.some((option) => option.service === service));
  return {
    name: "",
    lifetime: ttlPolicy.defaultTtl ?? ttlPolicy.options[0] ?? "",
    // A stale service link must still require an explicit boundary choice.
    accessMode: services.length ? "restricted" : "policy",
    selectedExecutionContexts: [...options.executionContexts],
    selectedServices,
    selectedActions: Object.fromEntries(selectedServices.map((service) => [
      service,
      options.services.find((option) => option.service === service)!.actions.map((action) => action.action),
    ])),
    resourceSelections: {},
  };
}

/** The editor section an issue belongs to; `service:<id>` is one selected service. */
export type AgentTokenDraftField = "name" | "lifetime" | "contexts" | "services" | `service:${string}`;
export type AgentTokenDraftIssue = { field: AgentTokenDraftField; message: string };
type InvalidDraft = { valid: false; issues: AgentTokenDraftIssue[] };
export type AgentTokenBoundaryResult = { valid: true; boundary: TokenEffectiveAccessBody } | InvalidDraft;
export type AgentTokenIssuanceResult = { valid: true; body: AgentTokenIssueBody } | InvalidDraft;

/** Structural validation is shared by preview and issue; empty resource restrictions are valid. */
export function buildAgentTokenBoundary(draft: AgentTokenDraft, options: AgentTokenOptions): AgentTokenBoundaryResult {
  const issues: AgentTokenDraftIssue[] = [];
  if (!draft.selectedExecutionContexts.length) issues.push({ field: "contexts", message: "Select at least one execution context." });
  if (draft.accessMode === "restricted") {
    if (!draft.selectedServices.length) issues.push({ field: "services", message: "Select at least one service." });
    for (const service of draft.selectedServices) {
      if (agentTokenSelectedActions(draft.selectedActions, service).length) continue;
      const name = options.services.find((option) => option.service === service)?.displayName ?? service;
      issues.push({ field: `service:${service}`, message: `Select at least one action for ${name}.` });
    }
  }
  if (issues.length) return { valid: false, issues };
  return {
    valid: true,
    boundary: {
      allowedExecutionContexts: [...draft.selectedExecutionContexts],
      ...(draft.accessMode === "restricted" ? {
        allowedServices: [...draft.selectedServices],
        serviceRestrictions: buildAgentTokenServiceRestrictions(draft.selectedServices, draft.selectedActions, draft.resourceSelections, options),
      } : {}),
    },
  };
}

/** Issuance adds form requirements without making the preview depend on name or lifetime. */
export function buildAgentTokenIssuance(draft: AgentTokenDraft, options: AgentTokenOptions, ttlPolicy: TokenTtlPolicy): AgentTokenIssuanceResult {
  const boundary = buildAgentTokenBoundary(draft, options);
  const issues: AgentTokenDraftIssue[] = [];
  if (!draft.name.trim()) issues.push({ field: "name", message: "Enter a token name." });
  if (!draft.lifetime || !ttlPolicy.options.includes(draft.lifetime)) issues.push({ field: "lifetime", message: "Choose an available token lifetime." });
  if (!boundary.valid) issues.push(...boundary.issues);
  if (!boundary.valid || issues.length) return { valid: false, issues };
  return {
    valid: true,
    body: {
      ...boundary.boundary,
      name: draft.name.trim(),
      ...(draft.lifetime === "never" ? { never: true } : { ttl: draft.lifetime }),
    },
  };
}

/** Keep selected unavailable actions removable, with their reviewed effects when still known. */
export function tokenActionChoices(options: AgentTokenOptions, service: string, contexts: string[], selected: string[]): ClassifiedAction[] {
  const actions = options.services.find((option) => option.service === service)?.actions ?? [];
  const known = new Set(actions.map((action) => action.action));
  const choices: ClassifiedAction[] = actions.flatMap((action) => {
    const available = action.executionContexts.some((context) => contexts.includes(context));
    if (!available && !selected.includes(action.action)) return [];
    return [{
      action: action.action,
      description: action.description,
      readOnly: action.readOnly,
      available,
      ...(available ? {} : { unavailableReason: "Not available in the selected execution contexts" }),
    }];
  });
  for (const action of new Set(selected)) {
    if (!known.has(action)) choices.push({ action, available: false, unavailableReason: "Not currently granted" });
  }
  return choices;
}

const LIFETIME_UNITS: Record<string, string> = { s: "second", m: "minute", h: "hour", d: "day" };

/** "8h" reads "8 hours"; other configured spellings are shown as written. */
export function lifetimeLabel(lifetime: string) {
  if (lifetime === "never") return "Never expires";
  const match = /^(\d+)([smhd])$/.exec(lifetime);
  if (!match) return lifetime;
  const count = Number(match[1]);
  return `${count} ${LIFETIME_UNITS[match[2]]}${count === 1 ? "" : "s"}`;
}
