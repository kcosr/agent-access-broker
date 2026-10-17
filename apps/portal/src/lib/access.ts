import type { AgentTokenOptions, ConnectionConsumer, EffectiveAccessClause, EffectiveAccessItem } from "../types";

/**
 * Service display names from the services consuming the principal's credential
 * connections, then from its token options (both independent of the request's
 * execution context). Services missing from both keep their ID.
 */
export function serviceDisplayNames(options: AgentTokenOptions | null, connections: ReadonlyArray<{ consumers: ConnectionConsumer[] }> = []): Map<string, string> {
  const names = new Map<string, string>();
  for (const connection of connections) for (const consumer of connection.consumers) if (consumer.displayName) names.set(consumer.service, consumer.displayName);
  for (const service of options?.services ?? []) if (service.displayName) names.set(service.service, service.displayName);
  return names;
}

/** Each granted service's actions, from the token options (for "All N granted actions"). */
export function grantedServiceActions(options: AgentTokenOptions | null): Map<string, string[]> {
  return new Map((options?.services ?? []).map((service) => [service.service, service.actions.map((action) => action.action)]));
}

export type AccessActionSummary = {
  action: string;
  description: string;
  /** Explicitly classified read-only; anything else may write. */
  readOnly: boolean;
  contexts: string[];
  clauses: EffectiveAccessClause[];
};
export type AccessServiceSummary = { service: string; actions: AccessActionSummary[] };

/** Presentation-only grouping of the broker's compiled effective boundaries. */
export function buildAccessSummary(options: AgentTokenOptions, executionContext: string | null = null): AccessServiceSummary[] {
  return options.services.flatMap((service) => {
    const actions = service.actions.flatMap((action) => {
      const grouped = new Map<string, AccessActionSummary>();
      for (const context of action.executionContexts) {
        if (executionContext !== null && context !== executionContext) continue;
        if (!options.executionContexts.includes(context) || !service.executionContexts.includes(context)) continue;
        const clauses = action.effectiveAccessByExecutionContext[context] ?? [];
        if (clauses.length === 0) continue;
        const key = JSON.stringify(clauses);
        const existing = grouped.get(key);
        if (existing) existing.contexts.push(context);
        else grouped.set(key, { action: action.action, description: action.description, readOnly: action.readOnly === true, contexts: [context], clauses });
      }
      return [...grouped.values()];
    });
    return actions.length ? [{ service: service.service, actions }] : [];
  });
}

/**
 * One row of an effective-access listing: every action in `actions` has
 * exactly these clauses in every context in `contexts`.
 */
export type EffectiveAccessRow = {
  service: string;
  actions: string[];
  contexts: string[];
  clauses: EffectiveAccessClause[];
};

/**
 * Merges the broker's per-(action, context) effective access into compact
 * rows without losing or blurring anything: an action's contexts merge only
 * when their complete clauses are identical, and actions merge only
 * when their merged contexts and clauses are identical, so each row states
 * the exact access of every action × context pair it covers, and each pair
 * appears in exactly one row. Services, actions, and contexts keep the
 * broker's order.
 */
export function mergeEffectiveAccess(items: EffectiveAccessItem[]): EffectiveAccessRow[] {
  const signature = (item: Pick<EffectiveAccessItem, "clauses">) => JSON.stringify(item.clauses);
  // service -> action -> clause signature -> contexts (insertion-ordered maps)
  const services = new Map<string, Map<string, Map<string, { contexts: string[]; item: EffectiveAccessItem }>>>();
  for (const item of items) {
    const actions = services.get(item.service) ?? new Map<string, Map<string, { contexts: string[]; item: EffectiveAccessItem }>>();
    services.set(item.service, actions);
    const bySignature = actions.get(item.action) ?? new Map<string, { contexts: string[]; item: EffectiveAccessItem }>();
    actions.set(item.action, bySignature);
    const key = signature(item);
    const entry = bySignature.get(key);
    if (entry) {
      if (!entry.contexts.includes(item.executionContext)) entry.contexts.push(item.executionContext);
    } else bySignature.set(key, { contexts: [item.executionContext], item });
  }
  const rows: EffectiveAccessRow[] = [];
  for (const [service, actions] of services) {
    const merged = new Map<string, EffectiveAccessRow>();
    for (const [action, bySignature] of actions) {
      for (const [key, { contexts, item }] of bySignature) {
        const rowKey = JSON.stringify([contexts, key]);
        const row = merged.get(rowKey);
        if (row) row.actions.push(action);
        else merged.set(rowKey, { service, actions: [action], contexts, clauses: item.clauses });
      }
    }
    rows.push(...merged.values());
  }
  return rows;
}
