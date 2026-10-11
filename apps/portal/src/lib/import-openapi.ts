import type { ImportActionDefinition, ImportBinding, ImportDelivery, ImportDiscovery, ImportSecurityScheme } from "../import-types";

export function openApiConnectionSettings(existing: Record<string, string> | undefined, mutable: boolean, draft: { definitionUrl: string; definitionAuthKind: string; definitionAuthHeader: string; securityScheme: string }): Record<string, string> {
  // CLI-created services may omit defaults. Presentation and limit edits must
  // preserve a frozen definition exactly.
  if (existing && (!mutable || draft.definitionUrl.trim() === existing.definitionUrl
    && draft.definitionAuthKind === (existing.definitionAuthKind ?? "none")
    && draft.definitionAuthHeader.trim() === (existing.definitionAuthHeader ?? "")
    && draft.securityScheme === (existing.securityScheme ?? ""))) return existing;
  return { definitionUrl: draft.definitionUrl.trim(), definitionAuthKind: draft.definitionAuthKind, ...(draft.definitionAuthKind === "raw_header" ? { definitionAuthHeader: draft.definitionAuthHeader.trim() } : {}), ...(draft.securityScheme ? { securityScheme: draft.securityScheme } : {}) };
}

export function openApiSecuritySchemes(manifest?: ImportDiscovery): ImportSecurityScheme[] {
  const metadata = manifest?.metadata as { securitySchemes?: unknown } | undefined;
  if (!Array.isArray(metadata?.securitySchemes)) return [];
  return metadata.securitySchemes.filter((value): value is ImportSecurityScheme => Boolean(value && typeof value === "object" && typeof value.name === "string" && (value.kind === "bearer" || value.kind === "raw_header" && typeof value.header === "string")));
}

export function openApiDelivery(scheme: ImportSecurityScheme): ImportDelivery {
  return scheme.kind === "raw_header" ? { kind: "raw_header", name: scheme.header! } : { kind: "bearer" };
}

export function openApiBindings(existing: ImportBinding[], shared: boolean, personal: boolean, delivery: ImportDelivery): ImportBinding[] {
  const modes = existing.map((binding) => binding.ownerMode);
  if (shared && !modes.includes("service")) modes.push("service");
  if (personal && !modes.includes("per_user")) modes.push("per_user");
  return modes.map((ownerMode) => ({ ownerMode, mechanism: "static_token", status: "configured", delivery }));
}

export function openApiOperation(definition: ImportActionDefinition): { method: string; path: string; security?: ImportSecurityScheme } | null {
  const annotations = definition.annotations as { openapi?: { method?: unknown; path?: unknown; security?: { scheme?: unknown; kind?: unknown; header?: unknown } } } | null;
  const plan = annotations?.openapi;
  if (typeof plan?.method !== "string" || typeof plan.path !== "string") return null;
  const security = plan.security;
  return { method: plan.method.toUpperCase(), path: plan.path, ...(security && typeof security.scheme === "string" && (security.kind === "bearer" || security.kind === "raw_header" && typeof security.header === "string") ? { security: { name: security.scheme, kind: security.kind, ...(typeof security.header === "string" ? { header: security.header } : {}) } } : {}) };
}

export function openApiSchemeLabel(scheme: ImportSecurityScheme): string {
  return `${scheme.name} · ${scheme.kind === "bearer" ? "Authorization: Bearer" : scheme.header}`;
}
