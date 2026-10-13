import type { ImportAuthentication, ImportBinding, ImportDelivery, ImportOAuthRegistration } from "../import-types";

export type ImportPersonalAuth = "static_token" | "oauth" | "retained";
export type ImportCredentialDraft = { shared: boolean; personal: boolean; personalAuth: ImportPersonalAuth; registrationId: string; profile: string; delivery: ImportDelivery };
/** The OAuth companion the Broker selects for an import kind, if any. */
export function importAuthenticationFor(groups: ImportAuthentication[], kind: string): ImportAuthentication | undefined {
  return groups.find((group) => group.importKind === kind);
}
/** Whether a stored personal OAuth binding is usable as-is for this kind: it names the kind's approved companion. Others are retained unchanged. */
export function retainedImportBinding(binding: ImportBinding | undefined, authentication: ImportAuthentication | undefined): boolean {
  return Boolean(binding && (binding.status === "unsupported" || (binding.mechanism === "oauth" && binding.adapterId !== authentication?.dialectId)));
}
export function matchingImportRegistrations(authentication: ImportAuthentication | undefined, endpoint: string): ImportOAuthRegistration[] {
  return authentication?.registrations.filter((registration) => registration.resource === endpoint.trim()) ?? [];
}
export function importCredentialBindings(existing: ImportBinding[], draft: ImportCredentialDraft, authentication: ImportAuthentication | undefined): ImportBinding[] {
  const shared = existing.find((binding) => binding.ownerMode === "service");
  const personal = existing.find((binding) => binding.ownerMode === "per_user");
  const bindings: ImportBinding[] = [];
  if (shared || draft.shared) bindings.push(shared ? { ...shared, delivery: draft.delivery } : { ownerMode: "service", mechanism: "static_token", delivery: draft.delivery, status: "configured" });
  if (personal || draft.personal) {
    if (draft.personalAuth === "retained" && personal) bindings.push(personal);
    // The dialect ID is copied from the kind's approved companion; without one
    // the binding names none, and importOAuthError blocks saving it.
    else if (draft.personalAuth === "oauth") bindings.push({ ownerMode: "per_user", mechanism: "oauth", delivery: { kind: "bearer" }, status: "configured", ...(authentication ? { adapterId: authentication.dialectId } : {}), registrationId: draft.registrationId, profile: draft.profile });
    else bindings.push({ ownerMode: "per_user", mechanism: "static_token", delivery: draft.delivery, status: "configured" });
  }
  // Preserve stored ordering so presentation edits do not manufacture a
  // credential change that would require another grant confirmation.
  const order = (binding: ImportBinding) => {
    const index = existing.findIndex((old) => old.ownerMode === binding.ownerMode);
    return index < 0 ? existing.length + (binding.ownerMode === "service" ? 0 : 1) : index;
  };
  return bindings.sort((left, right) => order(left) - order(right));
}
export function importOAuthError(authentication: ImportAuthentication | undefined, endpoint: string, registrationId: string, profile: string, raw: boolean, transport: boolean): string | null {
  if (raw || transport) return "OAuth requires Bearer delivery without a separate transport bearer token.";
  if (!authentication) return "This import type has no OAuth authentication in this Broker.";
  const approved = matchingImportRegistrations(authentication, endpoint);
  if (!approved.length) return "The operator has not approved an OAuth registration for this endpoint.";
  const registration = approved.find((entry) => entry.id === registrationId);
  if (!registration) return "Select an approved OAuth registration for this endpoint.";
  if (!registration.permissionProfiles.some((entry) => entry.id === profile)) return "Select an approved permission profile.";
  return null;
}
