import type { ImportBinding, ImportDelivery, ImportOAuthRegistration } from "../import-types";

export type ImportPersonalAuth = "static_token" | "oauth" | "retained";
export type ImportCredentialDraft = { shared: boolean; personal: boolean; personalAuth: ImportPersonalAuth; registrationId: string; profile: string; delivery: ImportDelivery };
export function matchingImportRegistrations(registrations: ImportOAuthRegistration[], endpoint: string): ImportOAuthRegistration[] {
  return registrations.filter((registration) => registration.adapterId === "mcp_oauth" && registration.resource === endpoint.trim());
}
export function importCredentialBindings(existing: ImportBinding[], draft: ImportCredentialDraft): ImportBinding[] {
  const shared = existing.find((binding) => binding.ownerMode === "service");
  const personal = existing.find((binding) => binding.ownerMode === "per_user");
  const bindings: ImportBinding[] = [];
  if (shared || draft.shared) bindings.push(shared ? { ...shared, delivery: draft.delivery } : { ownerMode: "service", mechanism: "static_token", delivery: draft.delivery, status: "configured" });
  if (personal || draft.personal) {
    if (draft.personalAuth === "retained" && personal) bindings.push(personal);
    else if (draft.personalAuth === "oauth") bindings.push({ ownerMode: "per_user", mechanism: "oauth", delivery: { kind: "bearer" }, status: "configured", adapterId: "mcp_oauth", registrationId: draft.registrationId, profile: draft.profile });
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
export function importOAuthError(registrations: ImportOAuthRegistration[], endpoint: string, registrationId: string, profile: string, raw: boolean, transport: boolean): string | null {
  if (raw || transport) return "OAuth requires Bearer delivery without a separate transport bearer token.";
  const approved = matchingImportRegistrations(registrations, endpoint);
  if (!approved.length) return "The operator has not approved an OAuth registration for this endpoint.";
  const registration = approved.find((entry) => entry.id === registrationId);
  if (!registration) return "Select an approved OAuth registration for this endpoint.";
  if (!registration.permissionProfiles.some((entry) => entry.id === profile)) return "Select an approved permission profile.";
  return null;
}
