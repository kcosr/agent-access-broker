import type { PrincipalRole, Session } from "../types";
import type { AccountSubject } from "../app/active-route";

export const ROLE_LABELS: Record<PrincipalRole, string> = {
  user: "User",
  auditor: "Auditor",
  service_policy_manager: "Service policy manager",
  admin: "Administrator"
};

export function canViewAdmin(session: Session) {
  return session.authenticated && (session.role === "admin" || session.role === "auditor");
}

export function canWriteAdmin(session: Session) {
  return session.authenticated && session.role === "admin";
}

export function canUseSelfService(session: Session) {
  return session.authenticated && session.selfServiceEnabled === true;
}

export function canViewPolicies(session: Session) {
  return canViewAdmin(session) || (session.authenticated && session.role === "service_policy_manager");
}

export function hasPolicyScope(session: Session) {
  return canViewAdmin(session) || (session.authenticated && session.role === "service_policy_manager" && Boolean(session.policyManagementServices?.length));
}

export function canWritePolicies(session: Session, service?: string) {
  if (canWriteAdmin(session)) return true;
  if (!session.authenticated || session.role !== "service_policy_manager") return false;
  return Boolean(service ? session.policyManagementServices?.includes(service) : session.policyManagementServices?.length);
}

export function canWriteSubject(session: Session, subject: AccountSubject) {
  return subject.administered ? canWriteAdmin(session) : canUseSelfService(session);
}

export function capabilityKey(session: Session) {
  return JSON.stringify([session.authenticated, session.principal, session.role, session.selfServiceEnabled, session.policyManagementServices ?? []]);
}
