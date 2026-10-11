// The portal's two spaces and their primary tabs, with role gating.
import { canViewAdmin, canUseSelfService } from "../lib/capabilities";
import type { Session } from "../types";
import type { IconName } from "../workbench";
import { canManagePolicies, canViewActivity, canViewAudit } from "../lib/helpers";
import { ROUTE } from "./paths";

export type SpaceKey = "admin" | "self";
export type TabKey = "access" | "tokens" | "credentials" | "activity" | "account" | "policies" | "principals" | "catalog" | "audit" | "system";

/** Route metadata: the space and tab a page belongs to, and who may open it. */
export type PortalRouteHandle = {
  space: SpaceKey;
  tab: TabKey;
  allow?: (session: Session) => boolean;
};

export type SpaceTab = { key: TabKey; label: string; href: string; icon: IconName; allow?: (session: Session) => boolean };



export const SELF_TABS: SpaceTab[] = [
  { key: "access", label: "Access", href: ROUTE.access, icon: "shield-check" },
  { key: "tokens", label: "Tokens", href: ROUTE.tokens, icon: "key" },
  { key: "credentials", label: "Credentials", href: ROUTE.credentials, icon: "lock" },
  { key: "activity", label: "Activity", href: ROUTE.activity, icon: "history", allow: canViewActivity }
];

export const ADMIN_TABS: SpaceTab[] = [
  { key: "policies", label: "Policies", href: ROUTE.policies, icon: "shield", allow: canManagePolicies },
  { key: "principals", label: "Principals", href: ROUTE.principals, icon: "users", allow: canViewAdmin },
  { key: "catalog", label: "Catalog", href: ROUTE.catalog, icon: "package", allow: canViewAdmin },
  { key: "audit", label: "Audit", href: ROUTE.audit, icon: "file-text", allow: canViewAudit }
];

export function spaceTabs(space: SpaceKey, session: Session) {
  return (space === "admin" ? ADMIN_TABS : canUseSelfService(session) ? SELF_TABS : []).filter((tab) => !tab.allow || tab.allow(session));
}

/** Administrators, auditors, and service policy managers work in Admin. */
export function hasAdminSpace(session: Session) {
  return canManagePolicies(session);
}

export function landingPath(session: Session) {
  return hasAdminSpace(session) ? ROUTE.policies : canUseSelfService(session) ? ROUTE.access : ROUTE.account;
}
