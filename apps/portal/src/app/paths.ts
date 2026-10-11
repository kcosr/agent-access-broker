// Portal URLs. Route patterns live here so pure helpers (return-path
// sanitizing) and the router agree on what a portal page is.
import { matchPath } from "react-router";

export const ROUTE = {
  root: "/ui",
  login: "/ui/login",
  access: "/ui/access",
  tokens: "/ui/tokens",
  credentials: "/ui/credentials",
  activity: "/ui/activity",
  account: "/ui/account",
  policies: "/ui/admin/policies",
  grantNew: "/ui/admin/policies/new",
  grantEdit: "/ui/admin/policies/:grantRef/edit",
  principals: "/ui/admin/principals",
  principal: "/ui/admin/principals/:principalId/:tab?",
  group: "/ui/admin/groups/:groupId/:tab?",
  catalog: "/ui/admin/catalog",
  catalogService: "/ui/admin/catalog/services/:service/:tab?",
  resources: "/ui/admin/catalog/resources",
  resourceGroups: "/ui/admin/catalog/resource-groups",
  audit: "/ui/admin/audit",
  system: "/ui/admin/system"
} as const;

export const ACCOUNT_PATH = ROUTE.account;

const PATTERNS = Object.values(ROUTE);

/** Whether a pathname is a portal page (not an unknown or foreign path). */
export function isPortalPath(pathname: string) {
  return PATTERNS.some((pattern) => matchPath({ path: pattern, end: true }, pathname) !== null);
}

/** A same-origin portal path for sign-in redirects; anything else becomes `/ui`. */
export function sanitizedUiReturnTo(pathname: string) {
  if (!pathname.startsWith("/ui") || pathname.startsWith("//") || pathname.includes("\\") || /[\u0000-\u001f\u007f]/.test(pathname)) {
    return ROUTE.root;
  }
  return isPortalPath(pathname) && pathname !== ROUTE.login ? pathname : ROUTE.root;
}

function query(params: Record<string, string | undefined | null>) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) if (value) search.set(key, value);
  const text = search.toString();
  return text ? `?${text}` : "";
}

const seg = encodeURIComponent;

export type PrincipalTab = "overview" | "access" | "grants" | "groups" | "tokens" | "credentials" | "limits" | "activity";
export type GroupTab = "overview" | "members" | "grants" | "microsoft";
export type ServiceTab = "actions" | "managers" | "limits" | "import";
export type PrincipalListKind = "users" | "service-accounts" | "groups";

export const paths = {
  access: (service?: string) => `${ROUTE.access}${query({ service })}`,
  accessAction: (service: string, action: string) => `${ROUTE.access}${query({ service, q: action })}`,
  tokens: (token?: string) => `${ROUTE.tokens}${query({ token })}`,
  credentials: (credential?: string) => `${ROUTE.credentials}${query({ credential })}`,
  account: () => ROUTE.account,
  policies: (params: Record<string, string | undefined> = {}) => `${ROUTE.policies}${query(params)}`,
  grant: (grantRef: string) => `${ROUTE.policies}${query({ grant: grantRef })}`,
  /** `returnTo` is where Save and Cancel go (a portal path); the default is the saved grant's drawer. */
  grantNew: (params: { subject?: string; from?: string; returnTo?: string } = {}) => `${ROUTE.grantNew}${query(params)}`,
  grantEdit: (grantRef: string, returnTo?: string) => `${ROUTE.policies}/${seg(grantRef)}/edit${query({ returnTo })}`,
  principals: (kind: PrincipalListKind = "users", item?: string) =>
    `${ROUTE.principals}${query({ kind: kind === "users" ? undefined : kind, item })}`,
  principal: (principalId: string, tab: PrincipalTab = "overview") =>
    `${ROUTE.principals}/${seg(principalId)}${tab === "overview" ? "" : `/${tab}`}`,
  group: (groupId: string, tab: GroupTab = "overview") => `/ui/admin/groups/${seg(groupId)}${tab === "overview" ? "" : `/${tab}`}`,
  catalog: () => ROUTE.catalog,
  /** Catalog with the Import service dialog open. */
  catalogImport: () => `${ROUTE.catalog}?import=1`,
  catalogService: (service: string, tab: ServiceTab = "actions") =>
    `${ROUTE.catalog}/services/${seg(service)}${tab === "actions" ? "" : `/${tab}`}`,
  catalogAction: (service: string, action: string) => `${ROUTE.catalog}/services/${seg(service)}${query({ action })}`,
  resources: (item?: string) => `${ROUTE.resources}${query({ item })}`,
  resourceGroups: (item?: string) => `${ROUTE.resourceGroups}${query({ item })}`,
  system: () => ROUTE.system
};

/** A `returnTo` query value when it names a portal page, else null. */
export function portalReturnTo(value: string | null) {
  if (!value || !value.startsWith("/ui") || value.startsWith("//")) return null;
  const [pathname = ""] = value.split(/[?#]/);
  return isPortalPath(pathname) ? value : null;
}
