// The portal route table. Every page renders inside the root layout's
// providers and the gate; route handles name the space and tab and gate roles.
import { createBrowserRouter, type RouteObject } from "react-router";
import { canManagePolicies, canViewActivity, canViewAudit } from "../lib/helpers";
import { AccessPage } from "../features/access/access-page";
import { AccountPage } from "../features/account/account-page";
import { ActivityPage, AuditPage } from "../features/audit/pages";
import { CatalogPage, CatalogServicePage, ResourceGroupsPage, ResourcesPage } from "../features/catalog/pages";
import { CredentialsPage } from "../features/credentials/credentials-page";
import { GrantEditorPage } from "../features/policies/grant-editor-page";
import { PoliciesPage } from "../features/policies/policies-page";
import { GroupPage } from "../features/principals/group-page";
import { PrincipalPage } from "../features/principals/principal-page";
import { PrincipalsPage } from "../features/principals/principals-page";
import { SystemPage } from "../features/system/system-page";
import { TokensPage } from "../features/tokens/tokens-page";
import { LandingRedirect, LoginRoute, NotFoundPage, PortalGate } from "./gate";
import { ROUTE } from "./paths";
import { RootLayout } from "./root";
import { canViewAdmin, canUseSelfService, canWritePolicies, hasPolicyScope } from "../lib/capabilities";
import { type PortalRouteHandle } from "./spaces";

function page(path: string, handle: PortalRouteHandle, element: RouteObject["element"]): RouteObject {
  return { path, handle, element };
}

const self = (tab: PortalRouteHandle["tab"], allow?: PortalRouteHandle["allow"]): PortalRouteHandle => ({ space: "self", tab, allow });
const admin = (tab: PortalRouteHandle["tab"], allow: PortalRouteHandle["allow"]): PortalRouteHandle => ({ space: "admin", tab, allow });

export const portalRoutes: RouteObject[] = [
  {
    element: <RootLayout />,
    children: [
      { path: ROUTE.login, element: <LoginRoute /> },
      {
        element: <PortalGate />,
        children: [
          { path: ROUTE.root, element: <LandingRedirect /> },
          page(ROUTE.access, self("access", canUseSelfService), <AccessPage />),
          page(ROUTE.tokens, self("tokens", canUseSelfService), <TokensPage />),
          page(ROUTE.credentials, self("credentials", canUseSelfService), <CredentialsPage />),
          page(ROUTE.activity, self("activity", canViewActivity), <ActivityPage />),
          page(ROUTE.account, self("account"), <AccountPage />),
          page(ROUTE.policies, admin("policies", canManagePolicies), <PoliciesPage />),
          page(ROUTE.grantNew, admin("policies", canWritePolicies), <GrantEditorPage />),
          page(ROUTE.grantEdit, admin("policies", hasPolicyScope), <GrantEditorPage />),
          page(ROUTE.principals, admin("principals", canViewAdmin), <PrincipalsPage />),
          page(ROUTE.principal, admin("principals", canViewAdmin), <PrincipalPage />),
          page(ROUTE.group, admin("principals", canViewAdmin), <GroupPage />),
          page(ROUTE.catalog, admin("catalog", canViewAdmin), <CatalogPage />),
          page(ROUTE.catalogService, admin("catalog", canViewAdmin), <CatalogServicePage />),
          page(ROUTE.resources, admin("catalog", canViewAdmin), <ResourcesPage />),
          page(ROUTE.resourceGroups, admin("catalog", canViewAdmin), <ResourceGroupsPage />),
          page(ROUTE.audit, admin("audit", canViewAudit), <AuditPage />),
          page(ROUTE.system, admin("system", canViewAdmin), <SystemPage />),
          { path: "*", element: <NotFoundPage /> }
        ]
      }
    ]
  }
];

export function createPortalRouter() {
  return createBrowserRouter(portalRoutes);
}
