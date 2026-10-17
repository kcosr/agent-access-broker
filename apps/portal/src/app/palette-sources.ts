// Search only explicitly selected, already authorized management metadata.
import type { PaletteItem, PaletteSource } from "../workbench";
import type { AgentTokenOptions, BrokerTokenRecord, CredentialList, GroupRecord, PolicyCatalogResult, PolicyGrantRecord, PrincipalRecord, ResourceGroupRecord, ResourceRecord, Session } from "../types";
import type { ImportedServiceRecord } from "../import-types";
import { canUseSelfService, canViewAdmin, hasPolicyScope } from "../lib/capabilities";
import { canViewAudit, credentialStatus, identityDisplayName, policySubjectShortLabel, tokenStatus } from "../lib/helpers";
import { auditListPath } from "../lib/audit";
import { resourceLabel } from "../lib/resource-labels";
import { resourceTypeLabel, resourceTypePluralLabel, type ResourceTypes } from "../lib/resource-types";
import { ADMIN_TABS, SELF_TABS, hasAdminSpace } from "./spaces";
import { ROUTE, paths } from "./paths";

type Go = (href: string) => () => void;

export function navigationPaletteItems(session: Session, go: Go): PaletteItem[] {
  return [
    ...(hasAdminSpace(session) ? ADMIN_TABS : []).filter((tab) => !tab.allow || tab.allow(session))
      .map((tab) => ({ id: `go-${tab.key}`, label: tab.label, icon: tab.icon, hint: "Admin", onSelect: go(tab.href) })),
    ...(canUseSelfService(session) ? SELF_TABS : []).filter((tab) => !tab.allow || tab.allow(session))
      .map((tab) => ({ id: `go-${tab.key}`, label: tab.label, icon: tab.icon, hint: "My access", onSelect: go(tab.href) })),
    ...(canViewAdmin(session) ? [
      { id: "go-users", label: "Users", icon: "user" as const, keywords: ["people", "principals", "accounts"], onSelect: go(paths.principals("users")) },
      { id: "go-service-accounts", label: "Service accounts", icon: "server" as const, keywords: ["principals", "automation", "bots"], onSelect: go(paths.principals("service-accounts")) },
      { id: "go-groups", label: "User groups", icon: "users" as const, keywords: ["groups", "identity groups", "principal groups", "teams"], onSelect: go(paths.principals("groups")) },
      { id: "go-resources", label: "Resources", icon: "database" as const, keywords: ["catalog", "projects", "repositories", "spaces"], onSelect: go(paths.resources()) },
      { id: "go-resource-groups", label: "Resource groups", icon: "database" as const, keywords: ["catalog", "collections", "include", "exclude"], onSelect: go(paths.resourceGroups()) },
      { id: "go-system", label: "System", icon: "gear" as const, keywords: ["runtime", "reload", "config"], onSelect: go(ROUTE.system) }
    ] : []),
    { id: "go-account", label: "Account settings", icon: "user", onSelect: go(ROUTE.account) }
  ];
}

export type PaletteEntities = {
  session: Session;
  types: ResourceTypes;
  principals: PrincipalRecord[];
  groups: GroupRecord[];
  catalog: PolicyCatalogResult | null;
  grants: PolicyGrantRecord[];
  resources: ResourceRecord[];
  resourceGroups: ResourceGroupRecord[];
  imports: ImportedServiceRecord[];
  tokenOptions: AgentTokenOptions | null;
  tokens: BrokerTokenRecord[];
  credentials: CredentialList;
};

export function entityPaletteSources(data: PaletteEntities, go: Go): PaletteSource[] {
  const { session, types, catalog } = data;
  const admin = canViewAdmin(session);
  const policy = hasPolicyScope(session);
  const self = canUseSelfService(session);
  const sources: PaletteSource[] = [];
  const add = (id: string, title: string, items: PaletteItem[]) => sources.push({ id, title, showWhenEmpty: false, items });
  if (admin) {
    add("principals", "Principals", data.principals.map((principal) => ({
      id: `principal-${principal.principalId}`, label: identityDisplayName(principal.displayName) || principal.principalId,
      icon: principal.kind === "service_account" ? "server" : "user",
      hint: `${principal.kind === "service_account" ? "Service account" : "User"} · ${principal.principalId} · ${principal.status}`,
      keywords: [principal.principalId, principal.email ?? "", principal.kind === "service_account" ? "service account" : "user", principal.status],
      onSelect: go(paths.principal(principal.principalId))
    })));
    add("groups", "User groups", data.groups.map((group) => ({
      id: `group-${group.groupId}`, label: identityDisplayName(group.displayName) || group.groupId, icon: "users",
      hint: `${group.groupId} · ${group.status}`, keywords: [group.groupId, group.description ?? "", "user group", "identity group", group.status],
      onSelect: go(paths.group(group.groupId))
    })));
  }
  // Policy catalogs are already restricted by the broker to the viewer's scope.
  const services = policy ? catalog?.services ?? [] : self ? data.tokenOptions?.services ?? [] : [];
  const imports = new Map((admin ? data.imports : []).map((entry) => [entry.definition.service, entry]));
  const serviceItems: PaletteItem[] = services.map((service) => {
    const imported = imports.get(service.service);
    return {
      id: `service-${service.service}`, label: service.displayName, icon: "package",
      hint: `${service.service}${imported ? ` · ${imported.status}` : ""}`,
      keywords: [service.service, "service", ...(imported ? [imported.status, imported.definition.adapterKind, "imported"] : [])],
      onSelect: go(admin ? paths.catalogService(service.service) : policy ? paths.policies({ service: service.service }) : paths.access(service.service))
    };
  });
  const listedServices = new Set(services.map((service) => service.service));
  for (const imported of imports.values()) {
    const { service, displayName, adapterKind } = imported.definition;
    if (listedServices.has(service)) continue;
    serviceItems.push({ id: `service-${service}`, label: displayName, icon: "package", hint: `${service} · ${imported.status}`, keywords: [service, adapterKind, imported.status, "imported service"], onSelect: go(paths.catalogService(service, "import")) });
  }
  if (policy || self || admin) {
    add("services", "Services", serviceItems);
    add("service-actions", "Service actions", services.flatMap((service) => service.actions.map((action) => ({
      id: `service-action-${service.service}/${action.action}`, label: action.action, icon: "list" as const,
      hint: `${service.displayName} · ${action.readOnly ? "Read-only" : "Write-capable"}`,
      keywords: [service.service, service.displayName, action.description, "service action", ...Object.keys(action.requiredScopes), action.readOnly ? "read only" : "write capable"],
      onSelect: go(admin ? paths.catalogAction(service.service, action.action) : policy ? paths.policies({ service: service.service, action: action.action }) : paths.accessAction(service.service, action.action))
    }))));
  }
  if (policy) {
    add("grants", "Grants", data.grants.map((grant) => ({
      id: `grant-${grant.grantRef}`, label: grant.grantRef, icon: "shield",
      hint: `${grant.service} · ${grant.subjects.map((subject) => policySubjectShortLabel(subject, catalog)).join(", ")} · ${grant.status}`,
      keywords: [grant.service, grant.description ?? "", ...grant.subjects, ...grant.subjects.map((subject) => policySubjectShortLabel(subject, catalog)), ...grant.actions, grant.status, "grant"],
      onSelect: go(paths.grant(grant.grantRef))
    })));
  }
  if (admin) {
    const byId = new Map(data.resources.map((resource) => [resource.id, resource]));
    const resourceKeywords = (resource: ResourceRecord) => [resource.id, resourceLabel(types, resource), resource.resourceType, resourceTypeLabel(types, resource.resourceType), resourceTypePluralLabel(types, resource.resourceType)];
    add("resources", "Resources", data.resources.map((resource) => ({
      id: `resource-${resource.id}`, label: resourceLabel(types, resource), icon: "database",
      hint: `${resourceTypeLabel(types, resource.resourceType)} · ${resource.enabled ? "Enabled" : "Disabled"}`,
      keywords: [...resourceKeywords(resource), "resource", resource.enabled ? "enabled" : "disabled"], onSelect: go(paths.resources(resource.id))
    })));
    add("resource-groups", "Resource groups", data.resourceGroups.map((group) => ({
      id: `resource-group-${group.id}`, label: group.name, icon: "database",
      hint: `${group.id} · ${group.includedResourceIds.length} included · ${group.excludedResourceIds.length} excluded`,
      keywords: [group.id, "resource group", ...[...group.includedResourceIds, ...group.excludedResourceIds].flatMap((id) => {
        const resource = byId.get(id);
        return resource ? resourceKeywords(resource) : [id];
      })],
      onSelect: go(paths.resourceGroups(group.id))
    })));
  }
  if (self) {
    add("tokens", "Your tokens", data.tokens.map((token) => ({
      id: `token-${token.tokenId}`, label: token.name, icon: "key", hint: `${token.tokenId.slice(0, 8)} · ${tokenStatus(token)}`, keywords: [token.tokenId, "token", tokenStatus(token)], onSelect: go(paths.tokens(token.tokenId))
    })));
    add("credentials", "Your credentials", data.credentials.connections.filter((connection) => connection.credential).map((connection) => {
      const credential = connection.credential!;
      return {
        id: `credential-${credential.credentialId}`, label: connection.displayName, icon: "lock",
        hint: `${connection.profile ?? credential.profile} · ${credentialStatus(credential)}`,
        // Never index opaque metadata, credential values, or verification error details.
        keywords: [credential.credentialId, connection.connection, ...connection.consumers.flatMap((consumer) => [consumer.service, consumer.displayName]), credential.profile, credential.credentialKind, credential.status, credentialStatus(credential), "credential"],
        onSelect: go(paths.credentials(connection.connection))
      };
    }));
  }
  if (canViewAudit(session)) {
    sources.push({ id: "audit-search", title: "Audit search", showWhenEmpty: false, items: (query) => query.trim() ? [{
      id: "search-audit", label: `Search audit for “${query.trim()}”`, icon: "file-text", hint: "Open audit search", onSelect: go(auditListPath("admin", { q: query.trim() }))
    }] : [] });
  }
  return sources;
}

/** Only an initial active fetch needs a loading row; cached refreshes keep results stable. */
export function paletteQueryFeedback(title: string, ...queries: Array<{ isFetching: boolean; isError: boolean; data: unknown; refetch: () => unknown }>): Pick<PaletteSource, "loading" | "error" | "onRetry"> {
  const failed = queries.filter((query) => query.isError);
  const message = failed.some((query) => query.data !== undefined)
    ? `Could not refresh ${title.toLowerCase()}. Available results may be out of date.`
    : `Could not load ${title.toLowerCase()}. Results may be incomplete.`;
  return {
    loading: queries.some((query) => query.isFetching && query.data === undefined),
    ...(failed.length ? { error: message, onRetry: () => { for (const query of failed) void query.refetch(); } } : {})
  };
}
