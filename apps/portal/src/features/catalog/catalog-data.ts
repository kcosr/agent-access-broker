// The Catalog's service index: built-in services from the policy catalog and
// imported services from the imports list, merged into one entry per service
// with its status, action count, and service policy manager count.
import { useMemo } from "react";
import type { ImportActionStatus, ImportedServiceRecord, ImportListResult, ImportServiceStatus } from "../../import-types";
import type { PolicyCatalogResult, PolicyServiceCatalog, ServicePolicyManagerAssignment } from "../../types";
import type { IconName, Tone } from "../../workbench";
import { useImports, usePolicyCatalog, useServicePolicyManagers } from "../../data/queries";

export type ServiceOrigin = "builtin" | "imported";

export type ServiceState = {
  key: "available" | "unavailable" | ImportServiceStatus;
  label: string;
  tone: Tone;
  icon: IconName;
  /** Why the service cannot execute, when the broker says. */
  reason: string | null;
};

export type CatalogService = {
  service: string;
  displayName: string;
  origin: ServiceOrigin;
  /** Broker surface (`invoke`, `git_http`, …) when the policy catalog lists the service. */
  surface: string | null;
  catalog: PolicyServiceCatalog | null;
  imported: ImportedServiceRecord | null;
  /** Catalog actions for built-in services; accepted, non-retired actions for imported ones. */
  actionCount: number;
  managerCount: number;
  state: ServiceState;
};

export const ADAPTER_LABELS: Record<string, string> = { mcp_http: "HTTP MCP", openapi_http: "OpenAPI HTTP" };

export function adapterLabel(kind: string) {
  return ADAPTER_LABELS[kind] ?? kind;
}

const IMPORT_STATES: Record<ImportServiceStatus, Omit<ServiceState, "reason">> = {
  draft: { key: "draft", label: "Draft", tone: "warning", icon: "pencil" },
  enabled: { key: "enabled", label: "Enabled", tone: "success", icon: "circle-check" },
  disabled: { key: "disabled", label: "Disabled", tone: "muted", icon: "pause" },
  retired: { key: "retired", label: "Retired", tone: "neutral", icon: "ban" }
};

export const ACTION_STATUS: Record<ImportActionStatus, { label: string; tone: Tone; icon: IconName }> = {
  enabled: { label: "Enabled", tone: "success", icon: "circle-check" },
  disabled: { label: "Disabled", tone: "muted", icon: "pause" },
  quarantined: { label: "Quarantined", tone: "warning", icon: "alert" },
  retired: { label: "Retired", tone: "neutral", icon: "ban" }
};

function serviceState(catalog: PolicyServiceCatalog | null, imported: ImportedServiceRecord | null): ServiceState {
  const unavailable = catalog?.available === false;
  if (imported) {
    if (imported.status === "enabled" && unavailable) {
      return { key: "unavailable", label: "Unavailable", tone: "warning", icon: "alert", reason: catalog?.unavailableReason ?? null };
    }
    return { ...IMPORT_STATES[imported.status], reason: null };
  }
  return unavailable
    ? { key: "unavailable", label: "Unavailable", tone: "warning", icon: "alert", reason: catalog?.unavailableReason ?? null }
    : { key: "available", label: "Available", tone: "success", icon: "circle-check", reason: null };
}

/** Whether a service needs a status marker (anything but a normally usable service). */
export function stateNeedsAttention(state: ServiceState) {
  return state.key !== "available" && state.key !== "enabled";
}

/** One entry per service, sorted by display name. */
export function buildCatalogServices(
  catalog: PolicyCatalogResult | null | undefined,
  imports: ImportListResult | null | undefined,
  managers: ServicePolicyManagerAssignment[] | null | undefined
): CatalogService[] {
  const importedById = new Map((imports?.services ?? []).map((record) => [record.definition.service, record]));
  const catalogById = new Map((catalog?.services ?? []).map((service) => [service.service, service]));
  const managerCounts = new Map<string, number>();
  for (const assignment of managers ?? []) managerCounts.set(assignment.service, (managerCounts.get(assignment.service) ?? 0) + 1);
  const ids = [...new Set([...catalogById.keys(), ...importedById.keys()])];
  return ids
    .map((service) => {
      const entry = catalogById.get(service) ?? null;
      const imported = importedById.get(service) ?? null;
      return {
        service,
        displayName: imported?.definition.displayName || entry?.displayName || service,
        origin: imported ? "imported" : "builtin",
        surface: entry?.surface ?? null,
        catalog: entry,
        imported,
        actionCount: imported ? imported.actions.filter((action) => action.status !== "retired").length : entry?.actions.length ?? 0,
        managerCount: managerCounts.get(service) ?? 0,
        state: serviceState(entry, imported)
      } satisfies CatalogService;
    })
    .sort((a, b) => a.displayName.localeCompare(b.displayName) || a.service.localeCompare(b.service));
}

/** The merged service index plus the queries behind it. */
export function useCatalogServices() {
  const catalog = usePolicyCatalog();
  const imports = useImports();
  const managers = useServicePolicyManagers();
  const services = useMemo(() => buildCatalogServices(catalog.data, imports.data, managers.data), [catalog.data, imports.data, managers.data]);
  const queries = [catalog, imports, managers];
  return {
    services,
    catalog: catalog.data ?? null,
    imports: imports.data ?? null,
    managers: managers.data ?? [],
    loading: (catalog.isPending && catalog.fetchStatus !== "idle") || (imports.isPending && imports.fetchStatus !== "idle"),
    fetching: queries.some((query) => query.isFetching),
    error: catalog.error ?? imports.error ?? null,
    refetch: () => Promise.all(queries.map((query) => query.refetch())),
    find: (service: string) => services.find((entry) => entry.service === service) ?? null
  };
}

export type CatalogIndex = ReturnType<typeof useCatalogServices>;

/** Why "Import service" cannot be used, or null. */
export function importBlocker(imports: ImportListResult | null) {
  if (!imports) return "Loading import settings…";
  if (!imports.operatorEnabled) return "Imports are disabled by operator configuration.";
  if (!imports.availableKinds.length) return "No import types are enabled by operator configuration.";
  return null;
}
