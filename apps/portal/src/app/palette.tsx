import { canViewAdmin, canWriteAdmin, canWritePolicies, hasPolicyScope } from "../lib/capabilities";
// Ctrl/Cmd-K command palette: go to views, jump to entities, run common actions.
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { useNavigate } from "react-router";
import { CommandPalette, useCommandPaletteHotkey, type PaletteItem, type PaletteSource } from "../workbench";
import { useResourceTypes } from "../lib/resource-types";
import {
  useAdminGroups,
  useAdminPrincipals,
  useAgentTokenOptions,
  useConsoleData,
  usePolicyCatalog,
  usePolicyGrants,
  usePolicyStatus,
  useImports,
  useResourceCatalog
} from "../data/queries";
import { useAuthActions } from "../mutations/auth";
import { useAgentTokenActions } from "../mutations/tokens";
import { useRuntimeActions } from "../mutations/runtime";
import { useSelfSubject } from "./active-route";
import { useModal } from "./modal";
import { paths } from "./paths";
import { useSession } from "./session";
import { entityPaletteSources, navigationPaletteItems, paletteQueryFeedback } from "./palette-sources";
import { usePortalTheme } from "./theme";

type PaletteValue = { openPalette: () => void };

const PaletteContext = createContext<PaletteValue>({ openPalette: () => undefined });

export function usePalette() {
  return useContext(PaletteContext);
}

export function PaletteProvider({ children }: { children: ReactNode }) {
  const { session } = useSession();
  const [open, setOpen] = useState(false);
  const usable = session.authenticated && !session.passwordChangeRequired;
  useCommandPaletteHotkey(() => setOpen((current) => !current), usable);
  const openPalette = useCallback(() => setOpen(true), []);
  const value = useMemo(() => ({ openPalette }), [openPalette]);
  return (
    <PaletteContext.Provider value={value}>
      {children}
      {open && usable ? <OpenPalette onClose={() => setOpen(false)} /> : null}
    </PaletteContext.Provider>
  );
}

function OpenPalette({ onClose }: { onClose: () => void }) {
  const sources = usePaletteSources();
  return <CommandPalette open onClose={onClose} sources={sources} placeholder="Search pages, people, groups, resources, services, and more…" />;
}

function usePaletteSources(): PaletteSource[] {
  const { session } = useSession();
  const navigate = useNavigate();
  const types = useResourceTypes();
  const { setModal } = useModal();
  const { mode, setMode } = usePortalTheme();
  const { logout } = useAuthActions();
  const runtime = useRuntimeActions();
  const admin = canViewAdmin(session);
  const policy = hasPolicyScope(session);
  const self = useSelfSubject();
  const console = useConsoleData(self);
  const tokenOptions = useAgentTokenOptions(self);
  const tokenActions = useAgentTokenActions(self, tokenOptions.options);
  const principals = useAdminPrincipals(admin);
  const groups = useAdminGroups(admin);
  const catalog = usePolicyCatalog(policy);
  const grants = usePolicyGrants(policy);
  const policyStatus = usePolicyStatus(policy);
  const resources = useResourceCatalog(admin);
  const imports = useImports(admin);

  return useMemo(() => {
    const go = (href: string) => () => navigate(href);
    const actions: PaletteItem[] = [
      ...(canWritePolicies(session) && policyStatus.data?.writable
        ? [{ id: "create-grant", label: "Create grant", icon: "plus" as const, keywords: ["policy", "new"], onSelect: go(paths.grantNew()) }]
        : []),
      ...(tokenActions.issueBlocker() === null
        ? [{ id: "issue-token", label: "Issue agent token", icon: "key" as const, keywords: ["token", "new"], onSelect: () => tokenActions.openIssueDialog() }]
        : []),
      ...(canWriteAdmin(session)
        ? [
            { id: "create-user", label: "Create user", icon: "user" as const, keywords: ["principal", "new"], onSelect: () => setModal({ type: "createPrincipal", kind: "user" }) },
            { id: "create-sa", label: "Create service account", icon: "server" as const, keywords: ["principal", "new"], onSelect: () => setModal({ type: "createPrincipal", kind: "service_account" }) },
            { id: "create-group", label: "Create group", icon: "users" as const, keywords: ["new"], onSelect: () => setModal({ type: "createGroup" }) },
            { id: "import-service", label: "Import service", icon: "upload" as const, keywords: ["mcp", "openapi", "catalog"], onSelect: go(paths.catalogImport()) },
            { id: "reload", label: "Reload runtime configuration", icon: "refresh" as const, keywords: ["config", "system"], onSelect: runtime.confirmReload }
          ]
        : []),
      ...(["system", "light", "dark"] as const)
        .filter((option) => option !== mode)
        .map((option) => ({
          id: `theme-${option}`,
          label: `Theme: ${option === "system" ? "System" : option === "light" ? "Light" : "Dark"}`,
          icon: option === "system" ? ("monitor" as const) : option === "light" ? ("sun" as const) : ("moon" as const),
          keywords: ["theme", "appearance"],
          onSelect: () => setMode(option)
        })),
      { id: "sign-out", label: "Sign out", icon: "log-out", onSelect: () => void logout() }
    ];

    const entities = entityPaletteSources({
      session, types,
      principals: principals.data ?? [], groups: groups.data ?? [], catalog: catalog.data ?? null,
      grants: grants.data ?? [], resources: resources.data?.resources ?? [], resourceGroups: resources.data?.resourceGroups ?? [],
      imports: imports.data?.services ?? [], tokenOptions: tokenOptions.options,
      tokens: console.tokens, credentials: console.credentials, credentialTargets: console.targets
    }, go);
    const serviceQueries = policy ? [catalog, ...(admin ? [imports] : [])] : [tokenOptions.query];
    const feedback: Record<string, ReturnType<typeof paletteQueryFeedback>> = {
      principals: paletteQueryFeedback("Principals", principals),
      groups: paletteQueryFeedback("User groups", groups),
      services: paletteQueryFeedback("Services", ...serviceQueries),
      "service-actions": paletteQueryFeedback("Service actions", policy ? catalog : tokenOptions.query),
      grants: paletteQueryFeedback("Grants", grants, catalog),
      resources: paletteQueryFeedback("Resources", resources),
      "resource-groups": paletteQueryFeedback("Resource groups", resources),
      tokens: paletteQueryFeedback("Your tokens", console.query),
      credentials: paletteQueryFeedback("Your credentials", console.query)
    };
    return [
      { id: "goto", title: "Go to", items: navigationPaletteItems(session, go) },
      ...entities.map((source) => ({ ...source, ...feedback[source.id] })),
      { id: "actions", title: "Actions", items: actions }
    ];
  }, [session, navigate, types, setModal, mode, setMode, logout, runtime, admin, policy, console, tokenOptions, tokenActions, principals, groups, catalog, grants, policyStatus, resources, imports]);
}
