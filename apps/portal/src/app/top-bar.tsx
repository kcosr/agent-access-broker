import { canViewAdmin, canUseSelfService } from "../lib/capabilities";
// The portal top bar: brand, space switch, the space's tabs, search, status,
// theme, System, and the account menu.
import type { ReactNode } from "react";
import { useNavigate } from "react-router";
import {
  AppShell,
  Badge,
  Brand,
  IconButton,
  Menu,
  NavTab,
  NavTabs,
  SegLinks,
  SidebarToggle,
  Spacer,
  ThemeMenu,
  TopBar,
  TopSearch,
  TopStatus,
  formatDateTime,
  useToast
} from "../workbench";
import { credentialStatus, identityDisplayName } from "../lib/helpers";
import { useConfigStatus, useConsoleData, usePolicyStatus } from "../data/queries";
import { useAuthActions } from "../mutations/auth";
import { useActiveRoute, useSelfSubject } from "./active-route";
import { usePalette } from "./palette";
import { ROUTE } from "./paths";
import { useSession } from "./session";
import { hasAdminSpace, landingPath, spaceTabs, type SpaceKey } from "./spaces";
import { usePortalTheme } from "./theme";

const SIDEBAR_KEY = "aab.portal.sidebar-width";

/** A portal page: the app frame with the top bar, an optional sidebar, and an optional drawer. */
export function PortalPage({ sidebar, drawer, children }: { sidebar?: ReactNode; drawer?: ReactNode; children: ReactNode }) {
  return (
    <AppShell topBar={<PortalTopBar />} sidebar={sidebar} sidebarStorageKey={SIDEBAR_KEY} drawer={drawer}>
      {children}
    </AppShell>
  );
}

/** Admin | My access: navigation links with the segmented look. */
function SpaceSwitch({ space }: { space: SpaceKey }) {
  return (
    <SegLinks
      label="Space"
      size="sm"
      items={[
        { href: ROUTE.policies, label: "Admin", current: space === "admin" },
        { href: ROUTE.access, label: "My access", current: space === "self" }
      ]}
    />
  );
}

export function PortalTopBar() {
  const { session } = useSession();
  const route = useActiveRoute();
  const { mode, setMode } = usePortalTheme();
  const { openPalette } = usePalette();
  const locked = Boolean(session.passwordChangeRequired);
  const space: SpaceKey = route?.space ?? (hasAdminSpace(session) ? "admin" : "self");
  const tabs = locked ? [] : spaceTabs(space, session);
  const attention = useCredentialAttention(!locked && space === "self" && canUseSelfService(session));
  return (
    <TopBar>
      <SidebarToggle />
      <Brand name="Agent Access Broker" icon="shield" href={landingPath(session)} />
      {!locked && hasAdminSpace(session) && canUseSelfService(session) ? <SpaceSwitch space={space} /> : null}
      {tabs.length ? (
        <NavTabs label={space === "admin" ? "Admin" : "My access"}>
          {tabs.map((tab) => (
            <NavTab
              key={tab.key}
              href={tab.href}
              icon={tab.icon}
              current={route?.tab === tab.key}
              {...(tab.key === "credentials" && attention > 0
                ? { count: attention, countTone: "warning" as const, countLabel: `${attention} ${attention === 1 ? "credential needs" : "credentials need"} attention` }
                : {})}
            >
              {tab.label}
            </NavTab>
          ))}
        </NavTabs>
      ) : null}
      {!locked && space === "admin" && session.role === "auditor" ? <Badge variant="outline">Auditor · read-only</Badge> : null}
      <Spacer />
      {!locked ? <TopSearch onClick={openPalette} placeholder="Search or jump to…" /> : null}
      {!locked ? <RuntimeStatus /> : null}
      <ThemeMenu mode={mode} onChange={setMode} />
      {!locked && canViewAdmin(session) ? (
        <IconButton href={ROUTE.system} icon="gear" label="System" aria-current={route?.tab === "system" ? "page" : undefined} />
      ) : null}
      <AccountMenu />
    </TopBar>
  );
}

/** Credentials that are saved but not verified, or failed verification. */
function useCredentialAttention(enabled: boolean) {
  const data = useConsoleData(useSelfSubject(), enabled);
  if (!enabled) return 0;
  return data.credentials.connections.filter((connection) => {
    if (!connection.credential) return false;
    const status = credentialStatus(connection.credential);
    return status === "Not verified" || status === "Verification failed";
  }).length;
}

function RuntimeStatus() {
  const { session } = useSession();
  const navigate = useNavigate();
  const admin = canViewAdmin(session);
  const config = useConfigStatus(admin).data;
  const policy = usePolicyStatus(!admin && hasAdminSpace(session)).data;
  if (admin && config) {
    const failed = config.lastReloadAttempt && config.lastReloadAttempt.decision !== "allow";
    return (
      <TopStatus
        tone={failed ? "warning" : "success"}
        label={failed ? `Reload failed · gen ${config.generation}` : `Config gen ${config.generation}`}
        shortLabel={failed ? "Reload failed" : `gen ${config.generation}`}
        detail={`Config generation ${config.generation} loaded ${formatDateTime(config.loadedAt)} · identity ${config.identityAuthority} · policy ${config.policyAuthority}`}
        onClick={() => navigate(ROUTE.system)}
      />
    );
  }
  if (policy) {
    return (
      <TopStatus
        tone={policy.writable ? "success" : "neutral"}
        label={`Policy gen ${policy.policyGeneration}`}
        shortLabel={`gen ${policy.policyGeneration}`}
        detail={`Policy generation ${policy.policyGeneration} · policy authority ${policy.policyAuthority}${policy.writable ? "" : " (read-only)"}`}
      />
    );
  }
  return null;
}

function AccountMenu() {
  const { session } = useSession();
  const { logout } = useAuthActions();
  const toast = useToast();
  const name = identityDisplayName(session.displayName) || session.principal || "Account";
  return (
    <Menu
      label="Account"
      items={[
        { type: "heading", label: name, sub: session.principal !== name ? session.principal : session.email ?? undefined },
        { type: "separator" },
        { id: "account", label: "Account settings", icon: "user", href: ROUTE.account },
        {
          id: "shortcuts",
          label: "Keyboard shortcuts",
          icon: "command",
          onSelect: () => toast("Ctrl K search · / filter · j k move · ↵ open · Esc close", { duration: 6000 })
        },
        { type: "separator" },
        { id: "signout", label: "Sign out", icon: "log-out", onSelect: () => void logout() }
      ]}
      trigger={(props) => <IconButton {...props} icon="user" label="Account" />}
    />
  );
}
