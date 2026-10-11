import { ROLE_LABELS } from "../../lib/capabilities";
import { AdminButton, AdminIconButton } from "../../components/admin-access";
// Admin › Principals › a user or service account: header with role actions
// and URL-driven tabs (Overview, Access, Grants, Groups, Tokens, Credentials,
// Limits, Activity). Replaces the former "Manage user" mode.
import { SignInMethodBadges } from "./sign-in-methods";
import { useId, type ReactNode } from "react";
import { useLocation, useParams } from "react-router";
import type { PrincipalDetail } from "../../types";
import { canViewAudit, identityDisplayName } from "../../lib/helpers";
import { auditListPath } from "../../lib/audit";
import { urlParam, urlStateSearch, useUrlState } from "../../lib/url-state";
import { Avatar, Badge, Button, EmptyState, ErrorState, findRowTarget, GroupHeader, LinkTabs, List, ListFooter, Main, Menu, PageHeader, plural, SkeletonBlock } from "../../workbench";
import { adminSubject } from "../../app/active-route";
import { paths, type PrincipalTab } from "../../app/paths";
import { useModal } from "../../app/modal";
import { useSession } from "../../app/session";
import { PortalPage } from "../../app/top-bar";
import { NotFoundPage } from "../../app/gate";
import {
  useAdminGroups,
  useAdminPrincipal,
  useAdminUserDetail,
  useAdminLoginMethods,
  useConfigStatus,
  usePolicyCatalog,
  usePolicyGrants,
  usePolicyStatus,
  writeAuthorities
} from "../../data/queries";
import { usePrincipalActions } from "../../mutations/principals";
import { useManagementTokenActions } from "../../mutations/tokens";
import { AccessDrawer, AccessRows, AccessToolbar, useAccessList } from "../access/access-list";
import { TokenDrawer, TokenTable, TokenToolbar, useTokenList } from "../tokens/token-list";
import { CredentialDrawer, CredentialRows, CredentialToolbar, useCredentialList } from "../credentials/credential-list";
import { GrantDrawer } from "../policies/policies-page";
import { PrincipalActivity } from "../audit/principal-activity";
import { GrantReferences, GrantReferencesToolbar, referenceRows } from "./policy-references";
import { ManagementTokenDrawer, ManagementTokens, MANAGEMENT_TOKEN_STATE } from "./management-tokens";
import { PrincipalGroups, PrincipalGroupsToolbar } from "./principal-groups";
import { PrincipalOverview } from "./principal-overview";
import { ServiceLimitsTab } from "./service-limits";

const TABS: PrincipalTab[] = ["overview", "access", "grants", "groups", "tokens", "credentials", "limits", "activity"];
const GRANT_STATE = { grant: urlParam.text() };

export function PrincipalPage() {
  const { principalId = "", tab = "overview" } = useParams();
  const { session } = useSession();
  const query = useAdminPrincipal(principalId);
  // Activity reads the audit store: unavailable (like /ui/admin/audit) when it cannot be queried.
  if (!TABS.includes(tab as PrincipalTab) || (tab === "activity" && !canViewAudit(session))) return <NotFoundPage />;
  if (query.isPending) {
    return (
      <PortalPage>
        <Main label="Principal">
          <List>
            <SkeletonBlock lines={6} />
          </List>
        </Main>
      </PortalPage>
    );
  }
  if (query.isError || !query.data) {
    return (
      <PortalPage>
        <Main label="Principal">
          <List>
            {query.isError && !/not.found|404/i.test(String(query.error)) ? (
              <ErrorState error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} />
            ) : (
              <EmptyState
                icon="user"
                title="Principal not found"
                actions={
                  <Button href={paths.principals()} icon="arrow-left">
                    Back to Principals
                  </Button>
                }
              >
                {principalId} does not exist.
              </EmptyState>
            )}
          </List>
        </Main>
      </PortalPage>
    );
  }
  const principal = query.data;
  const props = { principal, tab: tab as PrincipalTab };
  switch (tab as PrincipalTab) {
    case "access":
      return <AccessTab {...props} />;
    case "grants":
      return <GrantsTab {...props} />;
    case "groups":
      return <GroupsTab {...props} />;
    case "tokens":
      return <TokensTab {...props} />;
    case "credentials":
      return <CredentialsTab {...props} />;
    case "limits":
      return <LimitsTab {...props} />;
    case "activity":
      return <ActivityTab {...props} />;
    default:
      return <OverviewTab {...props} />;
  }
}

type TabProps = { principal: PrincipalDetail; tab: PrincipalTab };

/** The page frame shared by every tab: header, tabs, the tab's toolbar, and its drawer. */
function PrincipalFrame({
  principal,
  tab,
  toolbar,
  drawer,
  tint = false,
  refetching = false,
  children
}: TabProps & { toolbar?: ReactNode; drawer?: ReactNode; tint?: boolean; refetching?: boolean; children: ReactNode }) {
  const { session } = useSession();
  const { confirm } = useModal();
  const principals = usePrincipalActions();
  const tokens = useManagementTokenActions();
  const serviceAccount = principal.kind === "service_account";
  const name = identityDisplayName(principal.displayName);
  const admin = principal.role === "admin";
  const active = principal.status === "active";
  const self = principal.principalId === session.principal;
  // Each grant once, whether it names the user, reaches them through groups, or both.
  const grantCount = referenceRows(principal.policyReferenceSections).length;
  const tabs = TABS.filter((item) => item !== "activity" || canViewAudit(session)).map((item) => ({
    href: paths.principal(principal.principalId, item),
    label: item === "overview" ? "Overview" : item[0]!.toUpperCase() + item.slice(1),
    current: item === tab,
    count: item === "grants" ? grantCount : item === "groups" ? principal.groupMemberships.length : undefined
  }));
  const header = (
    <PageHeader
      back={{ href: paths.principals(serviceAccount ? "service-accounts" : "users"), label: "Principals" }}
      title={
        <span className="pt-person">
          <Avatar name={name || principal.principalId} size="lg" highlight={self} />
          {name || principal.principalId}
        </span>
      }
      meta={
        <>
          <Badge variant="outline">{serviceAccount ? "Service account" : principal.kind === "system" ? "System" : "User"}</Badge>
          <Badge tone={admin ? "info" : "neutral"}>{ROLE_LABELS[principal.role]}</Badge>
          <Badge tone={active ? "success" : "muted"} variant="dot">
            {principal.status}
          </Badge>
          {!serviceAccount ? <SignInMethodBadges methods={principal.signInMethods} /> : null}
          <span className="wb-num">{principal.principalId}</span>
          {principal.email ? (
            <>
              <span className="wb-sep">·</span>
              <span>{principal.email}</span>
            </>
          ) : null}
        </>
      }
      actions={
        <>
          <AdminButton
            variant={active ? "danger-ghost" : "default"}
            icon={active ? "pause" : "play"}
            disabled={self && active}
            onClick={() => (active ? confirmDisable() : void principals.patch(principal.principalId, { status: "active" }))}
          >
            {`${active ? "Disable" : "Enable"} ${serviceAccount ? "service account" : "user"}`}
          </AdminButton>
          <Menu
            label="More actions"
            items={[
              ...(!serviceAccount
                ? [
                    { id: "access", label: "Account access", icon: "shield" as const, href: paths.principal(principal.principalId) },
                    { id: "setup", label: "Issue setup token", icon: "key" as const, disabled: !active, onSelect: () => tokens.openIssueDialog(principal.principalId, "user_manage") },
                    { id: "admin-token", label: "Issue admin token", icon: "key" as const, disabled: !active || !(admin || principal.role === "auditor"), onSelect: () => tokens.openIssueDialog(principal.principalId, "admin") },
                    { type: "separator" as const }
                  ]
                : []),
              { id: "grant", label: "Create grant for this principal", icon: "plus", href: paths.grantNew({ subject: `user:${principal.principalId}`, returnTo: paths.principal(principal.principalId, "grants") }) },
              ...(canViewAudit(session) ? [{ id: "audit", label: "View in Audit", icon: "history" as const, href: auditListPath("admin", { principal: principal.principalId }) }] : [])
            ]}
            trigger={(props) => <AdminIconButton {...props} variant="default" icon="more" label="More actions" />}
          />
        </>
      }
    >
      <LinkTabs label={serviceAccount ? "Service account sections" : "User sections"} items={tabs} />
    </PageHeader>
  );

  function confirmDisable() {
    confirm({
      title: serviceAccount ? "Disable service account?" : "Disable user?",
      body: `${principal.principalId} can no longer sign in or use its tokens until it is enabled again. Grants, groups, and tokens are kept.`,
      confirmLabel: serviceAccount ? "Disable service account" : "Disable user",
      onConfirm: () => principals.patch(principal.principalId, { status: "disabled" })
    });
  }

  return (
    <PortalPage drawer={drawer}>
      <Main
        label={name || principal.principalId}
        tint={tint}
        refetching={refetching}
        toolbar={header}
        header={toolbar}
      >
        {children}
      </Main>
    </PortalPage>
  );
}

function OverviewTab(props: TabProps) {
  const detail = useAdminLoginMethods(props.principal.principalId);
  const { groupWritesEnabled } = writeAuthorities(useConfigStatus().data);
  return (
    <PrincipalFrame {...props} tint>
      {detail.isPending ? <SkeletonBlock lines={5} /> : detail.isError ? <ErrorState error={detail.error} onRetry={() => void detail.refetch()} retrying={detail.isFetching} /> : <PrincipalOverview key={props.principal.principalId} principal={props.principal} loginMethods={detail.data} groupWritesEnabled={groupWritesEnabled} />}
    </PrincipalFrame>
  );
}

function AccessTab(props: TabProps) {
  const model = useAccessList(adminSubject(props.principal.principalId));
  return (
    <PrincipalFrame
      {...props}
      toolbar={<AccessToolbar model={model} embedded />}
      drawer={model.open ? <AccessDrawer model={model} /> : null}
      refetching={model.options.query.isFetching && !model.options.loading}
    >
      <List full>
        <AccessRows model={model} />
      </List>
    </PrincipalFrame>
  );
}

function GrantsTab(props: TabProps) {
  const catalog = usePolicyCatalog().data ?? null;
  const grants = usePolicyGrants();
  const status = usePolicyStatus().data;
  const location = useLocation();
  const [state, setState] = useUrlState(GRANT_STATE);
  const open = state.grant ? grants.data?.find((grant) => grant.grantRef === state.grant) ?? null : null;
  const count = referenceRows(props.principal.policyReferenceSections).length;
  return (
    <PrincipalFrame
      {...props}
      toolbar={<GrantReferencesToolbar subject={`user:${props.principal.principalId}`} writable={Boolean(status?.writable)} policyAuthority={status?.policyAuthority ?? "unknown"} count={count} />}
      drawer={
        open ? (
          <GrantDrawer
            grant={open}
            catalog={catalog}
            onClose={() => setState({ grant: "" }, { history: "push" })}
            returnFocus={() => findRowTarget(open.grantRef)}
            writableAuthority={Boolean(status?.writable)}
          />
        ) : null
      }
    >
      <List full>
        <GrantReferences
          sections={props.principal.policyReferenceSections}
          grants={grants.data ?? []}
          catalog={catalog}
          writable={Boolean(status?.writable)}
          grantHref={(grantRef) => `${location.pathname}${urlStateSearch(GRANT_STATE, location.search, { grant: state.grant === grantRef ? "" : grantRef })}`}
          openGrant={state.grant || null}
          onFollow={(grantRef) => setState({ grant: grantRef }, { history: "replace" })}
        />
      </List>
    </PrincipalFrame>
  );
}

function GroupsTab(props: TabProps) {
  const groups = useAdminGroups().data ?? [];
  const authorities = writeAuthorities(useConfigStatus().data);
  return (
    <PrincipalFrame
      {...props}
      toolbar={<PrincipalGroupsToolbar principal={props.principal} groups={groups} groupWritesEnabled={authorities.groupWritesEnabled} identityAuthority={authorities.identityAuthority} />}
    >
      <List full>
        <PrincipalGroups principal={props.principal} groups={groups} groupWritesEnabled={authorities.groupWritesEnabled} />
      </List>
    </PrincipalFrame>
  );
}

function TokensTab(props: TabProps) {
  const agentTokensHeading = useId();
  const model = useTokenList(adminSubject(props.principal.principalId));
  const detail = useAdminUserDetail(props.principal.principalId);
  const [state, setState] = useUrlState(MANAGEMENT_TOKEN_STATE);
  const managementOpen = state.mtoken ? detail.data?.userTokens.find((token) => token.tokenId === state.mtoken) ?? null : null;
  const serviceAccount = props.principal.kind === "service_account";
  return (
    <PrincipalFrame
      {...props}
      toolbar={<TokenToolbar model={model} />}
      drawer={
        managementOpen ? (
          <ManagementTokenDrawer record={managementOpen} onClose={() => setState({ mtoken: "" }, { history: "push" })} />
        ) : model.open ? (
          <TokenDrawer model={model} />
        ) : null
      }
      refetching={model.data.query.isFetching && !model.data.loading}
    >
      <List full>
        <section aria-labelledby={agentTokensHeading}>
          <GroupHeader id={agentTokensHeading} title="Agent tokens" count={`${model.shown.length} ${plural(model.shown.length, "token")}`} sticky={false} />
          <TokenTable model={model} label="Agent tokens" />
        </section>
        {!serviceAccount ? <ManagementTokens principal={props.principal} tokens={detail.data?.userTokens ?? []} /> : null}
        <ListFooter />
      </List>
    </PrincipalFrame>
  );
}

function CredentialsTab(props: TabProps) {
  const model = useCredentialList(adminSubject(props.principal.principalId));
  return (
    <PrincipalFrame
      {...props}
      toolbar={<CredentialToolbar model={model} />}
      drawer={model.open ? <CredentialDrawer model={model} /> : null}
      refetching={model.data.query.isFetching && !model.data.loading}
    >
      <List full>
        <CredentialRows model={model} />
      </List>
    </PrincipalFrame>
  );
}

function LimitsTab(props: TabProps) {
  const { identityAuthority } = writeAuthorities(useConfigStatus().data);
  return (
    <PrincipalFrame {...props} tint>
      <div className="pt-page">
        <ServiceLimitsTab principalId={props.principal.principalId} identityAuthority={identityAuthority} />
      </div>
    </PrincipalFrame>
  );
}

function ActivityTab(props: TabProps) {
  return <PrincipalActivity principalId={props.principal.principalId} frame={(parts) => <PrincipalFrame {...props} {...parts} />} />;
}
