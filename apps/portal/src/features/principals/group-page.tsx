import { AdminButton, AdminForm, AdminIconButton } from "../../components/admin-access";
// Admin › Principals › a group: header and URL-driven tabs (Overview,
// Members, Grants, and Microsoft mappings when Microsoft sign-in is configured).
import { useEffect, useState, type ReactNode } from "react";
import { useLocation, useParams } from "react-router";
import type { ExternalGroupBinding, GroupDetail, GroupMemberRecord } from "../../types";
import { errorMessage, identityDisplayName, principalIdentityLabel } from "../../lib/helpers";
import { urlParam, urlStateSearch, useUrlState } from "../../lib/url-state";
import { sortRows } from "../../lib/table-sort";
import { MembershipSource } from "./principal-groups";
import {
  Badge,
  Banner,
  Button,
  Combobox,
  type DataColumn,
  DataTable,
  EmptyState,
  ErrorState,
  findRowTarget,
  IconButton,
  Input,
  KeyValue,
  LinkTabs,
  List,
  Main,
  PageHeader,
  plural,
  SettingsPage,
  SettingsRow,
  SettingsSection,
  SkeletonBlock,
  StateCell,
  Textarea,
  Time,
  Toolbar,
  ToolbarRow,
  ToolbarSummary,
  useToast
} from "../../workbench";
import { FormError } from "../../components/form";
import { useActionRunner } from "../../app/actions";
import { paths, type GroupTab } from "../../app/paths";
import { useSession } from "../../app/session";
import { PortalPage } from "../../app/top-bar";
import { NotFoundPage } from "../../app/gate";
import {
  useAdminGroup,
  useAdminPrincipals,
  useConfigStatus,
  useExternalGroupBindings,
  usePolicyCatalog,
  usePolicyGrants,
  usePolicyStatus,
  writeAuthorities
} from "../../data/queries";
import { useGroupActions } from "../../mutations/groups";
import { GrantDrawer } from "../policies/policies-page";
import { GrantReferences, GrantReferencesToolbar, referenceRows } from "./policy-references";

const GRANT_STATE = { grant: urlParam.text() };
const MEMBER_STATE = { sort: urlParam.sort(["name", "id"]) };

export function GroupPage() {
  const { session } = useSession();
  const { groupId = "", tab = "overview" } = useParams();
  const query = useAdminGroup(groupId);
  const microsoft = Boolean(session.loginOptions?.microsoft?.enabled);
  const tabs: GroupTab[] = ["overview", "members", "grants", ...(microsoft ? (["microsoft"] as const) : [])];
  if (!tabs.includes(tab as GroupTab)) return <NotFoundPage />;
  if (query.isPending || query.isError || !query.data) {
    return (
      <PortalPage>
        <Main label="Group">
          <List>
            {query.isPending ? (
              <SkeletonBlock lines={6} />
            ) : query.isError && !/not.found|404/i.test(String(query.error)) ? (
              <ErrorState error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} />
            ) : (
              <EmptyState
                icon="users"
                title="Group not found"
                actions={
                  <Button href={paths.principals("groups")} icon="arrow-left">
                    Back to groups
                  </Button>
                }
              >
                {groupId} does not exist.
              </EmptyState>
            )}
          </List>
        </Main>
      </PortalPage>
    );
  }
  const props = { group: query.data, tab: tab as GroupTab, tabs };
  if (tab === "members") return <MembersTab {...props} />;
  if (tab === "grants") return <GrantsTab {...props} />;
  if (tab === "microsoft") return <MicrosoftTab {...props} />;
  return <OverviewTab {...props} />;
}

type TabProps = { group: GroupDetail; tab: GroupTab; tabs: GroupTab[] };

const TAB_LABEL: Record<GroupTab, string> = { overview: "Overview", members: "Members", grants: "Grants", microsoft: "Microsoft mappings" };

function GroupFrame({ group, tab, tabs, toolbar, drawer, tint = false, children }: TabProps & { toolbar?: ReactNode; drawer?: ReactNode; tint?: boolean; children: ReactNode }) {
  const groups = useGroupActions();
  const { groupWritesEnabled } = writeAuthorities(useConfigStatus().data);
  const runner = useActionRunner();
  const name = identityDisplayName(group.displayName);
  const active = group.status === "active";
  const grantCount = referenceRows(group.policyReferenceSections).length;
  return (
    <PortalPage drawer={drawer}>
      <Main
        label={name || group.groupId}
        tint={tint}
        toolbar={
          <PageHeader
            back={{ href: paths.principals("groups"), label: "Groups" }}
            title={name || group.groupId}
            meta={
              <>
                <Badge variant="outline">Group</Badge>
                <Badge tone={active ? "success" : "muted"} variant="dot">
                  {group.status}
                </Badge>
                <span className="wb-num">{group.groupId}</span>
                <span className="wb-sep">·</span>
                <span>
                  {group.memberCount} {plural(group.memberCount, "member")}
                </span>
              </>
            }
            actions={
              <>
                <AdminButton
                  icon="plus"
                  href={paths.grantNew({ subject: `group:${group.groupId}`, returnTo: paths.group(group.groupId, "grants") })}
                >
                  Create grant
                </AdminButton>
                <AdminButton
                  variant={active ? "danger-ghost" : "default"}
                  icon={active ? "pause" : "play"}
                  disabled={!groupWritesEnabled}
                  pending={runner.isPending("status")}
                  onClick={() => (active ? groups.confirmDisable(group.groupId) : void runner.run("status", () => groups.patch(group.groupId, { status: "active" })))}
                >
                  {active ? "Disable" : "Enable"}
                </AdminButton>
              </>
            }
          >
            <LinkTabs
              label="Group sections"
              items={tabs.map((item) => ({
                href: paths.group(group.groupId, item),
                label: TAB_LABEL[item],
                current: item === tab,
                count: item === "members" ? group.memberCount : item === "grants" ? grantCount : undefined
              }))}
            />
          </PageHeader>
        }
        header={toolbar}
      >
        {children}
      </Main>
    </PortalPage>
  );
}

function OverviewTab(props: TabProps) {
  const { group } = props;
  const groups = useGroupActions();
  const { groupWritesEnabled, identityAuthority } = writeAuthorities(useConfigStatus().data);
  const [displayName, setDisplayName] = useState(group.displayName ?? "");
  const [description, setDescription] = useState(group.description ?? "");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setDisplayName(group.displayName ?? "");
    setDescription(group.description ?? "");
  }, [group.groupId, group.displayName, group.description]);
  const dirty = displayName !== (group.displayName ?? "") || description !== (group.description ?? "");
  return (
    <GroupFrame {...props} tint>
      <SettingsPage>
        {!groupWritesEnabled && identityAuthority !== "unknown" ? (
          <Banner tone="warning" slim>
            Group writes are unavailable while identity authority is {identityAuthority}.
          </Banner>
        ) : null}
        <SettingsSection title="Profile">
          <AdminForm
            onSubmit={async (event) => {
              event.preventDefault();
              setPending(true);
              setError(null);
              try {
                await groups.patch(group.groupId, { displayName: displayName || null, description: description || null });
              } catch (failure) {
                setError(errorMessage(failure));
              } finally {
                setPending(false);
              }
            }}
          >
            <SettingsRow label="Group ID" help="The stable identifier grants refer to.">
              <span className="wb-num">{group.groupId}</span>
            </SettingsRow>
            <SettingsRow label="Display name">
              <Input className="flex-1" value={displayName} onChange={(event) => setDisplayName(event.target.value)} disabled={!groupWritesEnabled} />
            </SettingsRow>
            <SettingsRow label="Description" alignTop>
              <Textarea className="flex-1" rows={3} value={description} onChange={(event) => setDescription(event.target.value)} disabled={!groupWritesEnabled} />
            </SettingsRow>
            <FormError error={error} />
            <div className="wb-settings-actions">
              <AdminButton type="submit" variant="primary" disabled={!groupWritesEnabled || !dirty} pending={pending}>
                Save group
              </AdminButton>
            </div>
          </AdminForm>
        </SettingsSection>
        <SettingsSection title="History">
          <KeyValue
            items={[
              { label: "Members", value: group.memberCount },
              group.createdAt ? { label: "Created", value: <><Time value={group.createdAt} format="datetime" />{group.createdBy ? <span className="wb-muted"> by {group.createdBy}</span> : null}</> } : null,
              group.updatedAt ? { label: "Updated", value: <><Time value={group.updatedAt} format="datetime" />{group.updatedBy ? <span className="wb-muted"> by {group.updatedBy}</span> : null}</> } : null
            ]}
          />
        </SettingsSection>
      </SettingsPage>
    </GroupFrame>
  );
}

function MembersTab(props: TabProps) {
  const { group } = props;
  const groups = useGroupActions();
  const principals = useAdminPrincipals().data ?? [];
  const { groupWritesEnabled, identityAuthority } = writeAuthorities(useConfigStatus().data);
  const [member, setMember] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [state, setState] = useUrlState(MEMBER_STATE);
  const memberName = (item: GroupMemberRecord) => identityDisplayName(item.displayName) || item.principalId;
  const members = sortRows(
    group.members,
    state.sort,
    (item, key) => (key === "id" ? item.principalId : memberName(item)),
    (a, b) => memberName(a).localeCompare(memberName(b)) || a.principalId.localeCompare(b.principalId)
  );
  const columns: DataColumn<GroupMemberRecord>[] = [
    {
      key: "status",
      header: "Status",
      cell: (item) => {
        const status = item.status ?? "active";
        return <StateCell label={status === "active" ? "Active" : status[0]!.toUpperCase() + status.slice(1)} tone={status === "active" ? "success" : "muted"} quiet={status === "active"} />;
      }
    },
    { key: "name", header: "Name", primary: true, sortable: true, truncate: true, minWidth: "16ch", cell: memberName },
    { key: "id", header: "Principal ID", sortable: true, priority: 2, truncate: true, minWidth: "12ch", className: "wb-cell-mono", cell: (item) => item.principalId },
    {
      key: "kind",
      header: "Kind",
      priority: 3,
      cell: (item) => (item.kind === "service_account" ? "Service account" : item.kind === "system" ? "System" : "User")
    },
    { key: "email", header: "Email", priority: 4, truncate: true, minWidth: "12ch", cell: (item) => item.email ?? "" },
    { key: "source", header: "Source", cell: (item) => <MembershipSource membership={item.membership} /> },
    {
      key: "added",
      header: "Added",
      priority: 3,
      cell: (item) => (item.membership?.local ? <Time value={item.membership.local.addedAt} /> : null)
    },
    {
      key: "remove",
      header: <span className="wb-sr-only">Row actions</span>,
      className: "wb-cell-actions",
      cell: (item) =>
        item.membership?.local ? (
          <div className="wb-row-actions">
            <AdminIconButton
              size="sm"
              icon="x"
              label={`Remove ${item.principalId}`}
              disabled={!groupWritesEnabled}
              onClick={() => groups.confirmRemoveMember(group.groupId, item.principalId)}
            />
          </div>
        ) : null
    }
  ];
  const local = new Set(group.members.filter((item) => item.membership?.local).map((item) => item.principalId));
  const available = principals.filter((principal) => !local.has(principal.principalId));
  const toolbar = (
    <Toolbar>
      <ToolbarRow>
        <AdminForm
          className="flex flex-1 flex-wrap items-center gap-2"
          onSubmit={async (event) => {
            event.preventDefault();
            if (!member) return;
            setPending(true);
            setError(null);
            try {
              await groups.addMember(group.groupId, member);
              setMember(null);
            } catch (failure) {
              setError(errorMessage(failure));
            } finally {
              setPending(false);
            }
          }}
        >
          <div className="min-w-72">
            <Combobox
              aria-label="Principal to add"
              placeholder={groupWritesEnabled ? "Add a member…" : `Read-only under ${identityAuthority} identity authority`}
              value={member}
              onChange={setMember}
              allowCustom
              disabled={!groupWritesEnabled}
              options={available.map((principal) => ({ value: principal.principalId, label: principalIdentityLabel(principal.principalId, principal.displayName || principal.email) }))}
            />
          </div>
          <AdminButton type="submit" icon="plus" disabled={!member} pending={pending}>
            Add member
          </AdminButton>
          <FormError error={error} />
        </AdminForm>
        <ToolbarSummary>
          <b>{group.members.length}</b> {plural(group.members.length, "member")}
        </ToolbarSummary>
      </ToolbarRow>
    </Toolbar>
  );
  return (
    <GroupFrame {...props} toolbar={toolbar}>
      <List full>
        <DataTable
          label="Members"
          rows={members}
          rowId={(item) => item.principalId}
          columns={columns}
          rowHref={(item) => paths.principal(item.principalId)}
          rowDim={(item) => Boolean(item.status && item.status !== "active")}
          sort={state.sort}
          onSortChange={(sort) => setState({ sort })}
          cursorResetKey={`${state.sort?.key ?? ""}:${state.sort?.dir ?? ""}`}
          empty={<EmptyState compact icon="users" title="No members" />}
          bleed
        />
      </List>
    </GroupFrame>
  );
}

function GrantsTab(props: TabProps) {
  const { group } = props;
  const catalog = usePolicyCatalog().data ?? null;
  const grants = usePolicyGrants();
  const status = usePolicyStatus().data;
  const location = useLocation();
  const [state, setState] = useUrlState(GRANT_STATE);
  const open = state.grant ? grants.data?.find((grant) => grant.grantRef === state.grant) ?? null : null;
  const count = referenceRows(group.policyReferenceSections).length;
  return (
    <GroupFrame
      {...props}
      toolbar={<GrantReferencesToolbar subject={`group:${group.groupId}`} writable={Boolean(status?.writable)} policyAuthority={status?.policyAuthority ?? "unknown"} count={count} />}
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
          sections={group.policyReferenceSections}
          grants={grants.data ?? []}
          catalog={catalog}
          writable={Boolean(status?.writable)}
          grantHref={(grantRef) => `${location.pathname}${urlStateSearch(GRANT_STATE, location.search, { grant: state.grant === grantRef ? "" : grantRef })}`}
          openGrant={state.grant || null}
          onFollow={(grantRef) => setState({ grant: grantRef }, { history: "replace" })}
        />
      </List>
    </GroupFrame>
  );
}

function MicrosoftTab(props: TabProps) {
  const { group } = props;
  const groups = useGroupActions();
  const config = useConfigStatus().data;
  const { groupWritesEnabled, identityAuthority } = writeAuthorities(config);
  const bindings = useExternalGroupBindings(group.groupId, identityAuthority === "managed");
  const runner = useActionRunner();
  const toast = useToast();
  const [objectId, setObjectId] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const rows: ExternalGroupBinding[] = bindings.data ?? [];
  const toolbar = (
    <Toolbar>
      <ToolbarRow>
        <AdminForm
          className="flex flex-1 flex-wrap items-center gap-2"
          onSubmit={async (event) => {
            event.preventDefault();
            if (!objectId.trim()) return;
            setPending(true);
            setError(null);
            try {
              await groups.createMapping(group.groupId, objectId.trim());
              setObjectId("");
            } catch (failure) {
              setError(errorMessage(failure));
            } finally {
              setPending(false);
            }
          }}
        >
          <Input
            mono
            className="min-w-80"
            aria-label="Microsoft Group Object ID"
            placeholder="00000000-0000-0000-0000-000000000000"
            value={objectId}
            onChange={(event) => setObjectId(event.target.value)}
            disabled={!groupWritesEnabled}
          />
          <AdminButton type="submit" icon="plus" disabled={!groupWritesEnabled || !objectId.trim()} pending={pending}>
            Create mapping
          </AdminButton>
          <FormError error={error} />
        </AdminForm>
      </ToolbarRow>
    </Toolbar>
  );
  return (
    <GroupFrame {...props} toolbar={toolbar}>
      <div className="pt-header-banners">
        <Banner tone="warning" slim>
          Enabling a mapping lets future eligible Microsoft sign-ins receive this broker group and its existing grants.
        </Banner>
      </div>
      <List full>
        {identityAuthority !== "managed" ? (
          <EmptyState icon="users" title="Mappings need managed identity">
            Microsoft group mappings are available when identity authority is managed.
          </EmptyState>
        ) : (
          <DataTable
            label="Microsoft group mappings"
            rows={rows}
            rowId={(binding) => binding.bindingId}
            columns={[
              {
                key: "status",
                header: "Status",
                cell: (binding) => <StateCell label={binding.status === "active" ? "Active" : "Disabled"} tone={binding.status === "active" ? "success" : "muted"} quiet={binding.status === "active"} />
              },
              {
                key: "object",
                header: "Microsoft group Object ID",
                primary: true,
                className: "wb-cell-mono",
                cell: (binding) => binding.externalGroupId
              },
              {
                key: "updated",
                header: "Updated",
                priority: 2,
                cell: (binding) => <Time value={binding.updatedAt} />
              },
              { key: "by", header: "By", priority: 3, truncate: true, minWidth: "10ch", cell: (binding) => binding.updatedBy },
              {
                key: "row-actions",
                header: <span className="wb-sr-only">Row actions</span>,
                className: "wb-cell-actions",
                cell: (binding) => (
                  <span className="wb-btn-group">
                    <IconButton
                      size="sm"
                      icon="copy"
                      label={`Copy Microsoft group Object ID ${binding.externalGroupId}`}
                      onClick={() => void navigator.clipboard.writeText(binding.externalGroupId).then(() => toast("Object ID copied"))}
                    />
                    <AdminButton
                      size="sm"
                      disabled={!groupWritesEnabled}
                      pending={runner.isPending(binding.bindingId)}
                      onClick={() =>
                        void runner.run(binding.bindingId, () => groups.setMappingStatus(group.groupId, binding.bindingId, binding.status === "active" ? "disabled" : "active"))
                      }
                    >
                      {binding.status === "active" ? "Disable" : "Enable"}
                    </AdminButton>
                    <AdminIconButton
                      size="sm"
                      icon="trash"
                      label={`Delete mapping ${binding.externalGroupId}`}
                      title={binding.status === "active" ? "Disable before deleting" : "Delete mapping"}
                      disabled={!groupWritesEnabled || binding.status === "active"}
                      onClick={() => groups.confirmDeleteMapping(group.groupId, binding.bindingId)}
                    />
                  </span>
                )
              }
            ]}
            rowDim={(binding) => binding.status !== "active"}
            loading={bindings.isPending || (bindings.isError && bindings.isFetching)}
            error={
              bindings.isError ? (
                <ErrorState compact title="Couldn’t load Microsoft mappings" error={bindings.error} onRetry={() => void bindings.refetch()} retrying={bindings.isFetching} />
              ) : undefined
            }
            empty={
              <EmptyState compact icon="link" title="No Microsoft group mappings">
                Create a mapping with a Microsoft group Object ID.
              </EmptyState>
            }
            bleed
          />
        )}
      </List>
    </GroupFrame>
  );
}
