import { AdminForm, AdminButton, AdminIconButton } from "../../components/admin-access";
// User page › Groups: local and Microsoft-derived memberships.
import { useMemo, useState } from "react";
import type { GroupMembershipProvenance, GroupRecord, PrincipalDetail } from "../../types";
import { errorMessage, formatGroupOption, identityDisplayName } from "../../lib/helpers";
import { Badge, Combobox, type DataColumn, DataTable, EmptyState, formatDateTime, plural, StateCell, Time, Toolbar, ToolbarRow, ToolbarSummary } from "../../workbench";
import { FormError } from "../../components/form";
import { paths } from "../../app/paths";
import { usePrincipalActions } from "../../mutations/principals";

export function PrincipalGroupsToolbar({
  principal,
  groups,
  groupWritesEnabled,
  identityAuthority
}: {
  principal: PrincipalDetail;
  groups: GroupRecord[];
  groupWritesEnabled: boolean;
  identityAuthority: string;
}) {
  const principals = usePrincipalActions();
  const [group, setGroup] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const local = new Set(principal.groupMemberships.filter((membership) => membership.local).map((membership) => membership.groupId));
  const available = groups.filter((item) => !local.has(item.groupId));
  return (
    <Toolbar>
      <ToolbarRow>
        <AdminForm
          className="flex flex-1 flex-wrap items-center gap-2"
          onSubmit={async (event) => {
            event.preventDefault();
            if (!group) return;
            setPending(true);
            setError(null);
            try {
              await principals.addGroup(principal.principalId, group);
              setGroup(null);
            } catch (failure) {
              setError(errorMessage(failure));
            } finally {
              setPending(false);
            }
          }}
        >
          <div className="min-w-72">
            <Combobox
              aria-label="Group"
              placeholder={groupWritesEnabled ? (available.length ? "Add to a group…" : "No other groups") : `Read-only under ${identityAuthority} identity authority`}
              value={group}
              onChange={setGroup}
              disabled={!groupWritesEnabled || available.length === 0}
              options={available.map((item) => ({ value: item.groupId, label: formatGroupOption(item), disabled: item.status !== "active" }))}
            />
          </div>
          <AdminButton type="submit" icon="plus" disabled={!group} pending={pending}>
            Add group
          </AdminButton>
          <FormError error={error} />
        </AdminForm>
        <ToolbarSummary>
          <b>{principal.groupMemberships.length}</b> {plural(principal.groupMemberships.length, "group")}
        </ToolbarSummary>
      </ToolbarRow>
    </Toolbar>
  );
}

/** Where a membership comes from: Local and/or Microsoft, with the Microsoft evidence on hover. */
export function MembershipSource({ membership }: { membership: GroupMembershipProvenance | null | undefined }) {
  if (!membership) return null;
  const microsoft = membership.microsoft
    .map((source) => `${source.externalGroupId}: observed ${formatDateTime(source.observedAt)}, valid until ${formatDateTime(source.validUntil)}${source.current ? "" : " (expired)"}`)
    .join("\n");
  return (
    <>
      {membership.local ? (
        <Badge variant="outline" title={`Added ${formatDateTime(membership.local.addedAt)} by ${membership.local.addedBy}`}>
          Local
        </Badge>
      ) : null}
      {membership.local && membership.microsoft.length ? " " : null}
      {membership.microsoft.length ? (
        <Badge variant="outline" title={microsoft}>
          Microsoft
        </Badge>
      ) : null}
      {!membership.local && !membership.microsoft.length ? <span className="wb-muted">{membership.source}</span> : null}
    </>
  );
}

export function PrincipalGroups({ principal, groups, groupWritesEnabled }: { principal: PrincipalDetail; groups: GroupRecord[]; groupWritesEnabled: boolean }) {
  const principals = usePrincipalActions();
  const byId = useMemo(() => new Map(groups.map((group) => [group.groupId, group])), [groups]);
  const columns = useMemo<DataColumn<GroupMembershipProvenance>[]>(
    () => [
      {
        key: "effective",
        header: "Status",
        cell: (membership) => <StateCell label={membership.effective ? "Effective" : "Not effective"} tone={membership.effective ? "success" : "muted"} quiet={membership.effective} />
      },
      {
        key: "group",
        header: "Group",
        primary: true,
        truncate: true,
        minWidth: "16ch",
        cell: (membership) => identityDisplayName(byId.get(membership.groupId)?.displayName) || membership.groupId
      },
      {
        key: "id",
        header: "Group ID",
        priority: 2,
        truncate: true,
        minWidth: "12ch",
        className: "wb-cell-mono",
        cell: (membership) => membership.groupId
      },
      {
        key: "source",
        header: "Source",
        cell: (membership) => <MembershipSource membership={membership} />
      },
      {
        key: "added",
        header: "Added",
        priority: 3,
        cell: (membership) =>
          membership.local ? (
            <Time value={membership.local.addedAt} />
          ) : membership.microsoft[0] ? (
            <span title="Observed at the last Microsoft sign-in">
              <Time value={membership.microsoft[0].observedAt} />
            </span>
          ) : null
      },
      {
        key: "remove",
        header: <span className="wb-sr-only">Row actions</span>,
        className: "wb-cell-actions",
        cell: (membership) =>
          membership.local ? (
            <div className="wb-row-actions">
              <AdminIconButton
                size="sm"
                icon="x"
                label={`Remove ${membership.groupId}`}
                disabled={!groupWritesEnabled}
                onClick={() => principals.confirmRemoveGroup(principal.principalId, membership.groupId)}
              />
            </div>
          ) : null
      }
    ],
    [byId, groupWritesEnabled, principals, principal.principalId]
  );
  return (
    <DataTable
      label="Group memberships"
      rows={principal.groupMemberships}
      rowId={(membership) => membership.groupId}
      columns={columns}
      rowHref={(membership) => paths.group(membership.groupId)}
      rowDim={(membership) => !membership.effective}
      empty={<EmptyState compact icon="users" title="Not a member of any group" />}
      bleed
    />
  );
}
