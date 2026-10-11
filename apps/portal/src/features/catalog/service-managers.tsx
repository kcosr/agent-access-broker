import { AdminButton, AdminIconButton } from "../../components/admin-access";
// A service page's Managers tab: the accounts that manage every
// policy grant for the service. Global admins assign and revoke them. Rows
// open the account's page.
import { useMemo } from "react";
import type { ServicePolicyManagerAssignment } from "../../types";
import { identityDisplayName } from "../../lib/helpers";
import { sortRows } from "../../lib/table-sort";
import { urlParam, useUrlState } from "../../lib/url-state";
import { Banner, type DataColumn, DataTable, EmptyState, ErrorState, List, ListFooter, ListNote, plural, StateCell, Time, Toolbar, ToolbarRow, ToolbarSummary } from "../../workbench";
import { useModal } from "../../app/modal";
import { paths } from "../../app/paths";
import { useServicePolicyManagers } from "../../data/queries";
import { usePolicyActions } from "../../mutations/policy";
import type { CatalogService } from "./catalog-data";

const SORT_KEYS = ["holder", "assigned"] as const;

export const MANAGERS_STATE = {
  sort: urlParam.sort(SORT_KEYS)
};

/** Rows open the holder's page, so Enter opens rather than showing details. */
const FOOTER_HINTS = [
  [["j", "k"], "move"],
  [["↵"], "open"]
] as const;

function holderName(assignment: ServicePolicyManagerAssignment) {
  return identityDisplayName(assignment.displayName) || assignment.principalId;
}

export function useServiceManagers(service: string) {
  const query = useServicePolicyManagers();
  const [state, setState] = useUrlState(MANAGERS_STATE);
  const managers = useMemo(
    () =>
      sortRows(
        (query.data ?? []).filter((assignment) => assignment.service === service),
        state.sort,
        (assignment, key) => (key === "holder" ? holderName(assignment) : assignment.createdAt),
        (a, b) => holderName(a).localeCompare(holderName(b)) || a.principalId.localeCompare(b.principalId)
      ),
    [query.data, service, state.sort]
  );
  return { query, managers, state, setState, loading: query.isPending && query.fetchStatus !== "idle" };
}

type ManagersModel = ReturnType<typeof useServiceManagers>;

export function ManagersToolbar({ service, count }: { service: CatalogService; count: number }) {
  const { setModal } = useModal();
  return (
    <Toolbar>
      <ToolbarRow>
        <ToolbarSummary grow>
          <b>{count}</b> service policy {plural(count, "manager")} for {service.displayName}
        </ToolbarSummary>
        <AdminButton variant="primary" icon="plus" onClick={() => setModal({ type: "assignManager", service: service.service })}>
          Assign manager
        </AdminButton>
      </ToolbarRow>
    </Toolbar>
  );
}

/** Attention banners above the managers table. */
export function ManagersBanners({ model }: { model: ManagersModel }) {
  if (!model.managers.some((assignment) => !assignment.serviceConfigured)) return null;
  return (
    <div className="pt-header-banners">
      <Banner tone="warning" slim>
        This service is not configured right now. Assignments are kept and apply again when it returns.
      </Banner>
    </div>
  );
}

function holderHref(assignment: ServicePolicyManagerAssignment) {
  return paths.principal(assignment.principalId);
}

export function ManagersList({ service, model }: { service: CatalogService; model: ManagersModel }) {
  const { query, managers, loading, state, setState } = model;
  const { setModal } = useModal();
  const policy = usePolicyActions();
  const columns = useMemo<DataColumn<ServicePolicyManagerAssignment>[]>(
    () => [
      {
        key: "holder",
        header: "Account",
        sortable: true,
        truncate: true,
        minWidth: "16ch",
        cell: holderName
      },
      {
        key: "id",
        header: "ID",
        priority: 3,
        className: "wb-cell-mono",
        hug: "30ch",
        cell: (assignment) => assignment.principalId
      },
      {
        key: "status",
        header: "Status",
        cell: (assignment) => {
          const status = assignment.principalStatus;
          const label = status ? status.charAt(0).toUpperCase() + status.slice(1) : "Unknown";
          return <StateCell label={label} tone={status === "active" ? "success" : "muted"} quiet={status === "active"} />;
        }
      },
      {
        key: "assigned",
        header: "Assigned",
        sortable: true,
        firstSortDir: "desc",
        priority: 2,
        cell: (assignment) => <Time value={assignment.createdAt} />
      },
      {
        key: "by",
        header: "By",
        priority: 3,
        className: "wb-cell-mono",
        hug: "22ch",
        cell: (assignment) => assignment.createdBy
      },
      {
        key: "row-actions",
        header: <span className="wb-sr-only">Row actions</span>,
        className: "wb-cell-actions",
        cell: (assignment) => (
          <div className="wb-row-actions">
            <AdminIconButton
              size="sm"
              icon="trash"
              label={`Revoke ${assignment.principalId}`}
              onClick={() => policy.confirmRevokeManager(service.service, assignment.principalId)}
            />
          </div>
        )
      }
    ],
    [policy, service.service]
  );
  return (
    <List full>
      <DataTable
        label={`${service.displayName} service policy managers`}
        rows={managers}
        rowId={(assignment) => assignment.assignmentId}
        columns={columns}
        sort={state.sort}
        onSortChange={(sort) => setState({ sort })}
        rowHref={holderHref}
        cursorResetKey={JSON.stringify(state.sort)}
        rowDim={(assignment) => assignment.principalStatus !== "active"}
        loading={loading || (query.isError && query.isFetching)}
        skeletonRows={3}
        error={
          query.isError ? (
            <ErrorState compact title="Couldn’t load service managers" error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} />
          ) : undefined
        }
        empty={
          <EmptyState
            compact
            icon="users"
            title="No service policy managers"
            actions={
              <AdminButton variant="primary" icon="plus" onClick={() => setModal({ type: "assignManager", service: service.service })}>
                Assign manager
              </AdminButton>
            }
          >
            Only global administrators manage grants for {service.displayName}.
          </EmptyState>
        }
        bleed
      />
      {managers.length > 0 ? <ListFooter hints={FOOTER_HINTS} /> : null}
      <ListNote>
        Service policy managers manage every grant for {service.displayName}: granting access to themselves or anyone else, and authorizing configured service credentials
        without seeing the secrets. Grants they created stay in place when they are revoked.
      </ListNote>
    </List>
  );
}
