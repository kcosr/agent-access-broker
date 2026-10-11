import { AdminButton } from "../../components/admin-access";
// Admin › Catalog › All services: built-in and imported services with their
// status, action and manager counts; rows open the service page.
import { useMemo } from "react";
import {
  Banner,
  Button,
  type DataColumn,
  DataTable,
  EmptyState,
  ErrorState,
  FilterInput,
  List,
  ListFooter,
  Main,
  plural,
  Seg,
  type SortState,
  StateCell,
  TableGroupHeader,
  Toolbar,
  ToolbarRow,
  ToolbarSummary
} from "../../workbench";
import { GroupMenu } from "../../components/table-cells";
import { paths } from "../../app/paths";
import { groupRows, sortRows } from "../../lib/table-sort";
import { urlParam, useUrlState } from "../../lib/url-state";
import { adapterLabel, importBlocker, stateNeedsAttention, useCatalogServices, type CatalogService, type ServiceOrigin } from "./catalog-data";
import { CatalogFrame, useImportDialog } from "./catalog-frame";

const ORIGINS = ["all", "builtin", "imported"] as const;
const SORT_KEYS = ["name", "actions", "managers"] as const;
const GROUPINGS = ["none", "origin"] as const;

export const SERVICES_STATE = {
  origin: urlParam.oneOf(ORIGINS, "all"),
  sort: urlParam.sort(SORT_KEYS),
  group: urlParam.oneOf(GROUPINGS, "none"),
  q: urlParam.text()
};

const ORIGIN_GROUP: Record<ServiceOrigin, { title: string; sub: string; rank: number }> = {
  builtin: { title: "Built-in", sub: "backends compiled into the broker", rank: 0 },
  imported: { title: "Imported", sub: "MCP tools and OpenAPI operations", rank: 1 }
};

/** Rows open the service page, so Enter opens rather than showing details. */
const FOOTER_HINTS = [
  [["j", "k"], "move"],
  [["↵"], "open"],
  [["/"], "filter"]
] as const;

function originLabel(service: CatalogService) {
  return service.imported ? adapterLabel(service.imported.definition.adapterKind) : "Built-in";
}

function matches(service: CatalogService, query: string) {
  if (!query) return true;
  const text = [service.displayName, service.service, service.surface, service.state.label, service.imported ? adapterLabel(service.imported.definition.adapterKind) : "built-in"];
  return text.join(" ").toLowerCase().includes(query);
}

/** Services in table order: the chosen sort, else by name (the index order); regrouped by origin when grouped. */
function orderServices(services: CatalogService[], sort: SortState | null, grouped: boolean) {
  const sorted = sortRows(
    services,
    sort,
    (service, key) => (key === "name" ? service.displayName : key === "actions" ? service.actionCount : service.managerCount),
    () => 0
  );
  return grouped ? groupRows(sorted, (service) => service.origin, (a, b) => ORIGIN_GROUP[a as ServiceOrigin].rank - ORIGIN_GROUP[b as ServiceOrigin].rank) : sorted;
}

const COLUMNS: DataColumn<CatalogService>[] = [
  {
    key: "name",
    header: "Name",
    sortable: true,
    truncate: true,
    minWidth: "14ch",
    cell: (service) => service.displayName
  },
  {
    key: "id",
    header: "ID",
    priority: 3,
    className: "wb-cell-mono",
    hug: "22ch",
    cell: (service) => service.service
  },
  {
    key: "origin",
    header: "Origin",
    priority: 2,
    cell: (service) => originLabel(service)
  },
  {
    key: "surface",
    header: "Surface",
    priority: 4,
    className: "wb-cell-mono",
    cell: (service) => service.surface ?? <span className="wb-muted">—</span>
  },
  {
    key: "status",
    header: "Status",
    cell: (service) => <StateCell label={service.state.label} tone={service.state.tone} quiet={!stateNeedsAttention(service.state)} title={service.state.reason ?? undefined} />
  },
  {
    key: "actions",
    header: "Actions",
    sortable: true,
    firstSortDir: "desc",
    align: "end",
    cell: (service) => service.actionCount
  },
  {
    key: "managers",
    header: "Managers",
    sortable: true,
    firstSortDir: "desc",
    align: "end",
    priority: 3,
    cell: (service) => (service.managerCount ? service.managerCount : <span className="wb-muted">0</span>)
  }
];

export function ServicesPage() {
  const index = useCatalogServices();
  const [state, setState] = useUrlState(SERVICES_STATE);
  const dialog = useImportDialog();
  const query = state.q.trim().toLowerCase();
  const grouped = state.group === "origin";
  const shown = useMemo(
    () =>
      orderServices(
        index.services.filter((service) => (state.origin === "all" || service.origin === state.origin) && matches(service, query)),
        state.sort,
        grouped
      ),
    [index.services, state.origin, query, state.sort, grouped]
  );
  const counts = {
    all: index.services.length,
    builtin: index.services.filter((service) => service.origin === "builtin").length,
    imported: index.services.filter((service) => service.origin === "imported").length
  };
  const blocker = importBlocker(index.imports);
  const actionCount = shown.reduce((sum, service) => sum + service.actionCount, 0);
  const filtered = Boolean(state.q || state.origin !== "all");

  const empty =
    filtered && counts.all > 0 ? (
      <EmptyState
        compact
        icon="search"
        title="No matching services"
        actions={
          <Button icon="x" onClick={() => setState({ q: "", origin: "all" })}>
            Clear filters
          </Button>
        }
      >
        Try another origin or search.
      </EmptyState>
    ) : (
      <EmptyState
        compact
        icon="package"
        title={state.origin === "imported" ? "No imported services" : "No services"}
        actions={
          blocker ? null : (
            <AdminButton variant="primary" icon="plus" onClick={dialog.show}>
              Import service
            </AdminButton>
          )
        }
      >
        Import MCP tools or OpenAPI operations as actions: create a draft, configure credentials, then discover and review the upstream actions.
      </EmptyState>
    );

  return (
    <CatalogFrame section={{ kind: "services" }}>
      <Main
        label="Services"
        refetching={index.fetching && !index.loading}
        toolbar={
          <Toolbar>
            <ToolbarRow
              primary={
                <AdminButton variant="primary" icon="plus" onClick={dialog.show} disabled={blocker !== null} title={blocker ?? undefined}>
                  Import service
                </AdminButton>
              }
            >
              <Seg
                label="Service origin"
                value={state.origin}
                onChange={(origin) => setState({ origin })}
                options={[
                  { value: "all", label: "All", count: counts.all },
                  { value: "builtin", label: "Built-in", icon: "package", count: counts.builtin },
                  { value: "imported", label: "Imported", icon: "download", count: counts.imported }
                ]}
              />
              <FilterInput value={state.q} onChange={(q) => setState({ q })} placeholder="Filter services…" debounceMs={150} />
              <GroupMenu value={state.group} options={[{ value: "origin" as const, label: "Origin" }]} onChange={(group) => setState({ group })} />
              <ToolbarSummary grow>
                <b>{shown.length}</b> {plural(shown.length, "service")} · {actionCount} {plural(actionCount, "action")}
              </ToolbarSummary>
            </ToolbarRow>
          </Toolbar>
        }
        header={
          index.imports && !index.imports.operatorEnabled ? (
            <div className="pt-header-banners">
              <Banner tone="warning" slim>
                Imports are disabled by operator configuration. Retained services can be inspected, disabled or retired, and stored tokens can be deleted.
              </Banner>
            </div>
          ) : null
        }
      >
        <List full>
          <DataTable
            label="Services"
            rows={shown}
            rowId={(service) => service.service}
            columns={COLUMNS}
            sort={state.sort}
            onSortChange={(sort) => setState({ sort })}
            groupBy={grouped ? (service) => service.origin : undefined}
            groupHeader={({ key, rows }) => (
              <TableGroupHeader
                title={ORIGIN_GROUP[key as ServiceOrigin].title}
                sub={ORIGIN_GROUP[key as ServiceOrigin].sub}
                count={`${rows.length} ${plural(rows.length, "service")}`}
              />
            )}
            rowHref={(service) => paths.catalogService(service.service)}
            cursorResetKey={JSON.stringify([state.origin, state.q, state.sort, state.group])}
            rowDim={(service) => service.state.key === "disabled" || service.state.key === "retired"}
            loading={index.loading || (Boolean(index.error) && index.fetching)}
            error={index.error ? <ErrorState compact title="Couldn’t load the catalog" error={index.error} onRetry={() => void index.refetch()} retrying={index.fetching} /> : undefined}
            empty={empty}
            bleed
          />
          {shown.length > 0 ? <ListFooter hints={FOOTER_HINTS} /> : null}
        </List>
      </Main>
    </CatalogFrame>
  );
}
