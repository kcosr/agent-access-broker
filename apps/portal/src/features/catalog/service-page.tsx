// Admin › Catalog › a service: header with the service's identity and status,
// then tabs Actions · Managers · Limits · Import (imported services only).
import { useState } from "react";
import { Navigate, useParams } from "react-router";
import {
  AppLink,
  Badge,
  Button,
  EmptyState,
  ErrorState,
  LinkTabs,
  List,
  Main,
  PageHeader,
  SkeletonRows
} from "../../workbench";
import { paths, type ServiceTab } from "../../app/paths";
import { useImportPreview } from "../../data/queries";
import { adapterLabel, stateNeedsAttention, useCatalogServices, type CatalogService } from "./catalog-data";
import { CatalogFrame } from "./catalog-frame";
import { MetaLine } from "./catalog-ui";
import { ImportDialogs, ImportTab, type ImportDialog } from "./import-tab";
import { ActionDrawer, ActionsBanners, ActionsList, ActionsToolbar, useServiceActions } from "./service-actions";
import { LimitsTab } from "./service-limits";
import { ManagersBanners, ManagersList, ManagersToolbar, useServiceManagers } from "./service-managers";

const TABS: readonly ServiceTab[] = ["actions", "managers", "limits", "import"];

export function ServicePage() {
  const params = useParams();
  const serviceId = params.service ?? "";
  const tab = (params.tab ?? "actions") as ServiceTab;
  const index = useCatalogServices();
  const service = index.find(serviceId);
  const imported = Boolean(service?.imported);
  const preview = useImportPreview(serviceId, imported);
  // The j/k cursor and drawer belong to the Actions tab only.
  const actions = useServiceActions(tab === "actions" ? service : null);
  const managers = useServiceManagers(serviceId);
  const [dialog, setDialog] = useState<ImportDialog>(null);

  // Wait for the import list before deciding a service has no Import tab.
  if (!TABS.includes(tab) || (tab === "import" && !index.loading && index.imports && service && !imported)) {
    return <Navigate replace to={paths.catalogService(serviceId)} />;
  }
  const data = imported ? preview.data ?? null : null;
  const refetching = (index.fetching || (imported && preview.isFetching) || managers.query.isFetching) && !index.loading;
  const drawer = tab === "actions" && service ? <ActionDrawer model={actions} data={data} /> : null;

  let toolbar = null;
  let header = null;
  let body;
  if (index.loading) {
    body = (
      <List>
        <SkeletonRows />
      </List>
    );
  } else if (!service) {
    body = (
      <List>
        {index.error ? (
          <ErrorState error={index.error} onRetry={() => void index.refetch()} retrying={index.fetching} />
        ) : (
          <EmptyState
            icon="package"
            title="Service not found"
            actions={
              <Button icon="arrow-left" href={paths.catalog()}>
                All services
              </Button>
            }
          >
            <span className="wb-num">{serviceId}</span> is not a built-in or imported service.
          </EmptyState>
        )}
      </List>
    );
  } else if (tab === "actions") {
    toolbar = <ActionsToolbar model={actions} />;
    header = <ActionsBanners model={actions} />;
    body = (
      <ActionsList
        model={actions}
        data={data}
        retrying={Boolean(index.error) && index.fetching}
        error={index.error ? <ErrorState compact title="Couldn’t load the catalog" error={index.error} onRetry={() => void index.refetch()} retrying={index.fetching} /> : undefined}
      />
    );
  } else if (tab === "managers") {
    toolbar = <ManagersToolbar service={service} count={managers.managers.length} />;
    header = <ManagersBanners model={managers} />;
    body = <ManagersList service={service} model={managers} />;
  } else if (tab === "limits") {
    body = <LimitsTab service={service} data={data} onEdit={() => data && setDialog({ kind: "edit", data })} />;
  } else {
    body = <ImportTab service={service} query={preview} imports={index.imports} onDialog={setDialog} />;
  }

  return (
    <CatalogFrame section={{ kind: "services", service: serviceId }} drawer={drawer}>
      <Main
        label={service?.displayName ?? serviceId}
        tint={tab === "limits" || tab === "import"}
        refetching={refetching}
        header={header}
        toolbar={
          <>
            <ServiceHeader serviceId={serviceId} service={service} tab={tab} managerCount={managers.managers.length} />
            {toolbar}
          </>
        }
      >
        {body}
      </Main>
      {service && imported ? <ImportDialogs dialog={dialog} imports={index.imports} onDialog={setDialog} /> : null}
    </CatalogFrame>
  );
}

function ServiceHeader({ serviceId, service, tab, managerCount }: { serviceId: string; service: CatalogService | null; tab: ServiceTab; managerCount: number }) {
  const imported = service?.imported ?? null;
  const tabs = service
    ? [
        { href: paths.catalogService(serviceId), label: "Actions", current: tab === "actions", icon: "list" as const, count: service.actionCount },
        { href: paths.catalogService(serviceId, "managers"), label: "Managers", current: tab === "managers", icon: "users" as const, count: managerCount },
        { href: paths.catalogService(serviceId, "limits"), label: "Limits", current: tab === "limits", icon: "clock" as const },
        ...(imported ? [{ href: paths.catalogService(serviceId, "import"), label: "Import", current: tab === "import", icon: "download" as const }] : [])
      ]
    : [];
  return (
    <PageHeader
      back={{ href: paths.catalog(), label: "Catalog" }}
      title={service?.displayName ?? serviceId}
      meta={
        service ? (
          <MetaLine
            parts={[
              <span className="wb-num">{service.service}</span>,
              service.surface,
              imported ? (
                <Badge tone="neutral" icon="download">
                  Imported · {adapterLabel(imported.definition.adapterKind)}
                </Badge>
              ) : (
                <Badge tone="neutral" icon="package">
                  Built-in
                </Badge>
              ),
              <Badge tone={service.state.tone} icon={service.state.icon} title={service.state.reason ?? undefined}>
                {service.state.label}
              </Badge>,
              stateNeedsAttention(service.state) && service.state.reason ? <span className="wb-muted">{service.state.reason}</span> : null,
              <AppLink href={paths.policies({ service: service.service })} className="wb-link">
                View grants
              </AppLink>
            ]}
          />
        ) : null
      }
    >
      {tabs.length ? <LinkTabs label={`${service?.displayName ?? serviceId} sections`} items={tabs} /> : null}
    </PageHeader>
  );
}
