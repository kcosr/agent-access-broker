import { canWriteAdmin } from "../../lib/capabilities";
// The frame every Catalog page shares: the Catalog sidebar (services,
// resources, resource groups) and the Import service dialog, which opens from
// `?import=1` on any Catalog page (the command palette links there).
import { useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router";
import { Sidebar, SidebarItem, SidebarSection, SkeletonSidebar, StatusDot } from "../../workbench";
import { PortalPage } from "../../app/top-bar";
import { paths } from "../../app/paths";
import { useSession } from "../../app/session";
import { urlParam, useUrlState } from "../../lib/url-state";
import { useResourceCatalog } from "../../data/queries";
import { stateNeedsAttention, useCatalogServices, type CatalogIndex } from "./catalog-data";
import { ImportEditor } from "./import-editor";
import { useImportActions } from "./import-actions";
import { ImportDocumentModal } from "./import-document-modal";
import type { ImportRecordResult } from "../../import-types";
import type { OpenApiDocumentFile } from "../../lib/import-document";
import { errorMessage } from "../../lib/helpers";
import { brokerApi } from "../../api";
import "./catalog.css";

export type CatalogSection = { kind: "services"; service?: string } | { kind: "resources" } | { kind: "groups" };

const IMPORT_STATE = { import: urlParam.flag() };

/** Opens and closes the Import service dialog through the URL. */
export function useImportDialog() {
  const [state, setState] = useUrlState(IMPORT_STATE);
  const { session } = useSession();
  return {
    open: state.import && canWriteAdmin(session),
    show: () => setState({ import: true }, { history: "push" }),
    close: () => setState({ import: false })
  };
}

export function CatalogFrame({ section, drawer, children }: { section: CatalogSection; drawer?: ReactNode; children: ReactNode }) {
  const index = useCatalogServices();
  const dialog = useImportDialog();
  return (
    <PortalPage sidebar={<CatalogSidebar index={index} section={section} onImport={dialog.show} />} drawer={drawer}>
      {children}
      {dialog.open ? <NewImportDialog index={index} onClose={dialog.close} /> : null}
    </PortalPage>
  );
}

function CatalogSidebar({ index, section, onImport }: { index: CatalogIndex; section: CatalogSection; onImport: () => void }) {
  const resources = useResourceCatalog().data;
  const { session } = useSession();
  const current = section.kind === "services" ? section.service ?? "" : null;
  return (
    <Sidebar label="Catalog">
      <SidebarSection title="Services" action={canWriteAdmin(session) ? { label: "Import service", icon: "plus", onClick: onImport } : undefined}>
        <SidebarItem icon="layers" label="All services" count={index.loading ? undefined : index.services.length} current={current === ""} href={paths.catalog()} />
        {index.loading ? (
          <SkeletonSidebar lines={6} />
        ) : (
          index.services.map((service) => (
            <SidebarItem
              key={service.service}
              icon={service.origin === "imported" ? "download" : "package"}
              label={service.displayName}
              title={`${service.service} · ${service.origin === "imported" ? "imported" : "built-in"} · ${service.state.label.toLowerCase()}`}
              count={service.actionCount}
              current={current === service.service}
              href={paths.catalogService(service.service)}
              trailing={stateNeedsAttention(service.state) ? <StatusDot tone={service.state.tone} label={service.state.label} /> : undefined}
            />
          ))
        )}
      </SidebarSection>
      <SidebarSection title="Resources">
        <SidebarItem icon="database" label="Resources" count={resources?.resources.length} current={section.kind === "resources"} href={paths.resources()} />
        <SidebarItem icon="layers" label="Resource groups" count={resources?.resourceGroups.length} current={section.kind === "groups"} href={paths.resourceGroups()} />
      </SidebarSection>
    </Sidebar>
  );
}

/** Import service: create a draft, then continue on its Import tab. */
function NewImportDialog({ index, onClose }: { index: CatalogIndex; onClose: () => void }) {
  const { session, runQuery } = useSession();
  const actions = useImportActions();
  const navigate = useNavigate();
  // After creating, the draft's page replaces this URL; closing must not rewrite it.
  const created = useRef(false);
  const [uploadRetry, setUploadRetry] = useState<{ data: ImportRecordResult; file: OpenApiDocumentFile; error: string } | null>(null);
  const imports = index.imports;
  const openDraft = (data: ImportRecordResult) => navigate(paths.catalogService(data.service.definition.service, "import"), { replace: true });
  if (uploadRetry) return <ImportDocumentModal
    data={uploadRetry.data}
    initialFile={uploadRetry.file}
    initialError={uploadRetry.error}
    notice={<>Draft <span className="wb-mono">{uploadRetry.data.service.definition.service}</span> was created. Open it to check its document and preview, or reload its current state before retrying the selected file.</>}
    closeLabel="Open draft"
    onReload={async () => {
      const current = await runQuery((session) => brokerApi.importPreview(session, uploadRetry.data.service.definition.service));
      setUploadRetry((previous) => previous ? { ...previous, data: current } : previous);
    }}
    // The administrator sees this snapshot before explicitly retrying; never silently advance its fences.
    onUpload={(file) => actions.uploadDocument(uploadRetry.data, file)}
    onUploaded={() => openDraft(uploadRetry.data)}
    onClose={() => openDraft(uploadRetry.data)}
  />;
  return (
    <ImportEditor
      principal={session.principal ?? ""}
      authentication={imports?.importAuthentication ?? []}
      availableKinds={imports?.availableKinds ?? []}
      commandImports={imports?.commandImports.map((entry) => entry.name) ?? []}
      operatorEnabled={imports?.operatorEnabled ?? false}
      onClose={() => {
        if (!created.current) onClose();
      }}
      onSave={async (definition, _confirmed, document) => {
        const result = await actions.create(definition);
        created.current = true;
        if (document) {
          try {
            await actions.uploadDocument(result, document.file);
          } catch (failure) {
            // The first mutation succeeded. Retrying here must never create a second draft.
            setUploadRetry({ data: result, file: document, error: errorMessage(failure) });
            return;
          }
        }
        openDraft(result);
      }}
    />
  );
}
