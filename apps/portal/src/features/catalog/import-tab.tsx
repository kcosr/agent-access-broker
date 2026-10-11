import { canWriteAdmin, canUseSelfService } from "../../lib/capabilities";
import { AdminButton } from "../../components/admin-access";
// An imported service's Import tab: its definition, status, discovery and
// review, credential slots, and the administrator's OAuth discovery
// connection. The dialogs it opens (editor, review, token) live here too.
import { useState, type ReactNode } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import type { ImportBinding, ImportListResult, ImportPreviewResult, ImportPurpose } from "../../import-types";
import { errorMessage } from "../../lib/helpers";
import { formatServiceLimit } from "../../lib/service-limits";
import {
  AppLink,
  Badge,
  Banner,
  Button,
  EmptyState,
  ErrorState,
  KeyValue,
  Rows,
  SettingsPage,
  SettingsRow,
  SettingsSection,
  SkeletonBlock,
  StatePill,
  Time,
  plural
} from "../../workbench";
import { paths } from "../../app/paths";
import { useSession } from "../../app/session";
import { useOAuthConnections } from "../../data/queries";
import { OAuthConnectionRow, useOAuthConnectionActions } from "../../components/oauth-connections";
import { ACTION_STATUS, adapterLabel, type CatalogService } from "./catalog-data";
import { useImportActions, type ServiceStatusChange } from "./import-actions";
import { ImportEditor } from "./import-editor";
import { ImportReview, ScopedMcpStatus } from "./import-review";
import { ImportTokenModal, type TokenPurpose } from "./import-token-modal";

export type ImportDialog =
  | { kind: "edit"; data: ImportPreviewResult }
  | { kind: "review"; data: ImportPreviewResult }
  | { kind: "token"; purpose: TokenPurpose; rotate: boolean; data: ImportPreviewResult }
  | null;

const PURPOSES: ImportPurpose[] = ["execution", "discovery", "transport"];

export function bindingLabel(binding: ImportBinding) {
  const mode = binding.ownerMode === "service" ? "Shared service token" : binding.mechanism === "oauth" ? "Personal OAuth connection" : "Personal token";
  return `${mode}${binding.status === "unsupported" ? " (unsupported authentication)" : ""}`;
}

function deliveryLabel(binding: ImportBinding | undefined) {
  if (!binding) return null;
  return binding.delivery.kind === "bearer" ? "Authorization: Bearer" : binding.delivery.name;
}

function discoveryText(data: ImportPreviewResult) {
  const discovery = data.service.definition.discovery;
  if (discovery.kind === "anonymous") return "The public definition document is loaded without credentials.";
  if (discovery.kind === "execution") return "Discovery uses the shared execution token.";
  if (discovery.kind === "slot") return "Discovery uses a separate discovery token.";
  return `Discovery uses the personal credentials belonging to ${discovery.principal}.`;
}

/** Whether the signed-in administrator is this draft's per-user discovery principal with a given personal mechanism. */
function ownDiscovery(data: ImportPreviewResult, principal: string | undefined, mechanism: ImportBinding["mechanism"]) {
  const definition = data.service.definition;
  return (
    definition.discovery.kind === "per_user" &&
    definition.discovery.principal === principal &&
    definition.executionBindings.some((binding) => binding.ownerMode === "per_user" && binding.mechanism === mechanism && binding.status === "configured")
  );
}

const STATUS_TEXT: Record<ImportPreviewResult["service"]["status"], string> = {
  draft: "A draft cannot execute. Configure credentials, discover and accept actions, then enable it.",
  enabled: "Enabled actions execute for grants that select a configured credential mode.",
  disabled: "No action executes. Definitions, tokens and grants remain for later review.",
  retired: "Retired permanently. Action identities and grant references remain, but nothing executes."
};

export function ImportTab({
  service,
  query,
  imports,
  onDialog
}: {
  service: CatalogService;
  query: UseQueryResult<ImportPreviewResult>;
  imports: ImportListResult | null;
  onDialog: (dialog: ImportDialog) => void;
}) {
  const { session } = useSession();
  const actions = useImportActions();
  const [discovering, setDiscovering] = useState(false);
  const [discoverError, setDiscoverError] = useState<string | null>(null);
  const data = query.data;
  if (query.isPending && query.fetchStatus !== "idle") {
    return (
      <SettingsPage>
        <SkeletonBlock lines={6} />
        <SkeletonBlock lines={4} />
      </SettingsPage>
    );
  }
  if (!data) {
    return query.isError ? <ErrorState error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} /> : null;
  }
  const record = data.service;
  const definition = record.definition;
  const openapi = definition.adapterKind === "openapi_http";
  const allowed = data.operatorAllowed === true && record.status !== "retired";
  const status = { ...ACTION_STATUS, draft: { label: "Draft", tone: "warning" as const, icon: "pencil" as const } }[record.status];
  const actionCounts = (["enabled", "quarantined", "disabled", "retired"] as const)
    .map((key) => ({ key, count: record.actions.filter((action) => action.status === key).length }))
    .filter((entry) => entry.count > 0);
  const discoverLabel = openapi ? (data.preview || record.actions.length ? "Refresh definition" : "Load definition") : record.actions.length ? "Refresh discovery" : "Discover tools";

  async function discover() {
    if (!data) return;
    setDiscovering(true);
    setDiscoverError(null);
    try {
      const result = await actions.discover(data);
      onDialog({ kind: "review", data: result });
    } catch (failure) {
      setDiscoverError(errorMessage(failure));
    } finally {
      setDiscovering(false);
    }
  }

  const statusButton = (change: ServiceStatusChange, disabled: boolean, variant: "default" | "danger-ghost" = "default") => (
    <AdminButton key={change} variant={variant} icon={change === "enabled" ? "play" : change === "disabled" ? "pause" : "ban"} disabled={disabled} onClick={() => actions.confirmServiceStatus(data, change)}>
      {change === "enabled" ? "Enable" : change === "disabled" ? "Disable" : "Retire"}
    </AdminButton>
  );

  const credentialRows = PURPOSES.flatMap((purpose) => {
    const configured = Boolean(record.slotVersions[purpose]);
    const used =
      purpose === "execution"
        ? definition.executionBindings.some((binding) => binding.ownerMode === "service" && binding.status === "configured")
        : purpose === "discovery"
          ? definition.discovery.kind === "slot"
          : definition.transportAuth;
    if (!used && !configured) return [];
    return [
      <SettingsRow
        key={purpose}
        label={`${purpose[0]!.toUpperCase()}${purpose.slice(1)} token`}
        help={
          <>
            <Badge tone={configured ? "success" : "warning"} variant="dot">
              {configured ? "Configured" : "Missing"}
            </Badge>
            {!used ? " Retained, not selected by the configuration." : null}
          </>
        }
        group
      >
        <span className="wb-btn-group">
          <AdminButton size="sm" icon="key" disabled={!allowed || !used} onClick={() => onDialog({ kind: "token", purpose, rotate: configured, data })}>
            {configured ? "Rotate" : "Set"} {purpose} token
          </AdminButton>
          <AdminButton size="sm" variant="danger-ghost" icon="trash" disabled={!configured} onClick={() => actions.confirmDeleteToken(data, purpose)}>
            Delete {purpose} token
          </AdminButton>
        </span>
      </SettingsRow>
    ];
  });
  const personalToken = canWriteAdmin(session) && canUseSelfService(session) && ownDiscovery(data, session.principal, "static_token");

  return (
    <SettingsPage>
      {imports && !imports.operatorEnabled ? (
        <Banner tone="warning" slim>
          Imports are disabled by operator configuration. Retained services can be inspected, disabled or retired, and stored tokens can be deleted.
        </Banner>
      ) : null}
      {record.status === "enabled" && data.available === false ? (
        <Banner tone="warning" title="Service unavailable">
          {data.unavailableReason ?? "This service cannot currently execute. Existing grants and definitions are retained."}
        </Banner>
      ) : !data.operatorAllowed ? (
        <Banner tone="warning" title="Blocked by operator configuration">
          Operator configuration currently blocks this service. Existing grants and definitions are retained.
        </Banner>
      ) : null}

      <SettingsSection
        title="Status"
        description={STATUS_TEXT[record.status]}
        actions={
          <span className="wb-btn-group">
            {statusButton("enabled", !allowed || record.status === "enabled" || !record.actions.some((action) => action.status === "enabled"))}
            {statusButton("disabled", record.status === "retired" || record.status === "disabled")}
            {statusButton("retired", record.status === "retired", "danger-ghost")}
          </span>
        }
      >
        <KeyValue
          labelWidth={160}
          items={[
            {
              label: "Service",
              value: (
                <StatePill tone={status.tone} icon={status.icon}>
                  {status.label}
                </StatePill>
              )
            },
            {
              label: "Accepted actions",
              value: actionCounts.length ? (
                <AppLink href={paths.catalogService(service.service)} className="wb-link">
                  {actionCounts.map((entry) => `${entry.count} ${ACTION_STATUS[entry.key].label.toLowerCase()}`).join(" · ")}
                </AppLink>
              ) : (
                <span className="wb-muted">No actions accepted yet.</span>
              )
            },
            { label: "Revision", value: <span className="wb-num">{record.version}</span> },
            {
              label: "Updated",
              value: (
                <>
                  <Time value={record.updatedAt} /> <span className="wb-muted">by {record.updatedBy}</span>
                </>
              )
            }
          ]}
        />
        {record.actions.some((action) => action.status === "quarantined") ? (
          <div className="pt-catalog-stack">
            <p className="pt-catalog-warn">Quarantined actions require a new discovery review before they can be enabled.</p>
          </div>
        ) : null}
      </SettingsSection>

      <SettingsSection
        title="Definition"
        description={
          openapi
            ? "The OpenAPI document describes operations; agent calls go to the API base URL."
            : "Agent calls go to this HTTP MCP endpoint. Service ID and endpoint are fixed after creation."
        }
        actions={
          <AdminButton icon="pencil" disabled={!allowed} onClick={() => onDialog({ kind: "edit", data })}>
            Edit configuration
          </AdminButton>
        }
      >
        <KeyValue
          labelWidth={160}
          items={[
            { label: "Import type", value: <>{adapterLabel(definition.adapterKind)} <span className="wb-num wb-muted">{definition.adapterKind}</span></> },
            { label: openapi ? "API base URL" : "Endpoint", value: <span className="wb-mono pt-catalog-break">{definition.endpoint}</span> },
            openapi ? { label: "Definition URL", value: <span className="wb-mono pt-catalog-break">{definition.connectionSettings.definitionUrl}</span> } : null,
            openapi
              ? {
                  label: "Definition access",
                  value:
                    (definition.connectionSettings.definitionAuthKind ?? "none") === "none"
                      ? "Public document"
                      : definition.connectionSettings.definitionAuthKind === "bearer"
                        ? "Discovery Bearer token"
                        : <>Discovery token in <span className="wb-mono">{definition.connectionSettings.definitionAuthHeader}</span></>
                }
              : null,
            openapi
              ? {
                  label: "API security scheme",
                  value: definition.connectionSettings.securityScheme ? (
                    <span className="wb-mono">{definition.connectionSettings.securityScheme}</span>
                  ) : (
                    <span className="wb-muted">Select after loading the definition</span>
                  )
                }
              : null,
            {
              label: "Execution credentials",
              value: definition.executionBindings.length ? definition.executionBindings.map(bindingLabel).join(", ") : <span className="wb-muted">None</span>
            },
            { label: "Token delivery", value: <span className="wb-mono">{deliveryLabel(definition.executionBindings[0]) ?? "—"}</span> },
            !openapi && definition.transportAuth ? { label: "Transport", value: "Separate transport bearer token" } : null,
            { label: "Discovery", value: discoveryText(data) },
            {
              label: "Invocation limit",
              value: definition.invocationLimit ? (
                formatServiceLimit(definition.invocationLimit)
              ) : (
                <span className="wb-muted">Broker default</span>
              )
            },
            {
              label: "Created",
              value: (
                <>
                  <Time value={record.createdAt} /> <span className="wb-muted">by {record.createdBy}</span>
                </>
              )
            }
          ]}
        />
      </SettingsSection>

      <SettingsSection
        title="Discovery and review"
        description="Discovery is manual. New or changed actions need review before use; existing grant action lists do not expand."
        actions={
          <span className="wb-btn-group">
            <Button icon="eye" disabled={!data.preview} onClick={() => onDialog({ kind: "review", data })}>
              Review preview
            </Button>
            <AdminButton variant="primary" icon="download" pending={discovering} disabled={!allowed || (definition.discovery.kind === "per_user" && !canUseSelfService(session))} onClick={() => void discover()}>
              {discoverLabel}
            </AdminButton>
          </span>
        }
      >
        <KeyValue
          labelWidth={160}
          items={[
            {
              label: "Pending preview",
              value: data.preview ? (
                <>
                  {data.preview.manifest.tools.length} {plural(data.preview.manifest.tools.length, openapi ? "operation" : "tool")} · discovered <Time value={data.preview.createdAt} /> by{" "}
                  {data.preview.createdBy} · expires <Time value={data.preview.expiresAt} />
                </>
              ) : (
                <span className="wb-muted">None</span>
              )
            }
          ]}
        />
        <div className="pt-catalog-stack">
          <ScopedMcpStatus value={data.scopedMcp} />
          {discoverError ? (
            <Banner tone="danger" slim title="Discovery failed" live>
              {discoverError}
            </Banner>
          ) : null}
        </div>
      </SettingsSection>

      <SettingsSection title="Credentials" description={<>Execution credentials are used for agent calls. {discoveryText(data)} Tokens are never displayed after saving.</>}>
        {credentialRows}
        {personalToken ? (
          <SettingsRow label="Your personal discovery token" help={<span className="wb-num">{session.principal}</span>} group>
            <AdminButton size="sm" icon="key" disabled={!allowed} onClick={() => onDialog({ kind: "token", purpose: "personal", rotate: false, data })}>
              Set personal token
            </AdminButton>
          </SettingsRow>
        ) : null}
        {!credentialRows.length && !personalToken ? <p className="pt-prose">This configuration uses no service-owned tokens.</p> : null}
      </SettingsSection>

      {canWriteAdmin(session) && canUseSelfService(session) && ownDiscovery(data, session.principal, "oauth") ? <DiscoveryConnection service={service.service} /> : null}

      <SettingsSection title="Related">
        <div className="pt-catalog-links">
          <Button icon="shield" href={paths.policies({ service: service.service })}>
            Manage grants
          </Button>
          <Button icon="users" href={paths.catalogService(service.service, "managers")}>
            Service managers
          </Button>
          {canUseSelfService(session) ? <Button icon="lock" href={paths.credentials()}>
            My personal credentials
          </Button> : null}
        </div>
      </SettingsSection>
    </SettingsPage>
  );
}

/** The signed-in administrator's OAuth connection used for per-user discovery. */
function DiscoveryConnection({ service }: { service: string }) {
  const query = useOAuthConnections();
  const actions = useOAuthConnectionActions("/ui/admin/catalog");
  const target = query.data?.find((entry) => entry.service === service);
  let content: ReactNode;
  if (query.isPending && query.fetchStatus !== "idle") content = <SkeletonBlock lines={2} />;
  else if (query.isError) content = <ErrorState compact error={query.error} title="Connected accounts could not be loaded." onRetry={() => void query.refetch()} retrying={query.isFetching} />;
  else if (!target) content = <EmptyState compact icon="link" title="No connection target">The broker does not offer an OAuth connection for this service yet.</EmptyState>;
  else
    content = (
      <Rows label="Connected account">
        <OAuthConnectionRow target={target} pending={actions.pending === target.service} onConnect={() => actions.connect(target)} onDisconnect={() => actions.disconnect(target)} />
      </Rows>
    );
  return (
    <SettingsSection
      title="Connected account"
      description="Discovery uses your own OAuth connection. Authorization opens in a new tab, keeping this page and your edits in place."
    >
      {content}
    </SettingsSection>
  );
}

/** The dialog the Import tab (or Limits) opened, wired to the import mutations. */
export function ImportDialogs({ dialog, imports, onDialog }: { dialog: ImportDialog; imports: ImportListResult | null; onDialog: (dialog: ImportDialog) => void }) {
  const { session } = useSession();
  const actions = useImportActions();
  const close = () => onDialog(null);
  if (!dialog || (dialog.kind !== "review" && !canWriteAdmin(session)) || (dialog.kind === "token" && dialog.purpose === "personal" && !canUseSelfService(session))) return null;
  if (dialog.kind === "edit") {
    return (
      <ImportEditor
        key="edit"
        principal={session.principal ?? ""}
        data={dialog.data}
        registrations={dialog.data.oauthRegistrations ?? imports?.oauthRegistrations ?? []}
        availableKinds={imports?.availableKinds ?? []}
        onClose={close}
        onSave={(definition, confirmed) => actions.update(dialog.data, definition, confirmed)}
      />
    );
  }
  if (dialog.kind === "review") {
    const review = dialog.data;
    const configurable = review.service.definition.adapterKind === "openapi_http" && review.service.status === "draft" && !review.service.actions.length;
    return (
      <ImportReview
        key={`review-${review.preview?.manifestHash ?? "none"}`}
        data={review}
        onClose={close}
        onConfigure={configurable ? () => onDialog({ kind: "edit", data: review }) : undefined}
        onAccept={(rows, confirmed) => actions.accept(review, rows, confirmed)}
      />
    );
  }
  const { purpose, data } = dialog;
  return (
    <ImportTokenModal
      key={`token-${purpose}`}
      purpose={purpose}
      rotate={dialog.rotate}
      onClose={close}
      onSave={(token) => (purpose === "personal" ? actions.writePersonalToken(data, token) : actions.writeToken(data, purpose, token))}
    />
  );
}
