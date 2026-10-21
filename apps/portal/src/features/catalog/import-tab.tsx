import { canWriteAdmin, canUseSelfService } from "../../lib/capabilities";
import { AdminButton } from "../../components/admin-access";
// An imported service's Import tab: its definition (for a command import, the
// approved command and its accepted manifest), status, discovery and review,
// credential slots, and the administrator's OAuth discovery connection. The
// dialogs it opens (editor, review, token) live here too.
import { useState, type ReactNode } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import type { ImportBinding, ImportListResult, ImportPreviewResult, ImportPurpose } from "../../import-types";
import { errorMessage } from "../../lib/helpers";
import { importItemNoun } from "../../lib/imports";
import { COMMAND_KIND, commandCredentialText, commandName } from "../../lib/import-command";
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
  const secret = binding.delivery.kind === "stdin" ? "credential" : "token";
  const mode = binding.ownerMode === "service" ? `Shared service ${secret}` : binding.mechanism === "oauth" ? "Personal OAuth connection" : `Personal ${secret}`;
  return `${mode}${binding.status === "unsupported" ? " (unsupported authentication)" : ""}`;
}

function deliveryLabel(binding: ImportBinding | undefined) {
  if (!binding) return null;
  return binding.delivery.kind === "bearer" ? "Authorization: Bearer" : binding.delivery.kind === "stdin" ? "Request on stdin" : binding.delivery.name;
}

function discoveryText(data: ImportPreviewResult) {
  const discovery = data.service.definition.discovery;
  if (data.service.definition.adapterKind === COMMAND_KIND) return "Discovery runs the command's describe without credentials.";
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
  const command = definition.adapterKind === COMMAND_KIND;
  const accepted = record.acceptedMetadata;
  const noun = importItemNoun(definition.adapterKind);
  const allowed = data.operatorAllowed === true && record.status !== "retired";
  const status = { ...ACTION_STATUS, draft: { label: "Draft", tone: "warning" as const, icon: "pencil" as const } }[record.status];
  const actionCounts = (["enabled", "quarantined", "disabled", "retired"] as const)
    .map((key) => ({ key, count: record.actions.filter((action) => action.status === key).length }))
    .filter((entry) => entry.count > 0);
  const discoverLabel = openapi ? (data.preview || record.actions.length ? "Refresh definition" : "Load definition") : record.actions.length ? "Refresh discovery" : `Discover ${noun}s`;

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
    // A command's execution credential takes the kind its accepted manifest declares.
    const pendingManifest = command && purpose === "execution" && !accepted?.credential;
    const secret = command && purpose === "execution" ? "credential" : "token";
    return [
      <SettingsRow
        key={purpose}
        label={`${purpose[0]!.toUpperCase()}${purpose.slice(1)} ${secret}`}
        help={
          <>
            <Badge tone={configured ? "success" : "warning"} variant="dot">
              {configured ? "Configured" : "Missing"}
            </Badge>
            {!used ? " Retained, not selected by the configuration." : null}
            {pendingManifest && used ? " Accept the command's manifest first; it declares the credential kind." : null}
          </>
        }
        group
      >
        <span className="wb-btn-group">
          <AdminButton size="sm" icon="key" disabled={!allowed || !used || pendingManifest} onClick={() => onDialog({ kind: "token", purpose, rotate: configured, data })}>
            {configured ? "Rotate" : "Set"} {purpose} {secret}
          </AdminButton>
          <AdminButton size="sm" variant="danger-ghost" icon="trash" disabled={!configured} onClick={() => actions.confirmDeleteToken(data, purpose)}>
            Delete {purpose} {secret}
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
            : command
              ? "Each agent call runs the approved command once, with the request on its stdin. Service ID and command are fixed after creation."
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
            command
              ? { label: "Command", value: <span className="wb-mono pt-catalog-break">{commandName(definition.endpoint)}</span> }
              : { label: openapi ? "API base URL" : "Endpoint", value: <span className="wb-mono pt-catalog-break">{definition.endpoint}</span> },
            command ? { label: "Imported at version", value: data.commandVersion ?? <span className="wb-muted">Accept a discovery preview first</span> } : null,
            command && accepted ? { label: "Command credential", value: commandCredentialText(accepted.credential) } : null,
            command && accepted ? { label: "Verification", value: accepted.verify ? "Supported" : "Not supported by the command" } : null,
            command && accepted
              ? {
                  label: "Resource types",
                  value: accepted.resourceTypes.length ? (
                    <span className="pt-catalog-break">
                      {accepted.resourceTypes.map((type, index) => (
                        <span key={type.id}>
                          {index ? ", " : null}
                          {type.label} <span className="wb-mono wb-muted">{type.brokerType}</span>
                          <span className="wb-muted"> · exclusions {type.supportsExclusions === false ? "not supported" : "supported"}</span>
                          {type.removed ? <span className="wb-muted"> (removed; kept for its resources)</span> : null}
                        </span>
                      ))}
                    </span>
                  ) : (
                    <span className="wb-muted">None</span>
                  )
                }
              : null,
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
            command
              ? definition.executionBindings.length
                ? { label: "Credential delivery", value: "Request on stdin" }
                : null
              : { label: "Token delivery", value: <span className="wb-mono">{deliveryLabel(definition.executionBindings[0]) ?? "—"}</span> },
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
                  {data.preview.manifest.tools.length} {plural(data.preview.manifest.tools.length, noun)} · discovered <Time value={data.preview.createdAt} /> by{" "}
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
        {!credentialRows.length && !personalToken ? (
          <p className="pt-prose">{command && !definition.executionBindings.length ? "This command takes no credential." : "This configuration uses no service-owned tokens."}</p>
        ) : null}
      </SettingsSection>

      {canWriteAdmin(session) && canUseSelfService(session) && ownDiscovery(data, session.principal, "oauth") ? <DiscoveryConnection service={service.service} registration={definition.executionBindings.find((binding) => binding.ownerMode === "per_user")?.registrationId ?? null} /> : null}

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

/** The signed-in administrator's OAuth connection used for per-user discovery: the import's registration. */
function DiscoveryConnection({ service, registration }: { service: string; registration: string | null }) {
  const query = useOAuthConnections();
  const actions = useOAuthConnectionActions("/ui/admin/catalog", service);
  const target = query.data?.find((entry) => entry.registration === registration);
  let content: ReactNode;
  if (query.isPending && query.fetchStatus !== "idle") content = <SkeletonBlock lines={2} />;
  else if (query.isError) content = <ErrorState compact error={query.error} title="OAuth connections could not be loaded." onRetry={() => void query.refetch()} retrying={query.isFetching} />;
  else if (!target) content = <EmptyState compact icon="link" title="No connection target">The broker does not offer an OAuth connection for this service yet.</EmptyState>;
  else
    content = (
      <Rows label="Connected account">
        <OAuthConnectionRow target={target} connections={actions} />
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
        authentication={dialog.data.importAuthentication ?? imports?.importAuthentication ?? []}
        availableKinds={imports?.availableKinds ?? []}
        commandImports={imports?.commandImports.map((entry) => entry.name) ?? []}
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
        onAccept={(rows, confirmed, typeIds) => actions.accept(review, rows, confirmed, typeIds)}
      />
    );
  }
  const { purpose, data } = dialog;
  // A command's execution slot holds the kind its accepted manifest declares.
  const withUsername = purpose === "execution" && data.service.acceptedMetadata?.credential?.kind === "username_token";
  return (
    <ImportTokenModal
      key={`token-${purpose}`}
      purpose={purpose}
      rotate={dialog.rotate}
      withUsername={withUsername}
      noun={purpose === "execution" && data.service.definition.adapterKind === COMMAND_KIND ? "credential" : "token"}
      onClose={close}
      onSave={(token, username) => (purpose === "personal" ? actions.writePersonalToken(data, token) : actions.writeToken(data, purpose, token, username))}
    />
  );
}
