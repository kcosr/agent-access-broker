import { useSession } from "../../app/session";
import { canWriteAdmin } from "../../lib/capabilities";
import { AdminButton } from "../../components/admin-access";
// Reviewing a discovery preview: choose tools, operations or command actions
// to accept, name them, classify their effects, choose the Broker type IDs of
// a command's new resource types, and confirm changes that affect existing
// grants.
import { Fragment, useId, useState } from "react";
import { ApiError } from "../../api";
import type {
  ImportActionDefinition,
  ImportPreviewResult,
  ImportResourceTypeChange,
  ImportResourceTypeDeclaration,
  ImportResourceTypeIds,
  ImportScopedMcp,
  ImportScopedMcpIssueCode,
  ImportScopedMcpWarning
} from "../../import-types";
import { affectedImportGrants, importItemNoun, importReviewRows, importSelectionError, type ImportReviewRow } from "../../lib/imports";
import { openApiOperation, openApiSchemeLabel } from "../../lib/import-openapi";
import {
  COMMAND_CHECK_CAVEAT,
  COMMAND_KIND,
  TYPE_CHANGE_LABEL,
  blockedTypeChanges,
  commandCredentialText,
  commandName,
  commandNotices,
  commandResourceCheck,
  resourceCheckParts,
  resourceCheckText,
  resourceTypeIdIssues,
  typeChangeDetails,
  typeChangeOutcome
} from "../../lib/import-command";
import { errorMessage } from "../../lib/helpers";
import { AppLink, Badge, Banner, Button, Checkbox, Disclosure, Field, FilterInput, Input, KeyValue, Select, Time, cx, plural, toneClass, type Tone } from "../../workbench";
import { paths } from "../../app/paths";
import { resourceTypePluralLabel, useResourceTypes } from "../../lib/resource-types";
import { LongText, modalFrame, type EditorFrame } from "./catalog-ui";

export const SCOPED_MCP_ISSUE_TEXT: Record<ImportScopedMcpIssueCode, string> = {
  service_unavailable: "Service is not currently available.",
  missing_name: "The adapter cannot provide a tool name.",
  invalid_name: "Tool name must contain 1–128 ASCII letters, numbers, underscores, dots or hyphens.",
  reserved_name: "Tool name conflicts with a broker discovery helper.",
  duplicate_name: "Multiple actions use the same tool name.",
  projection_budget: "Scoped tool definitions exceed the catalog limit."
};

/** Readiness of the service-specific MCP connection for the currently published actions. */
export function ScopedMcpStatus({ value }: { value: ImportScopedMcp }) {
  return (
    <div className="pt-catalog-readiness" role="group" aria-label="Current service-specific MCP readiness">
      <div className="pt-catalog-readiness-head">
        <span>Current service-specific MCP</span>
        <Badge tone={value.ready ? "success" : "warning"}>{value.ready ? "Ready" : "Unavailable"}</Badge>
      </div>
      {!value.ready ? (
        <>
          <p className="pt-prose wb-small">
            This reflects the currently published actions. Name conflicts affect this service connection; aggregate MCP remains available when otherwise permitted.
          </p>
          {value.issues.map((issue, index) => (
            <p key={index} className="pt-prose wb-small pt-catalog-break">
              {SCOPED_MCP_ISSUE_TEXT[issue.code]}
              {issue.actions.length ? ` Actions: ${issue.actions.join(", ")}.` : ""}
            </p>
          ))}
          {value.truncated ? <p className="pt-prose wb-small">Additional issue details omitted.</p> : null}
        </>
      ) : null}
    </div>
  );
}

function ScopedMcpWarningText({ warning }: { warning?: ImportScopedMcpWarning | undefined }) {
  if (!warning) return null;
  return (
    <p className="pt-catalog-warn">
      Provisional service-specific MCP warning for {warning.proposedAction}: {warning.codes.map((code) => SCOPED_MCP_ISSUE_TEXT[code]).join(" ")}
    </p>
  );
}

/** `GET /items/{id}` and the operation's security scheme, for OpenAPI actions. */
export function OperationDetails({ definition }: { definition: ImportActionDefinition }) {
  const operation = openApiOperation(definition);
  if (!operation) return null;
  return (
    <p className="pt-catalog-op">
      <span className="wb-mono">
        {operation.method} {operation.path}
      </span>
      {operation.security ? <span className="wb-muted"> · {openApiSchemeLabel(operation.security)}</span> : null}
    </p>
  );
}

/**
 * "Resources checked by" for a command action: the Broker, from the inputs
 * naming its resources, or the command, with the caller's grants. Command
 * rows point to `caveatId`, the explanation of what the command must do.
 */
function ResourcesCheckedBy({ definition, types, caveatId }: { definition: ImportActionDefinition; types: readonly ImportResourceTypeDeclaration[]; caveatId?: string | undefined }) {
  const check = commandResourceCheck(definition);
  const parts = resourceCheckParts(check, types);
  return (
    <p className="pt-catalog-op" aria-describedby={check.by === "command" ? caveatId : undefined}>
      Resources checked by: <b>{check.by === "broker" ? "Broker" : "Command"}</b>
      <span className="wb-muted">
        {" · "}
        {parts.type ?? "no resource type"}
        {parts.inputs.length ? ", from " : null}
        {parts.inputs.map((input, index) => (
          <Fragment key={input}>
            {index ? ", " : null}
            <span className="wb-mono">{input}</span>
          </Fragment>
        ))}
      </span>
    </p>
  );
}

/**
 * An acceptance failure. A change refused because retained grants or stored
 * resources would not stay valid lists them, linked to where they are fixed.
 */
export function ImportErrorAlert({ error }: { error: unknown }) {
  const types = useResourceTypes();
  if (!error) return null;
  const blocked = error instanceof ApiError ? error.blocked : undefined;
  if (!blocked) {
    return (
      <div className="wb-form-error" role="alert">
        {errorMessage(error)}
      </div>
    );
  }
  const resources = new Map<string, string[]>();
  for (const resource of blocked.resources) resources.set(resource.type, [...(resources.get(resource.type) ?? []), resource.id]);
  return (
    <div className="wb-form-error" role="alert">
      {blocked.affectedGrants.length ? (
        <>
          This change would leave retained grants invalid. Update or remove them first:
          <ul className="pt-catalog-error-list">
            {blocked.affectedGrants.map((grant, index) => (
              // A grant is referenced by its managed ID or `toml:<index>`; one
              // the Broker could not attribute has no reference to open.
              <li key={index}>
                {grant.id ? (
                  <AppLink href={paths.policies({ grant: grant.id })} className="wb-link wb-mono">
                    {grant.id}
                  </AppLink>
                ) : (
                  <span className="wb-muted">Unidentified grant</span>
                )}
                : {grant.reason}
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {resources.size ? (
        <>
          Stored resources no longer fit these resource type changes. Edit or delete them, or refresh the preview:
          <ul className="pt-catalog-error-list">
            {[...resources].map(([type, entries]) => (
              <li key={type}>
                {resourceTypePluralLabel(types, type)} <span className="wb-mono wb-muted">{type}</span>:{" "}
                {entries.map((id, index) => (
                  <Fragment key={id}>
                    {index ? ", " : null}
                    <AppLink href={paths.resources(id)} className="wb-link wb-mono">
                      {id}
                    </AppLink>
                  </Fragment>
                ))}
                {entries.length >= 100 ? " and possibly more" : null}
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </div>
  );
}

const TYPE_CHANGE_TONE: Record<ImportResourceTypeChange["outcome"], Tone> = { applied: "info", needs_new_id: "warning", retained: "warning", dropped: "neutral" };

/** Resource IDs from a preview list, which names at most 100; `total` when the full count is known. */
function ResourceIds({ ids, total }: { ids: string[]; total?: number | undefined }) {
  const more = total !== undefined ? total - ids.length : ids.length >= 100 ? null : 0;
  return (
    <>
      {ids.map((id, index) => (
        <Fragment key={id}>
          {index ? ", " : null}
          <span className="wb-mono">{id}</span>
        </Fragment>
      ))}
      {more === null ? " and more" : more > 0 ? ` and ${more} more` : null}
    </>
  );
}

/** One declared, retained or dropped type: its Broker type ID and what accepting does with it. */
function ResourceTypeReview({
  declared,
  change,
  typeId,
  issue,
  pending,
  onTypeId
}: {
  declared: ImportResourceTypeDeclaration | undefined;
  change: ImportResourceTypeChange | undefined;
  typeId: string;
  issue: string | undefined;
  pending: boolean;
  onTypeId: (value: string) => void;
}) {
  const id = declared?.id ?? change?.id ?? "";
  const title = declared ? `${declared.label} (${declared.pluralLabel})` : id;
  return (
    <div className="pt-catalog-review-item" role="group" aria-label={`Resource type ${id}`}>
      <div className="pt-catalog-review-title">
        <span className="pt-catalog-break">
          <b>{title}</b> <span className="wb-mono wb-muted">{id}</span>
          {" · "}
          {change ? <span className={cx("pt-catalog-tone-text", toneClass(TYPE_CHANGE_TONE[change.outcome]))}>{TYPE_CHANGE_LABEL[change.change]}</span> : <span className="wb-muted">Unchanged</span>}
        </span>
      </div>
      {change?.editable ? (
        <Field label={`Broker type ID for ${id}`} hint="Used in resources and grants. Fixed once accepted." error={issue}>
          <Input mono inputSize="sm" maxLength={64} value={typeId} disabled={pending} onChange={(event) => onTypeId(event.target.value)} spellCheck={false} />
        </Field>
      ) : (
        <p className="pt-catalog-op">
          Broker type ID <span className="wb-mono">{change?.brokerType ?? declared?.brokerType}</span>
        </p>
      )}
      {declared && change?.change !== "removed" ? (
        <p className="pt-catalog-op">
          Example <span className="wb-mono">{declared.example}</span>
          {declared.attributes.length ? ` · private attributes: ${declared.attributes.map((attribute) => `${attribute.label}${attribute.required ? " (required)" : ""}`).join(", ")}` : null}
        </p>
      ) : null}
      {change ? (
        <>
          {change.details.length ? <p className="pt-prose wb-small">Changed: {typeChangeDetails(change)}.</p> : null}
          <p className="pt-prose wb-small">{typeChangeOutcome(change)}</p>
          {change.blocked && change.blockingResources.length ? (
            <p className="pt-catalog-warn">
              Accepting is rejected until you edit or delete: <ResourceIds ids={change.blockingResources} />.
            </p>
          ) : change.blockingResources.length ? (
            <p className="pt-prose wb-small">
              Resources: <ResourceIds ids={change.blockingResources} total={change.outcome === "retained" ? change.resourceCount : undefined} />.
            </p>
          ) : null}
          {change.affectedResources.length ? (
            <p className="pt-catalog-warn">
              Accepting deletes the removed attributes' values from: <ResourceIds ids={change.affectedResources} />.
            </p>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

/** A command preview's manifest: version, credential, verification, notices and resource types. */
function CommandPreview({
  data,
  typeIds,
  issues,
  pending,
  onTypeId
}: {
  data: ImportPreviewResult;
  typeIds: ImportResourceTypeIds;
  issues: Record<string, string>;
  pending: boolean;
  onTypeId: (id: string, value: string) => void;
}) {
  const metadata = data.preview?.manifest.serviceMetadata;
  if (!metadata) return null;
  const changes = data.resourceTypeChanges ?? [];
  const types = [...metadata.resourceTypes.map((declared) => declared.id), ...changes.filter((change) => !metadata.resourceTypes.some((declared) => declared.id === change.id)).map((change) => change.id)];
  return (
    <section className="pt-catalog-review-retained" aria-label="Command manifest">
      <h3 className="pt-section-title">Command</h3>
      {commandNotices(data.preview?.manifest).map((notice) => (
        <Banner key={notice} tone="info" slim>
          {notice}
        </Banner>
      ))}
      <KeyValue
        labelWidth={150}
        items={[
          { label: "Command", value: <span className="wb-mono">{commandName(data.service.definition.endpoint)}</span> },
          {
            label: "Version",
            value: (
              <>
                {metadata.version}
                {data.commandVersion && data.commandVersion !== metadata.version ? <span className="wb-muted"> · imported at version {data.commandVersion}</span> : null}
              </>
            )
          },
          { label: "Credential", value: commandCredentialText(metadata.credential) },
          { label: "Verification", value: metadata.verify ? "Supported" : "Not supported" }
        ]}
      />
      <h3 className="pt-section-title">Resource types</h3>
      {!types.length ? <p className="pt-prose wb-small">The command declares no resource types.</p> : null}
      {types.map((id) => {
        const change = changes.find((entry) => entry.id === id);
        return (
          <ResourceTypeReview
            key={id}
            declared={metadata.resourceTypes.find((declared) => declared.id === id)}
            change={change}
            typeId={typeIds[id] ?? change?.brokerType ?? ""}
            issue={issues[id]}
            pending={pending}
            onTypeId={(value) => onTypeId(id, value)}
          />
        );
      })}
    </section>
  );
}

const CHANGE_TONE: Record<ImportReviewRow["change"], Tone> = {
  New: "info",
  Changed: "warning",
  "Metadata changed": "neutral",
  Unchanged: "muted",
  Removed: "warning",
  Unsupported: "danger",
  Retired: "neutral",
  "Retired – new identity required": "warning"
};

export type ImportReviewProps = {
  data: ImportPreviewResult;
  onClose: () => void;
  onAccept: (rows: ImportReviewRow[], confirmAffectedGrants: boolean, resourceTypeIds: ImportResourceTypeIds) => Promise<unknown>;
  /** Offered for an empty OpenAPI draft whose operations need an API security scheme first. */
  onConfigure?: (() => void) | undefined;
  frame?: EditorFrame;
};

export function ImportReview({ data, onClose, onAccept, onConfigure, frame = modalFrame }: ImportReviewProps) {
  const writable = canWriteAdmin(useSession().session);
  const caveatId = useId();
  const [rows, setRows] = useState(() => importReviewRows(data));
  const [typeIds, setTypeIds] = useState<ImportResourceTypeIds>({});
  const [confirmed, setConfirmed] = useState(false);
  const [search, setSearch] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const noun = importItemNoun(data.service.definition.adapterKind);
  const items = `${noun}s`;
  const command = data.service.definition.adapterKind === COMMAND_KIND;
  const metadata = data.preview?.manifest.serviceMetadata;
  // The accepted types of a command import and those this preview declares, for action type labels.
  const types = [...(metadata?.resourceTypes ?? []), ...(data.service.acceptedMetadata?.resourceTypes ?? [])];
  const changes = data.resourceTypeChanges ?? [];
  const typeIssues = resourceTypeIdIssues(changes, metadata, typeIds);
  const blockedTypes = blockedTypeChanges(changes);
  const invalid = importSelectionError(data, rows);
  const typeProblem = Object.keys(typeIssues).length
    ? "Choose valid, unused Broker type IDs."
    : blockedTypes.length
      ? `Resolve the blocked resource type ${plural(blockedTypes.length, "change")} first.`
      : null;
  const affected = affectedImportGrants(data, rows);
  const query = search.trim().toLowerCase();
  const matches = (row: ImportReviewRow) =>
    !query ||
    `${row.action} ${row.tool.definition.description} ${row.change} ${JSON.stringify(row.tool.definition.source)} ${JSON.stringify(openApiOperation(row.tool.definition))} ${command ? resourceCheckText(commandResourceCheck(row.tool.definition), types) : ""}`
      .toLowerCase()
      .includes(query);
  const update = (key: string, change: Partial<ImportReviewRow>) => {
    setConfirmed(false);
    setRows((current) => current.map((row) => (row.key === key ? { ...row, ...change } : row)));
  };
  const selectedCount = rows.filter((row) => row.selected && row.selectable).length;
  const retained = rows.filter((row) => !row.selectable && matches(row));
  const commandChecked = command && rows.some((row) => commandResourceCheck(row.tool.definition).by === "command");
  const blocked = Boolean(invalid || typeProblem) || (affected.length > 0 && !confirmed);

  async function accept() {
    if (!writable || blocked) return;
    setPending(true);
    setError(null);
    try {
      await onAccept(rows, confirmed, typeIds);
      onClose();
    } catch (failure) {
      setError(failure);
      setPending(false);
    }
  }

  const body = (
    <div className="wb-form-stack pt-catalog-form">
      <p className="pt-prose">
        <b>{data.service.definition.displayName}</b> <span className="wb-num">{data.service.definition.service}</span>
        <br />
        Select {items} to accept and review their effects. New and changed {items} start write-capable. Upstream read-only hints are suggestions. Unselected accepted actions
        keep their current status.
      </p>
      <p className="pt-prose wb-small wb-muted">
        Preview expires <Time value={data.preview?.expiresAt} format="datetime" fallback="soon" />. Configuration, credential or catalog changes require a fresh preview.
      </p>
      <ScopedMcpStatus value={data.scopedMcp} />
      {data.scopedMcpWarnings.length ? (
        <Banner tone="warning" slim>
          Provisional service-specific MCP warnings apply to names proposed in this preview. These warnings do not prevent acceptance or aggregate MCP use. Action name edits and
          your final selection may change readiness; the broker checks it again after acceptance.
        </Banner>
      ) : null}
      {command ? (
        <CommandPreview
          data={data}
          typeIds={typeIds}
          issues={typeIssues}
          pending={pending || !writable}
          onTypeId={(id, value) => setTypeIds((current) => ({ ...current, [id]: value }))}
        />
      ) : null}
      <Disclosure summary="Discovery source details">
        <p className="pt-prose wb-small">Protocol: {data.preview?.manifest.protocolVersion}</p>
        <pre className="wb-code pt-catalog-code">{JSON.stringify(data.preview?.manifest.metadata, null, 2)}</pre>
      </Disclosure>
      {commandChecked ? (
        <p id={caveatId} className="pt-prose wb-small">
          <b>Resources checked by: Command.</b> {COMMAND_CHECK_CAVEAT}
        </p>
      ) : null}
      {writable && onConfigure ? (
        <Banner
          tone="info"
          slim
          actions={
            <AdminButton size="sm" icon="gear" disabled={pending || !writable} onClick={onConfigure}>
              Configure API authentication
            </AdminButton>
          }
        >
          Select the definition's API security scheme before accepting operations.
        </Banner>
      ) : null}
      <FilterInput value={search} onChange={setSearch} placeholder={`Filter ${items}…`} label={`Filter discovered ${items}`} hotkey={null} />
      {[true, false].map((readOnly) => {
        const group = rows.filter((row) => row.selectable && row.readOnly === readOnly && matches(row));
        const label = readOnly ? "Read-only" : "Write-capable";
        return (
          <fieldset key={label} className="pt-fieldset pt-catalog-review-group">
            <legend>{label}</legend>
            <div className="pt-catalog-review-head">
              <span className="wb-small wb-muted">
                {group.filter((row) => row.selected).length} of {group.length} matching selected
              </span>
              <span className="wb-btn-group">
                {[true, false].map((selected) => (
                  <AdminButton
                    key={String(selected)}
                    size="sm"
                    aria-label={`Select ${selected ? "all" : "none"} matching ${label.toLowerCase()} ${items}`}
                    disabled={pending || !group.some((row) => row.selected !== selected)}
                    onClick={() => {
                      setConfirmed(false);
                      setRows((current) => current.map((row) => (group.some((match) => match.key === row.key) ? { ...row, selected } : row)));
                    }}
                  >
                    {selected ? "All" : "None"}
                  </AdminButton>
                ))}
              </span>
            </div>
            {!group.length ? <p className="pt-prose wb-small">No matching {items}.</p> : null}
            {group.map((row) => (
              <ReviewRow key={row.key} row={row} pending={pending || !writable} update={update} command={command ? { types, caveatId } : null} />
            ))}
          </fieldset>
        );
      })}
      {rows.some((row) => !row.selectable) ? (
        <section className="pt-catalog-review-retained" aria-label={`Unavailable ${items} and retained identities`}>
          <h3 className="pt-section-title">Unavailable {items} and retained identities</h3>
          {retained.map((row) => (
            <div key={row.key} className="pt-catalog-review-item">
              <b className="pt-catalog-break">
                {row.action || "Unsupported action"} · {row.change}
              </b>
              <OperationDetails definition={row.tool.definition} />
              {command && row.change !== "Unsupported" ? <ResourcesCheckedBy definition={row.tool.definition} types={types} caveatId={caveatId} /> : null}
              {row.reason ? <p className="pt-prose wb-small">{row.reason}</p> : null}
              <ScopedMcpWarningText warning={row.scopedMcpWarning} />
            </div>
          ))}
        </section>
      ) : null}
      {affected.length ? (
        <Banner tone="warning" slim title="Existing grants to review">
          <p className="pt-catalog-break">Existing grants to review: {affected.join(", ")}</p>
          <Checkbox
            label="I reviewed the affected grants and approve these action changes."
            checked={confirmed}
            disabled={pending || !writable}
            onChange={(event) => setConfirmed(event.target.checked)}
          />
        </Banner>
      ) : null}
      <ImportErrorAlert error={error} />
    </div>
  );

  return frame({
    title: `Review discovered ${items}`,
    body,
    footerNote:
      invalid ??
      typeProblem ??
      (selectedCount ? `${selectedCount} ${plural(selectedCount, noun)} selected` : `No ${items} selected: accepting applies only the command's metadata and resource type changes.`),
    footer: (
      <>
        <Button onClick={onClose} disabled={pending}>
          Cancel
        </Button>
        <AdminButton type="submit" variant="primary" pending={pending || !writable} disabled={blocked}>
          Accept selected {items}
        </AdminButton>
      </>
    ),
    onSubmit: () => void accept(),
    onClose,
    pending
  });
}

function ReviewRow({
  row,
  pending,
  update,
  command
}: {
  row: ImportReviewRow;
  pending: boolean;
  update: (key: string, change: Partial<ImportReviewRow>) => void;
  /** Command actions show who checks their resources. */
  command: { types: readonly ImportResourceTypeDeclaration[]; caveatId: string } | null;
}) {
  const source = row.tool.definition.action;
  return (
    <div className={row.selected ? "pt-catalog-review-item is-selected" : "pt-catalog-review-item"}>
      <div className="pt-catalog-review-title">
        <Checkbox
          aria-label={`Accept ${row.action}`}
          label={
            <span className="pt-catalog-break">
              <span className="wb-mono">{row.action}</span> · <span className={cx("pt-catalog-tone-text", toneClass(CHANGE_TONE[row.change]))}>{row.change}</span>
            </span>
          }
          checked={row.selected}
          disabled={pending}
          onChange={(event) => update(row.key, { selected: event.target.checked })}
        />
      </div>
      <OperationDetails definition={row.tool.definition} />
      {command ? <ResourcesCheckedBy definition={row.tool.definition} types={command.types} caveatId={command.caveatId} /> : null}
      <LongText text={row.tool.definition.description} subject={source} />
      {row.reason ? <p className="pt-prose wb-small">{row.reason}</p> : null}
      <ScopedMcpWarningText warning={row.scopedMcpWarning} />
      <div className="pt-catalog-review-fields">
        <Field label={`Action name for ${source}`}>
          <Input
            mono
            inputSize="sm"
            value={row.action}
            disabled={pending || Boolean(row.existing && row.existing.status !== "retired")}
            onChange={(event) => update(row.key, { action: event.target.value })}
            spellCheck={false}
          />
        </Field>
        <Field label={`Display label for ${source}`}>
          <Input inputSize="sm" maxLength={256} value={row.label} disabled={pending} onChange={(event) => update(row.key, { label: event.target.value })} />
        </Field>
        <Field label={`Effects for ${source}`} hint={row.tool.readOnlyHint === true ? "Upstream suggests read-only." : undefined}>
          <Select inputSize="sm" value={row.readOnly ? "read" : "write"} disabled={pending} onChange={(event) => update(row.key, { readOnly: event.target.value === "read" })}>
            <option value="write">Write-capable / unconfirmed</option>
            <option value="read">Reviewed read-only</option>
          </Select>
        </Field>
      </div>
      <Disclosure summary="Schemas and source">
        <pre className="wb-code pt-catalog-code">
          {JSON.stringify(
            {
              source: row.tool.definition.source,
              inputSchema: row.tool.definition.inputSchema,
              outputSchema: row.tool.definition.outputSchema,
              annotations: row.tool.definition.annotations
            },
            null,
            2
          )}
        </pre>
      </Disclosure>
    </div>
  );
}
