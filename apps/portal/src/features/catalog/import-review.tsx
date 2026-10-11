import { useSession } from "../../app/session";
import { canWriteAdmin } from "../../lib/capabilities";
import { AdminButton } from "../../components/admin-access";
// Reviewing a discovery preview: choose tools or operations to accept, name
// them, classify their effects, and confirm changes that affect existing grants.
import { useState } from "react";
import type { ImportActionDefinition, ImportPreviewResult, ImportScopedMcp, ImportScopedMcpIssueCode, ImportScopedMcpWarning } from "../../import-types";
import { affectedImportGrants, importReviewRows, importSelectionError, type ImportReviewRow } from "../../lib/imports";
import { openApiOperation, openApiSchemeLabel } from "../../lib/import-openapi";
import { errorMessage } from "../../lib/helpers";
import { Badge, Banner, Button, Checkbox, Disclosure, Field, FilterInput, Input, Select, Time, cx, plural, toneClass, type Tone } from "../../workbench";
import { FormError } from "../../components/form";
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
  onAccept: (rows: ImportReviewRow[], confirmAffectedGrants: boolean) => Promise<unknown>;
  /** Offered for an empty OpenAPI draft whose operations need an API security scheme first. */
  onConfigure?: (() => void) | undefined;
  frame?: EditorFrame;
};

export function ImportReview({ data, onClose, onAccept, onConfigure, frame = modalFrame }: ImportReviewProps) {
  const writable = canWriteAdmin(useSession().session);
  const [rows, setRows] = useState(() => importReviewRows(data));
  const [confirmed, setConfirmed] = useState(false);
  const [search, setSearch] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const items = data.service.definition.adapterKind === "openapi_http" ? "operations" : "tools";
  const invalid = importSelectionError(data.service, rows);
  const affected = affectedImportGrants(data, rows);
  const query = search.trim().toLowerCase();
  const matches = (row: ImportReviewRow) =>
    !query ||
    `${row.action} ${row.tool.definition.description} ${row.change} ${JSON.stringify(row.tool.definition.source)} ${JSON.stringify(openApiOperation(row.tool.definition))}`
      .toLowerCase()
      .includes(query);
  const update = (key: string, change: Partial<ImportReviewRow>) => {
    setConfirmed(false);
    setRows((current) => current.map((row) => (row.key === key ? { ...row, ...change } : row)));
  };
  const selectedCount = rows.filter((row) => row.selected && row.selectable).length;
  const retained = rows.filter((row) => !row.selectable && matches(row));

  async function accept() {
    if (!writable || invalid || (affected.length > 0 && !confirmed)) return;
    setPending(true);
    setError(null);
    try {
      await onAccept(rows, confirmed);
      onClose();
    } catch (failure) {
      setError(errorMessage(failure));
      setPending(false);
    }
  }

  const body = (
    <div className="pt-form pt-catalog-form">
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
      <Disclosure summary="Discovery source details">
        <p className="pt-prose wb-small">Protocol: {data.preview?.manifest.protocolVersion}</p>
        <pre className="wb-code pt-catalog-code">{JSON.stringify(data.preview?.manifest.metadata, null, 2)}</pre>
      </Disclosure>
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
              <ReviewRow key={row.key} row={row} pending={pending || !writable} update={update} />
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
      <FormError error={error} />
    </div>
  );

  return frame({
    title: `Review discovered ${items}`,
    body,
    footerNote: invalid ?? `${selectedCount} ${plural(selectedCount, items === "tools" ? "tool" : "operation")} selected`,
    footer: (
      <>
        <Button onClick={onClose} disabled={pending}>
          Cancel
        </Button>
        <AdminButton type="submit" variant="primary" pending={pending || !writable} disabled={Boolean(invalid) || (affected.length > 0 && !confirmed)}>
          Accept selected {items}
        </AdminButton>
      </>
    ),
    onSubmit: () => void accept(),
    onClose,
    pending
  });
}

function ReviewRow({ row, pending, update }: { row: ImportReviewRow; pending: boolean; update: (key: string, change: Partial<ImportReviewRow>) => void }) {
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
