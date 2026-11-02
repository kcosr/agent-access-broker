import { Badge, Button, Checkbox } from "../../workbench";

/** Only the stored Boolean or explicit draft choice describes a token's ceiling. */
export function TokenEffect({ readOnly, quiet = false }: { readOnly: unknown; quiet?: boolean }) {
  if (readOnly === false) return <Badge tone="warning" icon="pencil" title="May use granted write actions">Write-capable</Badge>;
  if (!quiet) return null;
  return <span className="wb-muted">{readOnly === true ? "Read-only" : "Restriction unavailable"}</span>;
}

/** A required restriction is information; changing a stale draft still needs consent. */
export function TokenReadOnlyControl({ readOnly, required, disabled, onChange }: { readOnly: boolean; required: boolean; disabled: boolean; onChange: (readOnly: boolean) => void }) {
  if (required) return <>
    <div>
      <p className="m-0">Read-only</p>
      <p className="wb-field-hint">Required by your account’s token issuance policy</p>
    </div>
    {!readOnly ? <Button disabled={disabled} onClick={() => onChange(true)}>Apply read-only restriction</Button> : null}
  </>;
  return <Checkbox label="Read-only" checked={readOnly} disabled={disabled} onChange={(event) => onChange(event.target.checked)} description="Allow only actions the current catalog classifies as reads. Write grants remain blocked." />;
}
