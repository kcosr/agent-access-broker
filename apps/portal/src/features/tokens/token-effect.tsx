import { Badge } from "../../workbench";

/** Only the stored Boolean or explicit draft choice describes a token's ceiling. */
export function TokenEffect({ readOnly, quiet = false }: { readOnly: unknown; quiet?: boolean }) {
  if (readOnly === false) return <Badge tone="warning" icon="pencil" title="May use granted write actions">Write-capable</Badge>;
  if (!quiet) return null;
  return <span className="wb-muted">{readOnly === true ? "Read-only" : "Restriction unavailable"}</span>;
}
