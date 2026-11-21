import type { LocationHints, PageCoverage } from "../../lib/resource-locations";
import type { ResourceLocationService } from "../../types";
import { Field, Input, Select } from "../../workbench";

/** Controlled presentation. The parent owns the single normalization-and-save operation. */
export function ResourceLocationEntry({ url, choice, hints, service, disabled, issue, onUrl, onChoice }: {
  url: string;
  choice: PageCoverage;
  hints: LocationHints | null;
  service: ResourceLocationService | null;
  disabled: boolean;
  issue?: string;
  onUrl: (value: string) => void;
  onChoice: (value: PageCoverage) => void;
}) {
  return <div className="flex flex-col gap-3">
    <Field label="Location URL" hint="Paste a supported Confluence space, page, folder or blog URL. Saving does not check existence or permissions." error={issue}>
      <Input value={url} disabled={disabled} spellCheck={false} onChange={(event) => onUrl(event.target.value)} placeholder={service ? `https://${service.siteHost}/wiki/spaces/ENG/pages/12345` : "Paste a Confluence location URL"} />
    </Field>
    {service ? <p className="pt-prose wb-small">Site: {service.siteHost}</p> : null}
    {hints?.kind === "page" ? <Field label="Location coverage">
      <Select value={choice} disabled={disabled} onChange={(event) => onChoice(event.target.value as PageCoverage)}>
        <option value="">Choose coverage</option>
        <option value="exact">This page only</option>
        <option value="subtree">This page and descendants</option>
      </Select>
    </Field> : hints?.kind === "folder" ? <p>This folder and descendants</p>
      : hints?.kind === "blog" ? <p>This blog post only</p>
      : hints?.kind === "space" ? <div className="flex flex-col gap-2">
        <p>Entire {hints.spaceKey} space</p>
        <p>Space key to save: <strong>{hints.spaceKey}</strong></p>
        <p className="pt-prose wb-small">Browser URLs may contain aliases. Enter the canonical key using By space key.</p>
      </div> : null}
    {hints?.rootId ? <p className="pt-prose wb-small">{hints.kind === "blog" ? "Blog post" : hints.kind === "folder" ? "Folder" : "Page"} ID: {hints.rootId}</p> : null}
  </div>;
}
