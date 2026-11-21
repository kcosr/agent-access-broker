import { useEffect, useRef, useState } from "react";
import { brokerApi } from "../../api";
import { useSession } from "../../app/session";
import { locationCoverage, locationInputHints, locationPreviewLabel } from "../../lib/resource-locations";
import type { NormalizedResourceLocation, ResourceLocationService } from "../../types";
import { Banner, Button, ErrorState, Field, Input, KeyValue, Select } from "../../workbench";

/** Server normalization is the only source of a saved URL-entry selector. */
export function ResourceLocationEntry({ services, disabled, preview, onPreview }: {
  services: ResourceLocationService[];
  disabled: boolean;
  preview: NormalizedResourceLocation | null;
  onPreview: (value: NormalizedResourceLocation | null) => void;
}) {
  const { attempt } = useSession();
  const [service, setService] = useState("");
  const [url, setUrl] = useState("");
  const [spaceKey, setSpaceKey] = useState("");
  const [choice, setChoice] = useState<"" | "exact" | "subtree">("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const revision = useRef(0);
  useEffect(() => () => { revision.current += 1; }, []);
  const hints = locationInputHints(url);
  const coverage = locationCoverage(hints?.kind, choice);
  const chosenService = services.find((item) => item.service === service);
  function changed() { revision.current += 1; onPreview(null); setError(null); }
  async function normalize() {
    if (!chosenService || !coverage || !url.trim()) return;
    const requestedRevision = revision.current;
    setPending(true);
    setError(null);
    onPreview(null);
    try {
      const result = await attempt((session) => brokerApi.normalizeResourceLocation(session, { service, url: url.trim(), coverage, ...(spaceKey.trim() ? { spaceKey: spaceKey.trim() } : {}) }));
      if (revision.current === requestedRevision) onPreview(result);
    } catch (failure) {
      if (revision.current === requestedRevision) setError(failure);
    } finally { setPending(false); }
  }
  return <div className="flex flex-col gap-3">
    <Field label="Location service">
      <Select value={service} disabled={disabled} onChange={(event) => { changed(); setService(event.target.value); }}>
        <option value="">Choose a service</option>
        {services.map((item) => <option key={item.service} value={item.service}>{item.service} · {item.siteHost}</option>)}
      </Select>
    </Field>
    <Field label="Location URL" hint="Paste a space, page, folder or blog URL. Titles in URLs are not fetched titles.">
      <Input value={url} disabled={disabled} spellCheck={false} onChange={(event) => { changed(); setUrl(event.target.value); setSpaceKey(locationInputHints(event.target.value)?.spaceKey ?? ""); setChoice(""); }} placeholder={chosenService ? `https://${chosenService.siteHost}/wiki/spaces/ENG/pages/12345` : "Choose a service, then paste its URL"} />
    </Field>
    <Field label="Space key" hint="Prefilled from the URL. Replace a browser alias with the actual canonical space key; this is checked when the resource is used.">
      <Input value={spaceKey} disabled={disabled} onChange={(event) => { changed(); setSpaceKey(event.target.value); }} spellCheck={false} />
    </Field>
    {hints?.kind === "space" ? <p>Entire {spaceKey || hints.spaceKey} space</p>
      : hints?.kind === "folder" ? <p>This folder and descendants</p>
      : hints?.kind === "blog" ? <p>This blog post only</p>
      : <Field label="Location coverage"><Select value={choice} disabled={disabled} onChange={(event) => { changed(); setChoice(event.target.value as "" | "exact" | "subtree"); }}>
        <option value="">Choose coverage</option><option value="exact">This page only</option><option value="subtree">This page and descendants</option>
      </Select></Field>}
    {hints?.rootId ? <p className="pt-prose wb-small">Root ID: {hints.rootId} · Configured space key: {spaceKey || hints.spaceKey}</p> : null}
    <Button className="self-start" disabled={disabled || !chosenService || !coverage || !url.trim()} pending={pending} onClick={() => void normalize()}>Preview location</Button>
    {error ? <ErrorState compact title="Couldn’t preview location" error={error} /> : null}
    {preview ? <Banner tone="info"><div className="flex flex-col gap-2">
      <strong>{locationPreviewLabel(preview)}</strong>
      <KeyValue items={[
        { label: "Resource type", value: preview.resourceType },
        { label: "Canonical identifier", value: preview.selector.kind === "all" ? "All" : preview.selector.value },
        { label: "Space key", value: preview.configuredSpaceKey }
      ]} />
      <span>Not checked upstream. Preview does not verify existence or permissions. Save stores exactly this coverage.</span>
    </div></Banner> : null}
  </div>;
}
