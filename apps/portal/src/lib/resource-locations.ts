import type { NormalizedResourceLocation, ResourceLocationRequest, ResourceLocationService, ResourceType } from "../types";

export type LocationKind = "space" | "page" | "folder" | "blog";
export type LocationHints = { siteOrigin: string; kind: LocationKind; rootId: string | null; spaceKey?: string };
export type ContentIdentity = { siteOrigin: string; kind: Exclude<LocationKind, "space">; id: string };
export type PageCoverage = "" | "exact" | "subtree";

const SPACE_SEGMENT = /^(?:[A-Za-z0-9][A-Za-z0-9_-]{0,254}|~[A-Za-z0-9][A-Za-z0-9._@:+-]{0,253})$/;
const CONTENT_ID = /^[1-9][0-9]{0,19}$/;

/** Rust str::trim's Unicode whitespace set, without JavaScript's extra BOM trim. */
export function trimLocationInput(value: string): string {
  return value.replace(/^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g, "");
}

/** Check the raw path before URL() can remove dot segments or normalize authority. */
function parsedLocationUrl(raw: string): { url: URL; siteOrigin: string } | null {
  if (/[\u0000-\u001f\u007f\\]/.test(raw)) return null;
  const prefix = /^https:\/\/([^/?#]*)([^?#]*)(.*)$/i.exec(raw);
  if (!prefix || !prefix[1] || /[@:\[\]%]/.test(prefix[1]) || prefix[3]) return null;
  for (const segment of prefix[2].split("/")) {
    if (/%(?![0-9a-f]{2})/i.test(segment)) return null;
    const decoded = segment.replace(/%([0-9a-f]{2})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
    if (/[\u0000-\u001f\u007f/\\?#]/.test(decoded) || decoded === "." || decoded === "..") return null;
  }
  try {
    const url = new URL(raw);
    const host = url.hostname.replace(/\.$/, "");
    if (!host || host.length > 253 || /^\d+\.\d+\.\d+\.\d+$/.test(host)
      || !host.split(".").every((part) => part.length <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(part))) return null;
    return { url, siteOrigin: `https://${host}` };
  } catch { return null; }
}

function dateNumber(value: string, max: number): boolean {
  // Rust's u8 parser permits a leading plus and zero-padded components.
  return /^\+?\d+$/.test(value) && Number(value) >= 1 && Number(value) <= max;
}

/** Presentation only. The Rust normalizer remains the authority for every URL save. */
export function locationInputHints(value: string): LocationHints | null {
  if (/[\u0000-\u001f\u007f\\]/.test(value)) return null;
  const parsed = parsedLocationUrl(trimLocationInput(value));
  if (!parsed) return null;
  const { url, siteOrigin } = parsed;
  const path = url.pathname.replace(/\/$/, "");
  const parts = path.split("/");
  if (parts[0] !== "" || parts[1] !== "wiki" || parts[2] !== "spaces" || !SPACE_SEGMENT.test(parts[3] ?? "")) return null;
  const tail = parts.slice(4);
  if (!tail.length || tail.length === 1 && tail[0] === "overview") return { siteOrigin, kind: "space", rootId: null, spaceKey: parts[3] };
  let kind: Exclude<LocationKind, "space">;
  let content = tail.slice(1);
  if (tail[0] === "pages" && (content.length === 1 || content.length === 2)) kind = "page";
  else if (tail[0] === "folder" && content.length === 1) kind = "folder";
  else if (tail[0] === "blog") {
    kind = "blog";
    if (content.length >= 3 && /^\d{4}$/.test(content[0]) && dateNumber(content[1], 12) && dateNumber(content[2], 31)) content = content.slice(3);
    if (content.length !== 1 && content.length !== 2) return null;
  } else return null;
  if (!CONTENT_ID.test(content[0])) return null;
  return { siteOrigin, kind, rootId: content[0] };
}

/** A stored identity is text, not a browser URL or evidence of current space. */
export function parseContentIdentity(value: string): ContentIdentity | null {
  const parsed = parsedLocationUrl(value);
  if (!parsed) return null;
  const match = /^\/wiki\/content\/(page|folder|blog)\/([1-9][0-9]{0,19})$/.exec(parsed.url.pathname);
  if (!match || value !== `${parsed.siteOrigin}${parsed.url.pathname}`) return null;
  return { siteOrigin: parsed.siteOrigin, kind: match[1] as ContentIdentity["kind"], id: match[2] };
}

export function locationResourceType(kind: LocationKind): ResourceType {
  return kind === "space" ? "confluence_space" : "confluence_content";
}

export function locationCoverage(kind: LocationKind | undefined, choice: PageCoverage): ResourceLocationRequest["coverage"] | null {
  if (kind === "space") return "space";
  if (kind === "folder") return "subtree";
  if (kind === "blog") return "exact";
  return kind === "page" ? choice || null : null;
}

export function locationPreviewLabel(location: NormalizedResourceLocation): string {
  if (location.locationKind === "space") return `Entire ${location.selector.kind === "exact" ? location.selector.value : ""} space`;
  if (location.locationKind === "blog") return "This blog post only";
  if (location.locationKind === "folder") return "This folder and descendants";
  return location.selector.kind === "subtree" ? "This page and descendants" : "This page only";
}

export function configuredLocationService(services: ResourceLocationService[], type: ResourceType, hints: LocationHints | null): {
  service: ResourceLocationService | null; issue: "absent" | "wrong_site" | "ambiguous" | null;
} {
  const applicable = services.filter((item) => item.resourceTypes.includes(type));
  if (!applicable.length) return { service: null, issue: "absent" };
  const matching = hints ? applicable.filter((item) => `https://${item.siteHost}` === hints.siteOrigin) : applicable;
  if (!matching.length) return { service: null, issue: "wrong_site" };
  if (matching.length !== 1) return { service: null, issue: "ambiguous" };
  return { service: matching[0], issue: null };
}

/** A successful response cannot silently change the identity displayed at Save. */
export function normalizedLocationMatches(hints: LocationHints, coverage: ResourceLocationRequest["coverage"], result: NormalizedResourceLocation): boolean {
  if (!result || !result.selector || result.verification !== "not_checked" || result.resourceType !== locationResourceType(hints.kind)
    || result.locationKind !== hints.kind || result.selector.kind !== (coverage === "space" ? "exact" : coverage)) return false;
  if (hints.kind === "space") return result.selector.kind === "exact" && result.selector.value === hints.spaceKey;
  if (result.selector.kind !== "exact" && result.selector.kind !== "subtree") return false;
  const identity = parseContentIdentity(result.selector.value);
  return identity !== null && identity.siteOrigin === hints.siteOrigin && identity.kind === hints.kind && identity.id === hints.rootId;
}
