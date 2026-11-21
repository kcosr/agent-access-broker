import type { NormalizedResourceLocation, ResourceLocationRequest } from "../types";

/** Presentation hints only. The broker validates the complete URL before saving. */
export function locationInputHints(value: string): { kind: string; spaceKey: string; rootId: string | null } | null {
  try {
    const url = new URL(value);
    const match = /^\/wiki\/spaces\/([^/]+)(?:\/(.*))?$/.exec(url.pathname);
    if (!match) return null;
    const parts = (match[2] ?? "").split("/");
    if (!parts[0] || parts[0] === "overview") return { kind: "space", spaceKey: match[1], rootId: null };
    if (parts[0] === "pages" || parts[0] === "folder") return { kind: parts[0] === "pages" ? "page" : "folder", spaceKey: match[1], rootId: parts[1] ?? null };
    if (parts[0] === "blog") return { kind: "blog", spaceKey: match[1], rootId: /^\d{4}$/.test(parts[1] ?? "") && /^\d{1,2}$/.test(parts[2] ?? "") && /^\d{1,2}$/.test(parts[3] ?? "") ? parts[4] ?? null : parts[1] ?? null };
    return null;
  } catch { return null; }
}

export function locationCoverage(kind: string | undefined, choice: "" | "exact" | "subtree"): ResourceLocationRequest["coverage"] | null {
  if (kind === "space") return "space";
  if (kind === "folder") return "subtree";
  if (kind === "blog") return "exact";
  return choice || null;
}

export function locationPreviewLabel(location: NormalizedResourceLocation): string {
  if (location.locationKind === "space") return `Entire ${location.configuredSpaceKey} space`;
  if (location.locationKind === "blog") return "This blog post only";
  if (location.locationKind === "folder") return "This folder and descendants";
  return location.selector.kind === "subtree" ? "This page and descendants" : "This page only";
}
