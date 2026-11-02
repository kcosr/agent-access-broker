/**
 * Kit style, independent of the light/dark theme: "default" (no attribute)
 * or "quiet" (data-wb-style="quiet" on <html>). An application picks one for
 * good: write the attribute in index.html, or call applyStyle() at the top of
 * main.tsx before the first render (CSSOM, so CSP-safe).
 */

export type StyleName = "default" | "quiet";

/** The <html> attribute that selects the style. */
export const STYLE_ATTRIBUTE = "data-wb-style";

/** Select the style on <html> ("default" removes the attribute). */
export function applyStyle(style: StyleName): void {
  const root = document.documentElement;
  if (style === "quiet") root.dataset.wbStyle = style;
  else delete root.dataset.wbStyle;
}

/** The style selected on <html> right now. */
export function appliedStyle(): StyleName {
  return document.documentElement.dataset.wbStyle === "quiet"
    ? "quiet"
    : "default";
}
