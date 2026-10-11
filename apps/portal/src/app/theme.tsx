// The portal's theme preference (System / Light / Dark), stored under the
// key earlier portal versions used for light/dark.
import { useTheme } from "../workbench";

export const THEME_KEY = "aab.portal.theme";

export function usePortalTheme() {
  return useTheme(THEME_KEY);
}
