// Cache invalidation after portal mutations.
import { useMemo } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { portalQueryKeys, viewerKey } from "../lib/portal-queries";
import { useSession } from "../app/session";

export function usePortalInvalidation() {
  const queryClient = useQueryClient();
  const { session } = useSession();
  const viewer = viewerKey(session);
  return useMemo(() => {
    const invalidate = (queryKey: readonly unknown[]) => queryClient.invalidateQueries({ queryKey });
    return {
      /** Everything the portal caches. */
      portal: () => void invalidate(portalQueryKeys.root),
      /** Self-service and managed-user console data. */
      console: () => void invalidate(portalQueryKeys.consoleRoot),
      oauthConnections: () => void invalidate(portalQueryKeys.oauthConnections(viewer)),
      agentTokenOptions: () => void invalidate(portalQueryKeys.agentTokenOptionsRoot),
      /** Admin data and effective-access previews. */
      admin: () => {
        void invalidate(portalQueryKeys.adminRoot(viewer));
        void invalidate(portalQueryKeys.effectiveAccessRoot);
      },
      runtime: () => void invalidate(portalQueryKeys.configStatus(viewer)),
      /** Awaitable session refresh (for example after a config reload). */
      session: () => invalidate(portalQueryKeys.session)
    };
  }, [queryClient, viewer]);
}
