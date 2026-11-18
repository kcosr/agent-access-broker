// Runtime configuration reload.
import { useMemo } from "react";
import { brokerApi } from "../api";
import { applicationTokensNotice } from "../lib/applications";
import { useToast } from "../workbench";
import { useSession } from "../app/session";
import { useModal } from "../app/modal";
import { usePortalInvalidation } from "../data/invalidation";

export function useRuntimeActions() {
  const { attempt } = useSession();
  const toast = useToast();
  const { confirm } = useModal();
  const invalidate = usePortalInvalidation();

  return useMemo(() => {
    async function reload() {
      const status = await attempt((current) => brokerApi.adminConfigReload(current));
      await invalidate.session();
      invalidate.admin();
      invalidate.console();
      invalidate.oauthConnections();
      const tokens = applicationTokensNotice(status.applicationTokens);
      const reloaded = `Config reloaded · generation ${status.generation}`;
      if (!tokens) toast(reloaded, { tone: "success" });
      // The configuration is active either way; a failed token step is retried by the next reload.
      else toast(`${reloaded}. ${tokens.text}`, { tone: tokens.failed ? "error" : "success", duration: 8000 });
    }

    function confirmReload() {
      confirm({
        title: "Reload broker configuration?",
        body: "The broker validates the configuration on disk and switches to it if it is valid. In-flight requests finish on the current generation.",
        confirmLabel: "Reload config",
        tone: "primary",
        onConfirm: reload
      });
    }

    return { reload, confirmReload };
  }, [attempt, toast, confirm, invalidate]);
}
