// Resource and resource-group mutations. Each resolves after the admin caches
// (catalog, used-by, effective access) and token options have refetched.
// Failures reject; callers show them where they happened.
import { useMemo } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { brokerApi } from "../../api";
import type { ResourceGroupRecord, ResourceGroupWriteBody, ResourceRecord, ResourceWriteBody } from "../../types";
import { portalQueryKeys, viewerKey } from "../../lib/portal-queries";
import { useToast } from "../../workbench";
import { useModal } from "../../app/modal";
import { useSession } from "../../app/session";

export type ResourceKind = "resources" | "resource-groups";

export function useResourceActions() {
  const queryClient = useQueryClient();
  const { session, attempt } = useSession();
  const { confirm } = useModal();
  const toast = useToast();
  const viewer = viewerKey(session);

  return useMemo(() => {
    async function refresh() {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: portalQueryKeys.adminRoot(viewer) }),
        queryClient.invalidateQueries({ queryKey: portalQueryKeys.effectiveAccessRoot }),
        queryClient.invalidateQueries({ queryKey: portalQueryKeys.agentTokenOptionsRoot })
      ]);
    }

    async function refreshResourceTypes() {
      await queryClient.invalidateQueries({ queryKey: portalQueryKeys.resourceTypes(viewer) }, { throwOnError: true });
    }

    async function saveResource(body: ResourceWriteBody, id?: string) {
      const result = await attempt((current) => brokerApi.saveResource(current, body, id));
      await refresh();
      toast(id ? "Resource saved" : "Resource added", { tone: "success" });
      return result.record;
    }

    async function setResourceEnabled(resource: ResourceRecord, enabled: boolean) {
      await attempt((current) =>
        brokerApi.saveResource(
          current,
          {
            resourceType: resource.resourceType,
            selector: resource.selector,
            displayName: resource.displayName,
            allowedExecutionContexts: resource.allowedExecutionContexts,
            expectedVersion: resource.version,
            enabled
          },
          resource.id
        )
      );
      await refresh();
      toast(enabled ? "Resource enabled" : "Resource disabled", { tone: "success" });
    }

    async function saveGroup(body: ResourceGroupWriteBody, id?: string) {
      const result = await attempt((current) => brokerApi.saveResourceGroup(current, body, id)).catch(async (failure: unknown) => {
        // Another operator may have changed a resource type while this editor
        // was open. Keep its selections and original error, but update eligibility.
        await Promise.allSettled([
          refreshResourceTypes(),
          queryClient.invalidateQueries({ queryKey: portalQueryKeys.resourceCatalog(viewer) })
        ]);
        throw failure;
      });
      await refresh();
      toast(id ? "Resource group saved" : "Resource group added", { tone: "success" });
      return result.record;
    }

    function confirmDelete(kind: ResourceKind, record: ResourceRecord | ResourceGroupRecord, label: string, onDeleted: () => void) {
      const noun = kind === "resources" ? "resource" : "resource group";
      confirm({
        title: `Delete ${noun}?`,
        body: `Delete ${label}? Grants and token restrictions can no longer reference it.`,
        confirmLabel: `Delete ${noun}`,
        onConfirm: async () => {
          await attempt((current) => brokerApi.deleteResourceEntry(current, kind, record.id, record.version));
          onDeleted();
          await refresh();
          toast(kind === "resources" ? "Resource deleted" : "Resource group deleted", { tone: "success" });
        }
      });
    }

    return { refresh, refreshResourceTypes, saveResource, setResourceEnabled, saveGroup, confirmDelete };
  }, [queryClient, viewer, attempt, confirm, toast]);
}
