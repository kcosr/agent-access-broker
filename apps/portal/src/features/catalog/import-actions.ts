// Imported service mutations. Each call resolves after the admin caches have
// refetched, so the next action uses the new service and catalog versions.
// Failures reject; callers show them where they happened.
import { useMemo } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { brokerApi } from "../../api";
import type {
  ImportActionStatus,
  ImportDefinition,
  ImportPreviewResult,
  ImportPurpose,
  ImportRecordResult,
  ImportServiceStatus
} from "../../import-types";
import { importVersions, selectedImportActions, type ImportReviewRow } from "../../lib/imports";
import { portalQueryKeys, viewerKey } from "../../lib/portal-queries";
import type { Session } from "../../types";
import { useToast } from "../../workbench";
import { useModal } from "../../app/modal";
import { useSession } from "../../app/session";

type Versioned = Pick<ImportPreviewResult, "catalogRevision" | "service">;
export type ServiceStatusChange = Exclude<ImportServiceStatus, "draft">;
export type ActionStatusChange = Exclude<ImportActionStatus, "quarantined">;

export const STATUS_VERB: Record<ServiceStatusChange, string> = { enabled: "Enable", disabled: "Disable", retired: "Retire" };

const SERVICE_STATUS_TEXT: Record<ServiceStatusChange, string> = {
  enabled: "Existing grants can become effective immediately for enabled actions and configured credential modes.",
  disabled: "All actions stop executing. Definitions, tokens and grants remain for later review.",
  retired: "Retirement is permanent. The service, action identities and grant references remain, but cannot execute. Stored tokens remain until you delete them."
};

const ACTION_STATUS_TEXT: Record<ActionStatusChange, string> = {
  enabled: "Existing grants for this action can become effective immediately.",
  disabled: "This action stops executing; its identity and grants remain.",
  retired: "This action identity is permanently retired. Grant references remain."
};

export function useImportActions() {
  const queryClient = useQueryClient();
  const { session, attempt } = useSession();
  const { confirm } = useModal();
  const toast = useToast();
  const viewer = viewerKey(session);

  return useMemo(() => {
    /** Admin data (imports, previews, policy catalog), services, and OAuth targets. */
    async function refresh() {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: portalQueryKeys.adminRoot(viewer) }),
        queryClient.invalidateQueries({ queryKey: portalQueryKeys.consoleRoot }),
        queryClient.invalidateQueries({ queryKey: portalQueryKeys.oauthConnections(viewer) }),
        queryClient.invalidateQueries({ queryKey: portalQueryKeys.effectiveAccessRoot })
      ]);
    }

    async function run<T>(operation: (current: Session) => Promise<T>, message: string) {
      const result = await attempt(operation);
      await refresh();
      toast(message, { tone: "success" });
      return result;
    }

    function create(definition: ImportDefinition): Promise<ImportRecordResult> {
      return run((current) => brokerApi.createImport(current, definition), `Draft ${definition.service} created`);
    }

    function update(data: Versioned, definition: ImportDefinition, confirmAffectedGrants: boolean): Promise<ImportRecordResult> {
      return run(
        (current) => brokerApi.updateImport(current, definition.service, { ...importVersions(data), definition, confirmAffectedGrants }),
        "Import configuration saved"
      );
    }

    /** Runs discovery; the result carries the fresh preview to review. */
    async function discover(data: Versioned): Promise<ImportPreviewResult> {
      const result = await attempt((current) => brokerApi.discoverImport(current, data.service.definition.service, importVersions(data)));
      await refresh();
      return result;
    }

    function accept(data: ImportPreviewResult, rows: ImportReviewRow[], confirmAffectedGrants: boolean): Promise<ImportRecordResult> {
      const preview = data.preview;
      if (!preview) return Promise.reject(new Error("This preview has expired. Run discovery again."));
      const selections = selectedImportActions(rows);
      return run(
        (current) =>
          brokerApi.acceptImport(current, data.service.definition.service, {
            ...importVersions(data),
            manifestHash: preview.manifestHash,
            selections,
            confirmAffectedGrants
          }),
        `${selections.length} ${selections.length === 1 ? "action" : "actions"} accepted`
      );
    }

    function confirmServiceStatus(data: Versioned, status: ServiceStatusChange) {
      const service = data.service.definition.service;
      confirm({
        title: `${STATUS_VERB[status]} ${service}?`,
        body: SERVICE_STATUS_TEXT[status],
        confirmLabel: `${STATUS_VERB[status]} service`,
        tone: status === "enabled" ? "primary" : "danger",
        onConfirm: () =>
          run(
            (current) => brokerApi.setImportStatus(current, service, { ...importVersions(data), status, confirm: true }),
            `${data.service.definition.displayName} ${status}`
          )
      });
    }

    function confirmActionStatus(data: Versioned, action: string, status: ActionStatusChange) {
      const service = data.service.definition.service;
      confirm({
        title: `${STATUS_VERB[status]} ${action}?`,
        body: ACTION_STATUS_TEXT[status],
        confirmLabel: `${STATUS_VERB[status]} action`,
        tone: status === "enabled" ? "primary" : "danger",
        onConfirm: () =>
          run(
            (current) => brokerApi.setImportActionStatus(current, service, action, { ...importVersions(data), status, confirm: true }),
            `${action} ${status}`
          )
      });
    }

    function writeToken(data: Versioned, purpose: ImportPurpose, token: string) {
      return run(
        (current) => brokerApi.writeImportToken(current, data.service.definition.service, purpose, { ...importVersions(data), token }),
        `${purpose[0]!.toUpperCase()}${purpose.slice(1)} token saved`
      );
    }

    /** The signed-in administrator's own static token for per-user discovery. */
    function writePersonalToken(data: Versioned, token: string) {
      const principal = session.principal;
      if (!principal) return Promise.reject(new Error("Sign in again to save a personal token."));
      return run(
        (current) => brokerApi.adminPrincipalSaveCredential(current, principal, data.service.definition.service, "default", "token", { token }),
        "Personal token saved"
      );
    }

    function confirmDeleteToken(data: Versioned, purpose: ImportPurpose) {
      confirm({
        title: `Delete ${purpose} token?`,
        body: "Calls requiring this token will fail until a replacement is saved. Grant references remain.",
        confirmLabel: "Delete token",
        onConfirm: () =>
          run(
            (current) => brokerApi.deleteImportToken(current, data.service.definition.service, purpose, importVersions(data)),
            `${purpose[0]!.toUpperCase()}${purpose.slice(1)} token deleted`
          )
      });
    }

    return { refresh, create, update, discover, accept, confirmServiceStatus, confirmActionStatus, writeToken, writePersonalToken, confirmDeleteToken };
  }, [queryClient, viewer, attempt, confirm, toast, session.principal]);
}

export type ImportActions = ReturnType<typeof useImportActions>;
